"""
全局 8 步风控中间件流水线（middleware/risk.py，系统心脏）。

严格按提示词第 6.1 节流水线顺序执行（命中短路项即刻终止并落库+SSE）：
① 封禁检查（bans 表 + 缓存黑名单） ──命中→ 403 BANNED
② 限流（IP 维度 → 指纹维度 + 增强定频检查） ──超限→ 429 RATE_LIMITED
③ Header 校验（规则表 6.2/8.2 + 可选 JA4/头顺序，计分不拦截）
④ IP 信誉（mock 库机房段/黑名单段，计分）
⑤ 蜜罐标记检查（是否曾触发 trap，计分）
⑥ 签名校验（仅核心数据接口 4、5；失败→ 401）
⑦ 累计风险分 → 决策：<40 放行 / 40–69 警告（敏感接口转 PoW 挑战） / ≥70 拦截
⑧ 落库 risk_logs + SSE 广播 → 放行时可选注入诱饵数据
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.cache import get_cache
from app.config import Settings, get_settings
from app.constants import DECISION_THRESHOLDS, ReasonCode, RiskAction, RiskModule
from app.db import get_session_factory
from app.services.geoip import GeoInfo, get_geoip_provider, resolve_effective_ip
from app.services.headercheck import check_headers
from app.services.honeypot import has_trap_history, is_ip_banned
from app.services.ratelimit import (
    TokenBucketResult,
    analyze_request_cadence,
    check_fp_rate_limit,
    check_ip_rate_limit,
    check_tiered_token_bucket,
)
from app.services.risk_logger import record_risk_event
from app.services.signature import verify_request_signature

# 免于限流与封禁拦截的基础设施路径（防止靶场前端、SSE、健康检查、授时与管理解封自我死锁）
EXEMPT_PREFIXES: tuple[str, ...] = (
    "/api/v1/health",
    "/api/v1/time",
    "/api/v1/events",
    "/api/v1/admin",
    "/static",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/favicon.ico",
)


@dataclass
class RiskContext:
    """挂载在 request.state.risk_ctx 的请求级风控上下文，供业务路由共享。"""

    start_time: float
    client_ip: str
    effective_ip: str
    is_simulated: bool
    ua: str
    fp_id: str
    session_id: str
    geo: GeoInfo | None = None
    score: int = 0
    reasons: List[str] = field(default_factory=list)
    details: List[str] = field(default_factory=list)
    pipeline_steps: List[Dict[str, Any]] = field(default_factory=list)
    module: str = RiskModule.NETWORK.value
    action: str = RiskAction.PASS.value
    decoy_served: bool = False
    handled_logging: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    def add_step(self, step: int, name: str, status: str, delta: int = 0, detail: str = "") -> None:
        self.pipeline_steps.append(
            {
                "step": step,
                "name": name,
                "status": status,
                "delta": delta,
                "detail": detail,
            }
        )

    def add_signal(self, score_delta: int, reason_code: str, detail: str = "") -> None:
        self.score = min(DECISION_THRESHOLDS["MAX_SCORE"], self.score + max(0, score_delta))
        if reason_code and reason_code not in self.reasons:
            self.reasons.append(reason_code)
        if detail:
            self.details.append(detail)


def _is_signature_required_path(path: str) -> bool:
    """契约 11.1：仅核心数据接口 4（/api/v1/products）与 5（/api/v1/products/{id}/price）强制签名。"""
    if path == "/api/v1/products":
        return True
    if path.startswith("/api/v1/products/") and path.endswith("/price"):
        parts = path.strip("/").split("/")
        return len(parts) == 5 and parts[3].isdigit()
    return False


def _is_exempt_path(path: str) -> bool:
    if path == "/" or path == "/price":
        return True
    if not path.startswith("/api/v1/"):
        return True
    return any(path.startswith(prefix) for prefix in EXEMPT_PREFIXES)


def _error_json(status_code: int, message: str, risk_reason: str, **extra_fields: Any) -> JSONResponse:
    """构造 6.3 统一 JSON 错误响应体（严禁 200 混用自造错误码）。"""
    body: Dict[str, Any] = {
        "code": status_code,
        "message": message,
        "risk_reason": risk_reason,
    }
    body.update(extra_fields)
    return JSONResponse(status_code=status_code, content=body)


def _attach_gateway_headers(
    response: Response,
    tb: TokenBucketResult | None,
    request_id: str,
) -> Response:
    """向所有业务响应注入网关令牌桶配额头与链路追踪 ID（复刻 pzds 网关观测头）。"""
    response.headers["X-Request-Id"] = request_id
    if tb is not None:
        response.headers["X-RateLimit-Tier"] = tb.tier
        response.headers["X-RateLimit-Burst-Capacity"] = str(tb.burst_capacity)
        response.headers["X-RateLimit-Replenish-Rate"] = str(tb.replenish_rate)
        response.headers["X-RateLimit-Remaining"] = str(tb.remaining)
        response.headers["X-RateLimit-Requested-Tokens"] = str(tb.requested_tokens)
    return response


def _merge_session_risk(ctx: RiskContext) -> None:
    """将缓存中同 IP/指纹最近上报的指纹风险与行为风险合并进核心业务接口上下文。"""
    cache = get_cache()
    if not ctx.fp_id:
        cached_fp = cache.get(f"ip_last_fp:{ctx.effective_ip}")
        if cached_fp:
            ctx.fp_id = cached_fp

    fp_score_raw = cache.get(f"fp_risk:{ctx.fp_id}") if ctx.fp_id else None
    if fp_score_raw is None:
        fp_score_raw = cache.get(f"fp_risk_ip:{ctx.effective_ip}")
    if fp_score_raw is not None:
        try:
            fp_score = int(fp_score_raw)
            if fp_score > 0:
                ctx.score = min(100, ctx.score + fp_score)
                fp_reasons_raw = (
                    cache.get(f"fp_reasons:{ctx.fp_id}") if ctx.fp_id else None
                ) or cache.get(f"fp_reasons_ip:{ctx.effective_ip}")
                if fp_reasons_raw:
                    for r in fp_reasons_raw.split(","):
                        if r and r not in ctx.reasons:
                            ctx.reasons.append(r)
                ctx.details.append(f"关联近期指纹探针风险分 +{fp_score}")
        except ValueError:
            pass

    beh_score_raw = cache.get(f"beh_risk_ip:{ctx.effective_ip}")
    if beh_score_raw is not None:
        try:
            beh_score = int(beh_score_raw)
            if beh_score > 0:
                ctx.score = min(100, ctx.score + beh_score)
                beh_flags_raw = cache.get(f"beh_flags_ip:{ctx.effective_ip}")
                if beh_flags_raw:
                    for r in beh_flags_raw.split(","):
                        if r and r not in ctx.reasons:
                            ctx.reasons.append(r)
                ctx.details.append(f"关联近期行为轨迹风险分 +{beh_score}")
        except ValueError:
            pass


class RiskMiddleware(BaseHTTPMiddleware):
    """全局风控中间件，实现第 6.1 节 8 步串联风控流水线。"""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path
        if _is_exempt_path(path):
            return await call_next(request)

        settings: Settings = get_settings()
        start_time = time.perf_counter()
        request_id = f"acl_{uuid.uuid4().hex[:12]}"
        client_ip = request.client.host if request.client else "127.0.0.1"
        effective_ip, is_simulated = resolve_effective_ip(client_ip, request.headers, settings.lab_mode)
        ua = request.headers.get("user-agent", "").strip()
        fp_id = request.headers.get("x-fp-id", "").strip()
        if not fp_id:
            fp_id = get_cache().get(f"ip_last_fp:{effective_ip}") or ""
        session_id = request.headers.get("x-session-id", "").strip() or fp_id or effective_ip

        ctx = RiskContext(
            start_time=start_time,
            client_ip=client_ip,
            effective_ip=effective_ip,
            is_simulated=is_simulated,
            ua=ua,
            fp_id=fp_id,
            session_id=session_id,
            extra={"simulated_ip": is_simulated},
        )
        request.state.risk_ctx = ctx

        session_factory = get_session_factory()
        with session_factory() as db:
            # ── ① 封禁检查（bans 表 + 缓存黑名单）────────────────────────────
            ban_reason = is_ip_banned(db, effective_ip)
            if ban_reason:
                ctx.add_step(1, "封禁检查", "blocked", 100, f"命中有效封禁（{ban_reason}）")
                ctx.score = 100
                ctx.reasons.append(ReasonCode.BANNED.value)
                ctx.action = RiskAction.BLOCK.value
                ctx.module = RiskModule.NETWORK.value
                latency = (time.perf_counter() - start_time) * 1000
                record_risk_event(
                    db,
                    client_ip=client_ip,
                    effective_ip=effective_ip,
                    path=path,
                    module=ctx.module,
                    action=ctx.action,
                    risk_score=ctx.score,
                    reasons=ctx.reasons,
                    ua=ua,
                    fingerprint_id=fp_id,
                    latency_ms=latency,
                    extra={
                        "simulated": is_simulated,
                        "pipeline_steps": ctx.pipeline_steps,
                        "details": [f"IP {effective_ip} 处于封禁期内（原始原因：{ban_reason}）"],
                    },
                )
                return _attach_gateway_headers(
                    _error_json(403, "当前 IP 已被封禁，请联系管理员在仪表盘解封", ReasonCode.BANNED.value),
                    None,
                    request_id,
                )
            ctx.add_step(1, "封禁检查", "pass", 0, "未命中封禁名单")

            # ── ② 限流检查（IP 滑动窗口 → 指纹维度 → 分级令牌桶）─────────────
            ip_rl = check_ip_rate_limit(effective_ip, settings.rate_limit_qps)
            fp_rl = check_fp_rate_limit(fp_id, settings.fp_rate_limit_qps) if fp_id else None
            tb_res = check_tiered_token_bucket(effective_ip, path, settings)
            if ip_rl.exceeded or (fp_rl and fp_rl.exceeded) or tb_res.exceeded:
                if ip_rl.exceeded:
                    dim_label = "IP 滑动窗口"
                elif fp_rl and fp_rl.exceeded:
                    dim_label = "指纹维度"
                else:
                    dim_label = f"网关令牌桶 ({tb_res.tier})"
                detail = (
                    f"{dim_label}超限（IP={ip_rl.count}/{ip_rl.limit}"
                    + (f", FP={fp_rl.count}/{fp_rl.limit}" if fp_rl else "")
                    + f", Bucket[{tb_res.tier}]={tb_res.remaining}/{tb_res.burst_capacity}）"
                )
                ctx.add_step(2, "限流检测", "blocked", 85, detail)
                ctx.score = 85
                ctx.reasons.append(ReasonCode.RATE_LIMITED.value)
                ctx.action = RiskAction.BLOCK.value
                ctx.module = RiskModule.NETWORK.value
                latency = (time.perf_counter() - start_time) * 1000
                record_risk_event(
                    db,
                    client_ip=client_ip,
                    effective_ip=effective_ip,
                    path=path,
                    module=ctx.module,
                    action=ctx.action,
                    risk_score=ctx.score,
                    reasons=ctx.reasons,
                    ua=ua,
                    fingerprint_id=fp_id,
                    latency_ms=latency,
                    extra={
                        "simulated": is_simulated,
                        "pipeline_steps": ctx.pipeline_steps,
                        "details": [detail],
                    },
                )
                return _attach_gateway_headers(
                    _error_json(
                        429,
                        "请求频率超限",
                        ReasonCode.RATE_LIMITED.value,
                        retry_after=max(1, tb_res.retry_after),
                    ),
                    tb_res,
                    request_id,
                )

            # 增强：固定周期轮询检测（不拦截，仅记告警）
            cadence = analyze_request_cadence(effective_ip)
            if cadence.robotic:
                ctx.add_signal(
                    cadence.score,
                    ReasonCode.BOT_TRAJECTORY.value,
                    f"检测到固定间隔轮询脚本节律（间隔变异系数 CV={cadence.cv} < 0.08）",
                )
            ctx.add_step(
                2,
                "限流检测",
                "warn" if cadence.robotic else "pass",
                cadence.score,
                f"IP {ip_rl.count}/{ip_rl.limit} · 令牌桶[{tb_res.tier}]余 {tb_res.remaining}/{tb_res.burst_capacity}"
                + (f"；定频异常 CV={cadence.cv}" if cadence.robotic else ""),
            )

            # ── ③ Header 校验（计分不拦截）───────────────────────────────────
            hdr_res = check_headers(request.headers)
            if hdr_res.score > 0:
                ctx.score = min(100, ctx.score + hdr_res.score)
                for r in hdr_res.reasons:
                    if r not in ctx.reasons:
                        ctx.reasons.append(r)
                ctx.details.extend(hdr_res.details)
            ctx.add_step(
                3,
                "Header 校验",
                "warn" if hdr_res.score > 0 else "pass",
                hdr_res.score,
                "；".join(hdr_res.details) if hdr_res.details else "请求头完整且与 UA 声明一致",
            )

            # ── ④ IP 信誉（mock 库机房/黑名单，计分）─────────────────────────
            geo = get_geoip_provider().lookup(db, effective_ip, is_simulated=is_simulated)
            ctx.geo = geo
            if geo.score > 0:
                ctx.score = min(100, ctx.score + geo.score)
                for r in geo.reasons:
                    if r not in ctx.reasons:
                        ctx.reasons.append(r)
                ctx.details.append(f"IP 信誉命中 {geo.country}/{geo.city} ({geo.asn}) (+{geo.score})")
            ctx.add_step(
                4,
                "IP 信誉",
                "warn" if geo.score > 0 else "pass",
                geo.score,
                f"{effective_ip} -> {geo.country}/{geo.city} ({geo.asn})"
                + (" [Simulated]" if is_simulated else ""),
            )

            # ── ⑤ 蜜罐标记检查（历史触发标记，计分）───────────────────────────
            if has_trap_history(effective_ip):
                ctx.add_signal(30, ReasonCode.HONEYPOT_TRIGGERED.value, "存在近期蜜罐触发历史标记 (+30)")
                ctx.add_step(5, "蜜罐标记", "warn", 30, "存在历史蜜罐标记")
            else:
                ctx.add_step(5, "蜜罐标记", "pass", 0, "无蜜罐触发历史")

            # ── ⑥ 签名校验（仅核心数据接口 4、5；失败→ 401）──────────────────
            if _is_signature_required_path(path):
                sig_res = verify_request_signature(request.method, path, request.headers, settings, db)
                if not sig_res.ok:
                    assert sig_res.reason_code is not None
                    ctx.add_step(6, "签名校验", "blocked", 80, sig_res.message)
                    ctx.score = min(100, max(75, ctx.score))
                    if sig_res.reason_code not in ctx.reasons:
                        ctx.reasons.insert(0, sig_res.reason_code)
                    ctx.action = RiskAction.BLOCK.value
                    ctx.module = RiskModule.BUSINESS.value
                    latency = (time.perf_counter() - start_time) * 1000
                    record_risk_event(
                        db,
                        client_ip=client_ip,
                        effective_ip=effective_ip,
                        path=path,
                        module=ctx.module,
                        action=ctx.action,
                        risk_score=ctx.score,
                        reasons=ctx.reasons,
                        ua=ua,
                        fingerprint_id=fp_id,
                        latency_ms=latency,
                        extra={
                            "simulated": is_simulated,
                            "pipeline_steps": ctx.pipeline_steps,
                            "details": ctx.details + [sig_res.message],
                        },
                    )
                    return _attach_gateway_headers(
                        _error_json(sig_res.status_code, sig_res.message, sig_res.reason_code),
                        tb_res,
                        request_id,
                    )
                ctx.add_step(6, "签名校验", "pass", 0, "HMAC-SHA256 与 Nonce 防重放校验通过")
            else:
                ctx.add_step(6, "签名校验", "skip", 0, "非强制签名接口跳过")

            # ── ⑦ 累计风险分与业务接口决策 ────────────────────────────────────
            is_probe_or_helper = path in {
                "/api/v1/fingerprint/report",
                "/api/v1/behavior/trace",
                "/api/v1/challenge/pow",
                "/api/v1/trap",
                "/api/v1/trap/form",
                "/api/v1/bot/check",
                "/api/v1/waf/protected-feed",
                "/api/v1/browse/limit",
                "/api/v1/browse/mock-login",
                "/api/v1/browse/mock-logout",
                "/api/v1/ip/whoami",
                "/api/v1/ip/audit",
                "/api/v1/ip/cn-clouds",
            }

            if _is_signature_required_path(path) or path == "/api/v1/font/session":
                _merge_session_risk(ctx)
                ctx.module = RiskModule.BUSINESS.value if _is_signature_required_path(path) else RiskModule.NETWORK.value

            # 高危 >=70 对受保护业务资源执行 403 拦截（探针上报/PoW/蜜罐自身交由各自路由处理）
            if not is_probe_or_helper and ctx.score >= DECISION_THRESHOLDS["BLOCK_MIN"]:
                ctx.action = RiskAction.BLOCK.value
                primary_reason = ctx.reasons[0] if ctx.reasons else ReasonCode.BANNED.value
                ctx.add_step(7, "风险决策", "blocked", 0, f"累计风险分 {ctx.score} ≥ 70，执行拦截")
                ctx.add_step(8, "落库与广播", "done", 0, "已写入 risk_logs 并广播 SSE")
                latency = (time.perf_counter() - start_time) * 1000
                record_risk_event(
                    db,
                    client_ip=client_ip,
                    effective_ip=effective_ip,
                    path=path,
                    module=ctx.module,
                    action=ctx.action,
                    risk_score=ctx.score,
                    reasons=ctx.reasons,
                    ua=ua,
                    fingerprint_id=fp_id,
                    latency_ms=latency,
                    extra={
                        "simulated": is_simulated,
                        "pipeline_steps": ctx.pipeline_steps,
                        "details": ctx.details,
                    },
                )
                return _attach_gateway_headers(
                    _error_json(
                        403,
                        f"综合风险分 {ctx.score} 达到拦截阈值（≥70），请求已被拒绝",
                        primary_reason,
                        risk_score=ctx.score,
                        reasons=ctx.reasons,
                    ),
                    tb_res,
                    request_id,
                )

            # 到达业务路由执行
            response = await call_next(request)

            # 若路由未自行落库（探针/蜜罐路由会写入细分模块日志并置 handled_logging=True），由步骤 ⑧ 统一落库并广播
            if not ctx.handled_logging:
                if ctx.score >= DECISION_THRESHOLDS["BLOCK_MIN"]:
                    ctx.action = RiskAction.BLOCK.value
                elif ctx.action != RiskAction.CHALLENGE.value:
                    ctx.action = (
                        RiskAction.WARN.value
                        if ctx.score >= DECISION_THRESHOLDS["WARN_MIN"] or ctx.reasons
                        else RiskAction.PASS.value
                    )

                ctx.add_step(
                    7,
                    "风险决策",
                    ctx.action,
                    0,
                    f"累计风险分 {ctx.score}，决策={ctx.action}"
                    + ("（已投喂诱饵）" if ctx.decoy_served else ""),
                )
                ctx.add_step(8, "落库与广播", "done", 0, "已写入 risk_logs 并广播 SSE")
                latency = (time.perf_counter() - start_time) * 1000
                record_risk_event(
                    db,
                    client_ip=client_ip,
                    effective_ip=effective_ip,
                    path=path,
                    module=ctx.module,
                    action=ctx.action,
                    risk_score=ctx.score,
                    reasons=ctx.reasons,
                    ua=ua,
                    fingerprint_id=fp_id,
                    decoy_served=ctx.decoy_served,
                    latency_ms=latency,
                    extra={
                        "simulated": is_simulated,
                        "pipeline_steps": ctx.pipeline_steps,
                        "details": ctx.details,
                        **ctx.extra,
                    },
                )

            return _attach_gateway_headers(response, tb_res, request_id)
