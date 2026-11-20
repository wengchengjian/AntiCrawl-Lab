"""
浏览器指纹上报与一致性/自动化检测端点（端点 2：POST /api/v1/fingerprint/report）。
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.cache import get_cache
from app.constants import DECISION_THRESHOLDS, ReasonCode, RiskAction, RiskModule
from app.db import get_db
from app.middleware.risk import RiskContext
from app.models.tables import Fingerprint
from app.services.automation import evaluate_automation
from app.services.consistency import evaluate_consistency
from app.services.geoip import GeoInfo
from app.services.honeypot import now_iso
from app.services.risk_logger import record_risk_event

router = APIRouter(tags=["fingerprint"])


class ScreenPayload(BaseModel):
    width: int = 0
    height: int = 0
    availWidth: int = 0
    availHeight: int = 0
    colorDepth: int = 24
    devicePixelRatio: float = 1.0


class WebGLPayload(BaseModel):
    vendor: str = ""
    renderer: str = ""
    masked: bool = False
    params_hash: str = ""


class FontsPayload(BaseModel):
    detected: List[str] = Field(default_factory=list)
    count: int = 0


class AutomationPayload(BaseModel):
    webdriver: bool = False
    webdriver_getter_tampered: bool = False
    cdc_keys: List[str] = Field(default_factory=list)
    selenium_keys: List[str] = Field(default_factory=list)
    legacy_keys: List[str] = Field(default_factory=list)
    cdp_console_probe: bool = False
    has_window_chrome: bool | None = None
    plugins_length: int | None = None
    hooked_native: bool = False
    iframe_mismatch: bool = False
    devtools_open: bool = False
    stack_automation_frame: bool = False


class FingerprintReportRequest(BaseModel):
    """9.2 指纹探针上报体结构（兼容基础字段与增强反伪装探针）。"""

    ua: str = ""
    platform: str = ""
    languages: List[str] = Field(default_factory=list)
    timezone: str = ""
    screen: ScreenPayload = Field(default_factory=ScreenPayload)
    device_memory: float = 0.0
    hardware_concurrency: int = 0
    touch_points: int = 0
    canvas_hash: str = ""
    audio_hash: str = ""
    webgl: WebGLPayload = Field(default_factory=WebGLPayload)
    fonts: FontsPayload = Field(default_factory=FontsPayload)
    automation: AutomationPayload = Field(default_factory=AutomationPayload)
    extra_probes: Dict[str, Any] = Field(default_factory=dict)


@router.post("/api/v1/fingerprint/report")
def report_fingerprint(
    payload: FingerprintReportRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """接收前端全量指纹探针，执行一致性矩阵 + 自动化特征 + 指纹复用检测并落库。"""
    ctx: RiskContext | None = getattr(request.state, "risk_ctx", None)
    effective_ip = ctx.effective_ip if ctx else (request.client.host if request.client else "127.0.0.1")
    client_ip = ctx.client_ip if ctx else effective_ip
    geo = ctx.geo if (ctx and ctx.geo) else GeoInfo(
        ip=effective_ip,
        country="UNKNOWN",
        city="Unknown",
        asn="AS0",
        is_datacenter=False,
        is_blacklist=False,
        is_simulated=False,
        score=0,
        reasons=[],
    )

    payload_dict = payload.model_dump()
    cons_res = evaluate_consistency(payload_dict, request.headers, geo)
    auto_res = evaluate_automation(payload_dict["automation"], ua=payload.ua or (ctx.ua if ctx else ""))

    fp_id = cons_res.fp_id
    fonts_hash = hashlib.sha256(
        ",".join(sorted(payload.fonts.detected)).encode("utf-8")
    ).hexdigest()[:16]
    now_str = now_iso()

    # 落库或更新 fingerprints 表
    existing = db.query(Fingerprint).filter(Fingerprint.fp_id == fp_id).first()
    if existing is None:
        fp_row = Fingerprint(
            fp_id=fp_id,
            ua=payload.ua,
            platform=payload.platform,
            languages=json.dumps(payload.languages, ensure_ascii=False),
            timezone=payload.timezone,
            screen_width=payload.screen.width,
            screen_height=payload.screen.height,
            color_depth=payload.screen.colorDepth,
            device_pixel_ratio=payload.screen.devicePixelRatio,
            device_memory=payload.device_memory,
            hardware_concurrency=payload.hardware_concurrency,
            touch_points=payload.touch_points,
            canvas_hash=payload.canvas_hash,
            webgl_vendor=payload.webgl.vendor,
            webgl_renderer=payload.webgl.renderer,
            webgl_masked=1 if cons_res.webgl_masked else 0,
            audio_hash=payload.audio_hash,
            font_count=payload.fonts.count,
            fonts_hash=fonts_hash,
            automation_flags=json.dumps(payload.automation.model_dump(), ensure_ascii=False),
            created_at=now_str,
            last_seen_at=now_str,
            hit_ips=cons_res.hit_ips,
            extra_probes=json.dumps(payload.extra_probes, ensure_ascii=False),
        )
        db.add(fp_row)
    else:
        existing.ua = payload.ua
        existing.platform = payload.platform
        existing.languages = json.dumps(payload.languages, ensure_ascii=False)
        existing.timezone = payload.timezone
        existing.screen_width = payload.screen.width
        existing.screen_height = payload.screen.height
        existing.color_depth = payload.screen.colorDepth
        existing.device_pixel_ratio = payload.screen.devicePixelRatio
        existing.device_memory = payload.device_memory
        existing.hardware_concurrency = payload.hardware_concurrency
        existing.touch_points = payload.touch_points
        existing.webgl_vendor = payload.webgl.vendor
        existing.webgl_renderer = payload.webgl.renderer
        existing.webgl_masked = 1 if cons_res.webgl_masked else 0
        existing.font_count = payload.fonts.count
        existing.fonts_hash = fonts_hash
        existing.automation_flags = json.dumps(payload.automation.model_dump(), ensure_ascii=False)
        existing.last_seen_at = now_str
        existing.hit_ips = cons_res.hit_ips
        existing.extra_probes = json.dumps(payload.extra_probes, ensure_ascii=False)
    db.commit()

    # 合并中间件前置风险 + 指纹一致性风险 + 自动化特征风险
    base_score = ctx.score if ctx else 0
    base_reasons = list(ctx.reasons) if ctx else []
    combined_warnings = list(dict.fromkeys(base_reasons + cons_res.reasons + auto_res.reasons))
    fp_only_score = min(100, cons_res.score + auto_res.score)
    total_score = min(100, base_score + cons_res.score + auto_res.score)

    # 缓存指纹风险供后续商品/价格接口联动拦截
    cache = get_cache()
    fp_reasons_only = list(dict.fromkeys(cons_res.reasons + auto_res.reasons))
    cache.set(f"fp_risk:{fp_id}", str(fp_only_score), ex=1800)
    cache.set(f"fp_reasons:{fp_id}", ",".join(fp_reasons_only), ex=1800)
    cache.set(f"fp_risk_ip:{effective_ip}", str(fp_only_score), ex=1800)
    cache.set(f"fp_reasons_ip:{effective_ip}", ",".join(fp_reasons_only), ex=1800)
    cache.set(f"ip_last_fp:{effective_ip}", fp_id, ex=1800)

    latency = (time.perf_counter() - ctx.start_time) * 1000 if ctx else 0.0
    pipeline_steps = list(ctx.pipeline_steps) if ctx else []
    pipeline_steps.append(
        {
            "step": 7,
            "name": "指纹与自动化复核",
            "status": "block" if total_score >= DECISION_THRESHOLDS["BLOCK_MIN"] else ("warn" if total_score >= DECISION_THRESHOLDS["WARN_MIN"] or fp_only_score > 0 else "pass"),
            "delta": fp_only_score,
            "detail": f"破绽={len(cons_res.conflicts)} 条，自动化告警={len(auto_res.findings)} 条",
        }
    )

    def decide_action(sc: int, has_warn: bool) -> str:
        if sc >= DECISION_THRESHOLDS["BLOCK_MIN"]:
            return RiskAction.BLOCK.value
        if sc >= DECISION_THRESHOLDS["WARN_MIN"] or has_warn:
            return RiskAction.WARN.value
        return RiskAction.PASS.value

    conflict_dicts = [c.to_dict() for c in cons_res.conflicts]

    # 按 9.3 规范：每条一致性破绽单独落一条 risk_logs（module=fingerprint），便于画像分组展示
    if cons_res.conflicts:
        for idx, c in enumerate(cons_res.conflicts):
            per_reasons = [ReasonCode.FINGERPRINT_CONFLICT.value]
            if idx == len(cons_res.conflicts) - 1:
                for extra_r in cons_res.reasons:
                    if extra_r not in per_reasons:
                        per_reasons.append(extra_r)
                for extra_r in base_reasons:
                    if extra_r not in per_reasons:
                        per_reasons.append(extra_r)
            record_risk_event(
                db,
                client_ip=client_ip,
                effective_ip=effective_ip,
                path=request.url.path,
                module=RiskModule.FINGERPRINT.value,
                action=decide_action(total_score, True),
                risk_score=total_score,
                reasons=per_reasons,
                ua=payload.ua or (ctx.ua if ctx else ""),
                fingerprint_id=fp_id,
                latency_ms=latency,
                extra={
                    "simulated": ctx.is_simulated if ctx else False,
                    "pipeline_steps": pipeline_steps,
                    "conflict_item": c.to_dict(),
                    "conflicts": conflict_dicts,
                    "enhanced_findings": cons_res.enhanced_findings,
                    "automation_findings": auto_res.findings,
                },
            )
    else:
        record_risk_event(
            db,
            client_ip=client_ip,
            effective_ip=effective_ip,
            path=request.url.path,
            module=RiskModule.FINGERPRINT.value,
            action=decide_action(total_score, bool(cons_res.reasons or base_reasons)),
            risk_score=total_score,
            reasons=list(dict.fromkeys(base_reasons + cons_res.reasons)),
            ua=payload.ua or (ctx.ua if ctx else ""),
            fingerprint_id=fp_id,
            latency_ms=latency,
            extra={
                "simulated": ctx.is_simulated if ctx else False,
                "pipeline_steps": pipeline_steps,
                "conflicts": [],
                "enhanced_findings": cons_res.enhanced_findings,
                "automation_findings": auto_res.findings,
            },
        )

    # 若检测到自动化特征（webdriver / $cdc_ / CDP / hooked_native），额外落一条 module=automation 日志
    if auto_res.score > 0:
        record_risk_event(
            db,
            client_ip=client_ip,
            effective_ip=effective_ip,
            path=request.url.path,
            module=RiskModule.AUTOMATION.value,
            action=decide_action(total_score, True),
            risk_score=total_score,
            reasons=auto_res.reasons,
            ua=payload.ua or (ctx.ua if ctx else ""),
            fingerprint_id=fp_id,
            latency_ms=latency,
            extra={
                "simulated": ctx.is_simulated if ctx else False,
                "pipeline_steps": pipeline_steps,
                "automation_findings": auto_res.findings,
                "conflicts": conflict_dicts,
            },
        )

    if ctx is not None:
        ctx.handled_logging = True

    return {
        "fp_id": fp_id,
        "risk_score": total_score,
        "warnings": combined_warnings,
        "conflicts": conflict_dicts,
        "enhanced_findings": cons_res.enhanced_findings,
        "automation_findings": auto_res.findings,
        "hit_ips": cons_res.hit_ips,
    }
