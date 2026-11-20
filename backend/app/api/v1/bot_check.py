"""
全维度机器人检测与置信分端点（bot_check.py：GET/POST /api/v1/bot/check）。
参考 BrowserScan / BrowserLeaks / Sannysoft 指标体系输出 0–100 置信分与可解释原因。
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.constants import RiskAction, RiskModule
from app.db import get_db
from app.middleware.risk import RiskContext
from app.services.bot_detector import assess_bot_confidence
from app.services.geoip import GeoInfo
from app.services.ip_intel import get_rich_ip_profile
from app.services.risk_logger import record_risk_event

router = APIRouter(tags=["bot-detection"])


class BotCheckRequest(BaseModel):
    """前端全量 Sannysoft + BrowserScan + BrowserLeaks + Behavior 探针上报结构。"""

    ua: str = ""
    platform: str = ""
    languages: list[str] = Field(default_factory=list)
    timezone: str = ""
    screen: Dict[str, Any] = Field(default_factory=dict)
    device_memory: float = 0.0
    hardware_concurrency: int = 0
    touch_points: int = 0
    canvas_hash: str = ""
    audio_hash: str = ""
    webgl: Dict[str, Any] = Field(default_factory=dict)
    fonts: Dict[str, Any] = Field(default_factory=dict)
    automation: Dict[str, Any] = Field(default_factory=dict)
    extra_probes: Dict[str, Any] = Field(default_factory=dict)
    behavior: Optional[Dict[str, Any]] = None


def _finalize_bot_response(
    request: Request,
    db: Session,
    payload_dict: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    ctx: RiskContext | None = getattr(request.state, "risk_ctx", None)
    effective_ip = ctx.effective_ip if ctx else (request.client.host if request.client else "127.0.0.1")
    client_ip = ctx.client_ip if ctx else effective_ip
    ua = (payload_dict.get("ua") if payload_dict else "") or (ctx.ua if ctx else request.headers.get("user-agent", ""))
    fp_id = ctx.fp_id if ctx else ""
    geo = (
        ctx.geo
        if (ctx and ctx.geo)
        else GeoInfo(
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
    )
    # 若未命中本地 mock 库，自动使用实时 IP 情报补全国家/城市/ASN/机房代理标记
    rich_ip = get_rich_ip_profile(db, effective_ip, is_simulated=geo.is_simulated)
    if geo.country == "UNKNOWN" and rich_ip.get("country_code") not in {"", "UNKNOWN"}:
        is_dc = bool(rich_ip.get("is_hosting") or rich_ip.get("is_proxy"))
        geo = GeoInfo(
            ip=effective_ip,
            country=str(rich_ip.get("country_code") or "UNKNOWN"),
            city=str(rich_ip.get("city") or "Unknown"),
            asn=str(rich_ip.get("asn") or rich_ip.get("isp") or "AS0"),
            is_datacenter=is_dc,
            is_blacklist=bool(rich_ip.get("is_blacklist")),
            is_simulated=geo.is_simulated,
            score=25 if is_dc else 0,
            reasons=["DATACENTER_IP"] if is_dc else [],
        )

    assessment = assess_bot_confidence(request.headers, geo, payload=payload_dict)
    bot_score_int = int(round(assessment.bot_confidence))

    if bot_score_int >= 55:
        action = RiskAction.BLOCK.value
    elif bot_score_int >= 25:
        action = RiskAction.WARN.value
    else:
        action = RiskAction.PASS.value

    reason_codes = list(dict.fromkeys(str(r.get("code", "")) for r in assessment.reasons if r.get("code")))
    latency = (time.perf_counter() - ctx.start_time) * 1000 if ctx else 0.0
    pipeline_steps = list(ctx.pipeline_steps) if ctx else []
    pipeline_steps.append(
        {
            "step": 7,
            "name": "全维度机器人置信评估",
            "status": action,
            "delta": bot_score_int,
            "detail": f"bot_confidence={assessment.bot_confidence}%, verdict={assessment.verdict}",
        }
    )

    row = record_risk_event(
        db,
        client_ip=client_ip,
        effective_ip=effective_ip,
        path=request.url.path,
        module=RiskModule.AUTOMATION.value,
        action=action,
        risk_score=bot_score_int,
        reasons=reason_codes,
        ua=ua,
        fingerprint_id=fp_id,
        latency_ms=latency,
        extra={
            "detail_code": "BOT_CONFIDENCE_CHECK",
            "verdict": assessment.verdict,
            "bot_confidence": assessment.bot_confidence,
            "category_scores": assessment.category_scores,
            "pipeline_steps": pipeline_steps,
            "details": [r["message"] for r in assessment.reasons[:8]],
        },
    )

    if ctx is not None:
        ctx.handled_logging = True

    return {
        "request_id": row.id,
        "effective_ip": effective_ip,
        "ip_geo": {"country": geo.country, "city": geo.city, "asn": geo.asn, "is_datacenter": geo.is_datacenter},
        "bot_confidence": assessment.bot_confidence,
        "human_confidence": assessment.human_confidence,
        "verdict": assessment.verdict,
        "verdict_label": assessment.verdict_label,
        "confidence_level": assessment.confidence_level,
        "summary": assessment.summary,
        "category_scores": assessment.category_scores,
        "reasons": assessment.reasons,
        "checks": assessment.checks,
        "telemetry_coverage": assessment.telemetry_coverage,
    }


@router.get("/api/v1/bot/check")
def quick_http_bot_check(request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """纯 HTTP 协议/IP 维度快速机器人置信分检测（支持 curl 等 CLI 直接调用）。"""
    return _finalize_bot_response(request, db, payload_dict=None)


@router.post("/api/v1/bot/check")
def full_bot_check(
    payload: BotCheckRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """全量浏览器指纹 + Sannysoft + BrowserScan + BrowserLeaks + 行为轨迹综合机器人置信分检测。"""
    return _finalize_bot_response(request, db, payload_dict=payload.model_dump())
