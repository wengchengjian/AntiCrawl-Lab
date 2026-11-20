"""
真实 IP 情报、地域地图坐标与 VPN/代理穿透检测端点（ip_intel.py）。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.constants import ReasonCode, RiskAction, RiskModule
from app.db import get_db
from app.middleware.risk import RiskContext
from app.services.cn_cloud_ranges import get_supported_cn_cloud_summary
from app.services.ip_intel import evaluate_vpn_and_geo_leaks, get_rich_ip_profile
from app.services.risk_logger import record_risk_event

router = APIRouter(prefix="/api/v1/ip", tags=["ip-intel"])


class IpAuditRequest(BaseModel):
    """前端多通道 VPN 穿透探测上报体。"""

    webrtc_public_ips: List[str] = Field(default_factory=list)
    webrtc_local_candidates: List[str] = Field(default_factory=list)
    overseas_echo_ip: str = ""
    domestic_echo_ip: str = ""
    browser_timezone: str = ""
    browser_tz_offset: Optional[int] = None
    browser_languages: List[str] = Field(default_factory=list)


@router.get("/whoami")
def ip_whoami(request: Request, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """快速查询当前出口 IP 的真实地理归属、ISP/ASN、rDNS 与托管/代理标记。"""
    ctx: RiskContext | None = getattr(request.state, "risk_ctx", None)
    effective_ip = ctx.effective_ip if ctx else (request.client.host if request.client else "127.0.0.1")
    client_ip = ctx.client_ip if ctx else effective_ip
    is_sim = ctx.is_simulated if ctx else False
    profile = get_rich_ip_profile(db, effective_ip, is_simulated=is_sim)
    return {
        "client_ip": client_ip,
        "effective_ip": effective_ip,
        "profile": profile,
    }


@router.get("/cn-clouds")
def list_cn_cloud_providers() -> Dict[str, Any]:
    """返回内置的国内主流云厂商与 IDC 机房识别目录（CIDR 数量与 ASN 列表）。"""
    providers = get_supported_cn_cloud_summary()
    return {
        "total_vendors": len(providers),
        "providers": providers,
    }


@router.post("/audit")
def ip_vpn_audit(
    payload: IpAuditRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """执行全维度 IP 地域 + WebRTC STUN 穿透 + 国内外规则分流 + 代理头/rDNS/时区对抗审计。"""
    ctx: RiskContext | None = getattr(request.state, "risk_ctx", None)
    effective_ip = ctx.effective_ip if ctx else (request.client.host if request.client else "127.0.0.1")
    client_ip = ctx.client_ip if ctx else effective_ip
    is_sim = ctx.is_simulated if ctx else False
    ua = ctx.ua if ctx else request.headers.get("user-agent", "")
    fp_id = ctx.fp_id if ctx else ""

    report = evaluate_vpn_and_geo_leaks(
        db,
        effective_ip=effective_ip,
        is_simulated=is_sim,
        headers=request.headers,
        webrtc_public_ips=payload.webrtc_public_ips,
        webrtc_local_candidates=payload.webrtc_local_candidates,
        overseas_echo_ip=payload.overseas_echo_ip,
        domestic_echo_ip=payload.domestic_echo_ip,
        browser_timezone=payload.browser_timezone,
        browser_tz_offset=payload.browser_tz_offset,
        browser_languages=payload.browser_languages,
    )

    risk_score = int(report["risk_score"])
    action = (
        RiskAction.BLOCK.value
        if risk_score >= 70
        else (RiskAction.WARN.value if risk_score >= 25 else RiskAction.PASS.value)
    )
    reasons: List[str] = []
    if report["primary_profile"].get("is_hosting") or report["primary_profile"].get("is_proxy"):
        reasons.append(ReasonCode.DATACENTER_IP.value)
    if report["vpn_pierced"] or any(f["id"] == "IP_TZ_VS_BROWSER_TZ" for f in report["findings"]):
        reasons.append(ReasonCode.FINGERPRINT_CONFLICT.value)

    latency = (time.perf_counter() - ctx.start_time) * 1000 if ctx else 0.0
    row = record_risk_event(
        db,
        client_ip=client_ip,
        effective_ip=effective_ip,
        path=request.url.path,
        module=RiskModule.NETWORK.value,
        action=action,
        risk_score=risk_score,
        reasons=reasons,
        ua=ua,
        fingerprint_id=fp_id,
        latency_ms=latency,
        extra={
            "detail_code": "IP_VPN_GEO_AUDIT",
            "vpn_pierced": report["vpn_pierced"],
            "suspected_real_ip": report["suspected_real_ip"],
            "suspected_proxy_ip": report["suspected_proxy_ip"],
            "concealment_score": report["concealment_score"],
            "details": [f["detail"] for f in report["findings"][:6]],
        },
    )
    if ctx is not None:
        ctx.handled_logging = True

    report["request_id"] = row.id
    return report
