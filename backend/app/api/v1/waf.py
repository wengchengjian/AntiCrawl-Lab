"""
边缘 WAF 透明 200 HTML/JS 动态挑战演示路由（waf.py）。
"""

from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from app.constants import ReasonCode, RiskAction, RiskModule
from app.db import get_db
from app.middleware.risk import RiskContext
from app.services.decoy import PRODUCTS_CATALOG
from app.services.js_challenge import WAF_PARAM_NAME, issue_js_challenge, verify_js_challenge_token
from app.services.risk_logger import record_risk_event

router = APIRouter(tags=["waf"])


@router.api_route("/api/v1/waf/protected-feed", methods=["GET", "POST"])
def waf_protected_feed(
    request: Request,
    timestamp__1366: str = Query(default=""),
    db: Session = Depends(get_db),
) -> Any:
    """
    复刻阿里云 ESA/WAF 动态令牌挑战：
    - 缺失或无效 `?timestamp__1366=...` 时，返回 200 text/html 混淆 JS 挑战页（非 403、非 JSON）；
    - 验证通过后返回受保护的 JSON 商品流并原子消耗该一次性令牌。
    """
    ctx: RiskContext | None = getattr(request.state, "risk_ctx", None)
    effective_ip = ctx.effective_ip if ctx else (request.client.host if request.client else "127.0.0.1")
    client_ip = ctx.client_ip if ctx else effective_ip
    ua = ctx.ua if ctx else request.headers.get("user-agent", "")
    fp_id = ctx.fp_id if ctx else ""
    latency = (time.perf_counter() - ctx.start_time) * 1000 if ctx else 0.0

    check = verify_js_challenge_token(timestamp__1366, effective_ip) if timestamp__1366 else {"ok": False, "reason": "missing_param"}

    if not check.get("ok"):
        nonce_id, html = issue_js_challenge(effective_ip, request.url.path)
        if ctx is not None:
            ctx.handled_logging = True
            ctx.add_step(
                7,
                "WAF 动态 JS 挑战",
                "challenge",
                20,
                f"缺少或无效 {WAF_PARAM_NAME}（{check.get('reason')}），下发 200 HTML 挑战页",
            )
        record_risk_event(
            db,
            client_ip=client_ip,
            effective_ip=effective_ip,
            path=request.url.path,
            module=RiskModule.NETWORK.value,
            action=RiskAction.CHALLENGE.value,
            risk_score=max(45, ctx.score if ctx else 45),
            reasons=[ReasonCode.POW_REQUIRED.value],
            ua=ua,
            fingerprint_id=fp_id,
            latency_ms=latency,
            extra={
                "detail_code": "WAF_JS_CHALLENGE_ISSUED",
                "param_name": WAF_PARAM_NAME,
                "nonce_id": nonce_id,
                "verify_failure": check.get("reason"),
                "pipeline_steps": ctx.pipeline_steps if ctx else [],
            },
        )
        return HTMLResponse(
            content=html,
            status_code=200,
            headers={
                "Cache-Control": "no-cache, no-store",
                "X-WAF-Challenge": "js-dynamic-token",
            },
        )

    if ctx is not None:
        ctx.handled_logging = True
        ctx.add_step(
            7,
            "WAF 动态 JS 挑战",
            "pass",
            0,
            f"{WAF_PARAM_NAME} 校验通过（env={check['env_tag']}, 耗时={check['solved_in_ms']}ms）",
        )
    record_risk_event(
        db,
        client_ip=client_ip,
        effective_ip=effective_ip,
        path=request.url.path,
        module=RiskModule.NETWORK.value,
        action=RiskAction.PASS.value,
        risk_score=ctx.score if ctx else 0,
        reasons=ctx.reasons if ctx else [],
        ua=ua,
        fingerprint_id=fp_id,
        latency_ms=latency,
        extra={
            "detail_code": "WAF_JS_CHALLENGE_PASSED",
            "param_name": WAF_PARAM_NAME,
            "env_tag": check["env_tag"],
            "pipeline_steps": ctx.pipeline_steps if ctx else [],
        },
    )

    items = [
        {"id": p.id, "sku": p.sku, "name": p.name, "category": p.category, "price": p.real_price}
        for p in PRODUCTS_CATALOG
    ]
    return JSONResponse(
        status_code=200,
        content={
            "waf_verified": True,
            "token_param": WAF_PARAM_NAME,
            "env_tag": check["env_tag"],
            "solved_in_ms": check["solved_in_ms"],
            "items": items,
        },
    )
