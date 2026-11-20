"""
蜜罐诱捕端点（端点 8：GET /api/v1/trap 及隐藏表单蜜罐 POST /api/v1/trap/form）。
"""

from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import get_settings
from app.constants import ReasonCode, RiskAction, RiskModule
from app.db import get_db
from app.middleware.risk import RiskContext
from app.services.honeypot import ban_ip
from app.services.risk_logger import record_risk_event

router = APIRouter(tags=["honeypot"])


class TrapFormPayload(BaseModel):
    """隐藏表单域提交载荷（第 8.4 节第 3 种蜜罐形态）。"""

    honeypot_field: str = ""
    email_trap: str = ""
    note: str = ""


def _trigger_honeypot_ban(
    request: Request,
    db: Session,
    trigger_detail: str,
) -> JSONResponse:
    settings = get_settings()
    ctx: RiskContext | None = getattr(request.state, "risk_ctx", None)
    effective_ip = ctx.effective_ip if ctx else (request.client.host if request.client else "127.0.0.1")
    client_ip = ctx.client_ip if ctx else effective_ip
    ua = ctx.ua if ctx else request.headers.get("user-agent", "")
    fp_id = ctx.fp_id if ctx else ""

    ban_ip(
        db,
        ip=effective_ip,
        reason_code=ReasonCode.HONEYPOT_TRIGGERED.value,
        duration_seconds=settings.ban_seconds,
    )

    if ctx is not None:
        ctx.add_step(7, "蜜罐诱捕", "blocked", 100, trigger_detail)
        ctx.add_step(8, "落库与广播", "done", 0, "已封禁并广播 HONEYPOT_TRIGGERED")
        ctx.handled_logging = True
        latency = (time.perf_counter() - ctx.start_time) * 1000
    else:
        latency = 0.0

    record_risk_event(
        db,
        client_ip=client_ip,
        effective_ip=effective_ip,
        path=request.url.path,
        module=RiskModule.NETWORK.value,
        action=RiskAction.BLOCK.value,
        risk_score=100,
        reasons=[ReasonCode.HONEYPOT_TRIGGERED.value],
        ua=ua,
        fingerprint_id=fp_id,
        latency_ms=latency,
        extra={
            "simulated": ctx.is_simulated if ctx else False,
            "pipeline_steps": ctx.pipeline_steps if ctx else [],
            "details": [trigger_detail],
        },
    )

    return JSONResponse(
        status_code=403,
        content={
            "code": 403,
            "message": f"触发隐藏蜜罐陷阱，IP {effective_ip} 已被封禁 {settings.ban_seconds} 秒",
            "risk_reason": ReasonCode.HONEYPOT_TRIGGERED.value,
            "banned_ip": effective_ip,
            "ban_seconds": settings.ban_seconds,
        },
    )


@router.get("/api/v1/trap")
def trap_endpoint(request: Request, db: Session = Depends(get_db)) -> JSONResponse:
    """隐藏链接蜜罐：任何访问即刻写入 bans 表并缓存封禁，返回 403 HONEYPOT_TRIGGERED。"""
    return _trigger_honeypot_ban(request, db, "访问了隐藏蜜罐链接 /api/v1/trap")


@router.post("/api/v1/trap/form")
def trap_form_endpoint(
    payload: TrapFormPayload,
    request: Request,
    db: Session = Depends(get_db),
) -> Any:
    """隐藏表单蜜罐：若隐藏字段非空即判定为自动化填表爬虫并封禁。"""
    if payload.honeypot_field.strip() or payload.email_trap.strip():
        return _trigger_honeypot_ban(
            request,
            db,
            "提交了隐藏表单诱饵字段（honeypot_field/email_trap 非空）",
        )
    return {"status": "ok", "message": "正常表单校验通过（未填写隐藏蜜罐域）"}
