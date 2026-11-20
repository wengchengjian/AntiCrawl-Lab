"""
用户行为轨迹上报与量化分析端点（端点 3：POST /api/v1/behavior/trace）。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.cache import get_cache
from app.constants import DECISION_THRESHOLDS, RiskAction, RiskModule
from app.db import get_db
from app.middleware.risk import RiskContext
from app.services.behavior import evaluate_behavior, record_visit
from app.services.risk_logger import record_risk_event

router = APIRouter(tags=["behavior"])


class BehaviorTraceRequest(BaseModel):
    """10.2 行为采集上报体结构。"""

    points: List[Dict[str, Any]] = Field(default_factory=list)
    keys: List[Dict[str, Any]] = Field(default_factory=list)
    scrolls: List[Dict[str, Any]] = Field(default_factory=list)
    page_focus_events: List[Dict[str, Any]] = Field(default_factory=list)
    page_seconds: float = 0.0
    visit_path: List[str] = Field(default_factory=list)


@router.post("/api/v1/behavior/trace")
def report_behavior_trace(
    payload: BehaviorTraceRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """接收鼠标/键盘/滚动轨迹与页面访问路径，返回行为风险分与特征标记。"""
    ctx: RiskContext | None = getattr(request.state, "risk_ctx", None)
    effective_ip = ctx.effective_ip if ctx else (request.client.host if request.client else "127.0.0.1")
    client_ip = ctx.client_ip if ctx else effective_ip
    session_id = ctx.session_id if ctx else effective_ip
    fp_id = ctx.fp_id if ctx else ""
    ua = ctx.ua if ctx else request.headers.get("user-agent", "")

    # 更新 10.3 会话访问顺序图
    for vp in payload.visit_path:
        record_visit(session_id, vp)
        if session_id != effective_ip:
            record_visit(effective_ip, vp)

    beh_res = evaluate_behavior(payload.model_dump())

    # 缓存行为分与交互总量，供业务数据接口读取
    cache = get_cache()
    total_events = len(payload.points) + len(payload.keys) + len(payload.scrolls)
    cache.set(f"beh_risk_ip:{effective_ip}", str(beh_res.score), ex=1800)
    cache.set(f"beh_flags_ip:{effective_ip}", ",".join(beh_res.flags), ex=1800)
    cache.set(f"beh_events_count:{session_id}", str(total_events), ex=1800)
    cache.set(f"beh_events_count:{effective_ip}", str(total_events), ex=1800)
    cache.set(f"beh_metrics_ip:{effective_ip}", str(beh_res.metrics.get("trusted_ratio", 1.0)), ex=1800)

    total_score = min(100, (ctx.score if ctx else 0) + beh_res.score)
    combined_reasons = list(dict.fromkeys((ctx.reasons if ctx else []) + beh_res.flags))

    if total_score >= DECISION_THRESHOLDS["BLOCK_MIN"]:
        action = RiskAction.BLOCK.value
    elif total_score >= DECISION_THRESHOLDS["WARN_MIN"] or combined_reasons:
        action = RiskAction.WARN.value
    else:
        action = RiskAction.PASS.value

    latency = (time.perf_counter() - ctx.start_time) * 1000 if ctx else 0.0
    pipeline_steps = list(ctx.pipeline_steps) if ctx else []
    pipeline_steps.append(
        {
            "step": 7,
            "name": "行为动力学分析",
            "status": action,
            "delta": beh_res.score,
            "detail": "；".join(beh_res.details) if beh_res.details else "轨迹与击键分布符合自然人类交互特征",
        }
    )

    record_risk_event(
        db,
        client_ip=client_ip,
        effective_ip=effective_ip,
        path=request.url.path,
        module=RiskModule.BEHAVIOR.value,
        action=action,
        risk_score=total_score,
        reasons=combined_reasons,
        ua=ua,
        fingerprint_id=fp_id,
        latency_ms=latency,
        extra={
            "simulated": ctx.is_simulated if ctx else False,
            "pipeline_steps": pipeline_steps,
            "behavior_metrics": beh_res.metrics,
            "details": beh_res.details,
        },
    )

    if ctx is not None:
        ctx.handled_logging = True

    return {
        "behavior_score": beh_res.score,
        "flags": beh_res.flags,
        "metrics": beh_res.metrics,
        "details": beh_res.details,
    }
