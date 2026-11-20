"""
SSE 实时风控事件流端点（端点 9：GET /api/v1/events）。
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from app.events import get_event_bus

router = APIRouter(tags=["events"])


@router.get("/api/v1/events")
async def stream_risk_events() -> StreamingResponse:
    """推送实时 `event: risk` SSE 流，关闭代理缓冲确保 1 秒内即时触达仪表盘。"""
    bus = get_event_bus()
    return StreamingResponse(
        bus.stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
