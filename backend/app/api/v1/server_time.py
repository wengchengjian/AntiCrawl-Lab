"""
服务端统一授时校准端点（server_time.py，对应 pzds /api/server/time 模型）。
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from fastapi import APIRouter

from app.config import get_settings

router = APIRouter(tags=["time"])
TZ_SHANGHAI = timezone(timedelta(hours=8))


@router.get("/api/v1/time")
def get_server_time() -> Dict[str, Any]:
    """返回服务端毫秒与秒级时间戳，供前端校准签名时钟偏移（不计入限流）。"""
    now_sec = time.time()
    settings = get_settings()
    return {
        "server_time_sec": int(now_sec),
        "server_time_ms": int(now_sec * 1000),
        "iso_time": datetime.fromtimestamp(now_sec, TZ_SHANGHAI).isoformat(timespec="milliseconds"),
        "sign_window_seconds": settings.sign_window_seconds,
    }
