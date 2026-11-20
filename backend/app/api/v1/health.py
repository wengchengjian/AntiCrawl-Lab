"""
健康检查与规则元数据下发端点（端点 1：GET /api/v1/health）。
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter

from app.cache import get_cache
from app.config import get_settings
from app.constants import build_rules_meta

router = APIRouter(tags=["health"])


@router.get("/api/v1/health")
def health_check() -> Dict[str, Any]:
    """返回服务健康状态、缓存降级模式（real/fakeredis）、LAB_MODE 以及前后端共享规则元数据。"""
    settings = get_settings()
    cache = get_cache()
    try:
        cache.ping()
        redis_ok = True
    except Exception:
        redis_ok = False

    return {
        "status": "ok",
        "redis_mode": cache.mode,
        "redis_ok": redis_ok,
        "lab_mode": settings.lab_mode,
        "rules_meta": build_rules_meta(settings),
    }
