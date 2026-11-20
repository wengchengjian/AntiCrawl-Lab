"""
动态会话字体下发端点（端点 6：GET /api/v1/font/session）。
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import Response

from app.middleware.risk import RiskContext
from app.services.fonts import select_variant_for_session

router = APIRouter(tags=["font"])


@router.get("/api/v1/font/session")
def get_session_font(request: Request) -> Response:
    """根据当前会话 ID 选定 8 个字体变体之一，返回二进制字体及 X-Font-Seed 头。"""
    ctx: RiskContext | None = getattr(request.state, "risk_ctx", None)
    session_id = (
        request.query_params.get("sid")
        or (ctx.session_id if ctx else "")
        or (request.client.host if request.client else "default-session")
    )
    variant = select_variant_for_session(session_id)
    font_bytes = variant.file_path.read_bytes()
    media_type = "font/woff2" if variant.fmt == "woff2" else "font/woff"

    return Response(
        content=font_bytes,
        media_type=media_type,
        headers={
            "X-Font-Seed": variant.seed,
            "X-Font-Variant": str(variant.variant_id),
            "Cache-Control": "no-store",
            "Access-Control-Expose-Headers": "X-Font-Seed, X-Font-Variant",
        },
    )
