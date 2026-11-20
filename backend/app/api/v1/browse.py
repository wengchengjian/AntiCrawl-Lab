"""
匿名浏览深度配额查询与实验室模拟登录端点（browse.py）。
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.config import get_settings
from app.middleware.risk import RiskContext
from app.services.browse_quota import (
    create_mock_session,
    get_browse_quota_status,
    revoke_mock_session,
)

router = APIRouter(prefix="/api/v1/browse", tags=["browse"])


class MockLoginBody(BaseModel):
    username: str = "lab_researcher"


@router.get("/limit")
def query_browse_limit(request: Request) -> Dict[str, Any]:
    """查询当前会话/IP 的匿名浏览额度（对应 pxb7 queryBrowseLimit 模型）。"""
    settings = get_settings()
    ctx: RiskContext | None = getattr(request.state, "risk_ctx", None)
    scope_key = ctx.effective_ip if ctx else (request.client.host if request.client else "127.0.0.1")
    auth_token = request.headers.get("x-lab-auth", "")
    return get_browse_quota_status(scope_key, auth_token, settings)


@router.post("/mock-login")
def mock_login(body: MockLoginBody) -> Dict[str, Any]:
    """实验室本地模拟登录，签发 X-Lab-Auth 以解锁深度翻页配额。"""
    return create_mock_session(body.username)


@router.post("/mock-logout")
def mock_logout(request: Request) -> Dict[str, Any]:
    """注销当前模拟登录令牌，恢复匿名浏览配额限制。"""
    auth_token = request.headers.get("x-lab-auth", "")
    revoked = revoke_mock_session(auth_token)
    return {"logged_out": True, "revoked": revoked}
