"""
工作量证明挑战（PoW）签发与验证端点（端点 7：POST /api/v1/challenge/pow）。
"""

from __future__ import annotations

import json
from typing import Any, Dict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.cache import get_cache
from app.config import get_settings
from app.constants import ReasonCode
from app.middleware.risk import RiskContext
from app.services.pow import issue_pow_challenge, verify_pow_answer

router = APIRouter(tags=["challenge"])


@router.post("/api/v1/challenge/pow")
async def pow_challenge_endpoint(request: Request) -> Any:
    """
    契约 7.1 端点 7：
    - 无 body 或无 answer 时：签发新挑战 `{difficulty, data, expires}`；
    - 携带 `{answer}`（及可选 `data`）时：校验 SHA-256 前导零并返回 `{token, expires_in}`。
    """
    settings = get_settings()
    ctx: RiskContext | None = getattr(request.state, "risk_ctx", None)
    scope_key = ctx.effective_ip if ctx else (request.client.host if request.client else "127.0.0.1")

    raw_body = await request.body()
    body_data: Dict[str, Any] = {}
    if raw_body.strip():
        try:
            parsed = json.loads(raw_body.decode("utf-8"))
            if isinstance(parsed, dict):
                body_data = parsed
        except Exception:
            return JSONResponse(
                status_code=400,
                content={"code": 400, "message": "无效的 JSON 请求体", "risk_reason": ReasonCode.POW_REQUIRED.value},
            )

    if "answer" not in body_data or body_data.get("answer") is None:
        challenge = issue_pow_challenge(settings.pow_difficulty, scope_key)
        get_cache().set(f"pow_last:{scope_key}", challenge["data"], ex=60)
        return challenge

    answer = str(body_data["answer"])
    chal_data = str(body_data.get("data") or "").strip()
    if not chal_data:
        chal_data = get_cache().get(f"pow_last:{scope_key}") or ""

    verified = verify_pow_answer(chal_data, answer, scope_key)
    if verified is None:
        return JSONResponse(
            status_code=403,
            content={
                "code": 403,
                "message": "PoW 工作量证明校验失败或挑战已过期",
                "risk_reason": ReasonCode.POW_REQUIRED.value,
            },
        )
    return verified
