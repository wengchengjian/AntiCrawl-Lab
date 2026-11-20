"""
匿名浏览深度配额与实验室模拟登录服务（browse_quota.py）。

灵感与教学目标：
- 复刻商业站常见的 `queryBrowseLimit` 策略：允许匿名游客与搜索引擎正常浏览前 N 页（默认 1–2 页），
  当试图深度翻页（第 3 页起）或累计浏览超额时，强制要求登录态（X-Lab-Auth）或通过 PoW 算力挑战。
存储原则：
- 全部配额计数与模拟会话仅存 cache.py，不新增 SQLite 表（严守 5 张表架构契约）。
"""

from __future__ import annotations

import secrets
from typing import Any, Dict, Optional

from app.cache import get_cache
from app.config import Settings

AUTH_TTL_SECONDS = 3600
QUOTA_TTL_SECONDS = 1800


def create_mock_session(username: str) -> Dict[str, Any]:
    """创建本地教学用模拟登录会话并返回 X-Lab-Auth Token。"""
    clean_name = (username.strip() or "lab_researcher")[:32]
    token = f"lab_{secrets.token_urlsafe(20)}"
    get_cache().set(f"lab_auth:{token}", clean_name, ex=AUTH_TTL_SECONDS)
    return {
        "token": token,
        "username": clean_name,
        "expires_in": AUTH_TTL_SECONDS,
    }


def get_mock_user(auth_token: str) -> Optional[str]:
    """校验 X-Lab-Auth 模拟登录令牌，有效返回用户名。"""
    if not auth_token or not auth_token.strip():
        return None
    return get_cache().get(f"lab_auth:{auth_token.strip()}")


def revoke_mock_session(auth_token: str) -> bool:
    """注销模拟登录令牌。"""
    if not auth_token or not auth_token.strip():
        return False
    return get_cache().delete(f"lab_auth:{auth_token.strip()}") > 0


def get_browse_quota_status(
    scope_key: str,
    auth_token: str,
    settings: Settings,
) -> Dict[str, Any]:
    """查询当前会话/IP 的匿名浏览配额状态。"""
    username = get_mock_user(auth_token)
    logged_in = username is not None
    raw_cnt = get_cache().get(f"browse_views:{scope_key}")
    current_views = int(raw_cnt) if (raw_cnt and raw_cnt.isdigit()) else 0
    remaining = max(0, settings.anon_max_views - current_views)

    return {
        "logged_in": logged_in,
        "username": username,
        "max_anon_page": settings.anon_max_page,
        "max_anon_views": settings.anon_max_views,
        "current_views": current_views,
        "remaining_views": remaining if not logged_in else settings.anon_max_views,
        "require_login": (not logged_in) and remaining <= 0,
    }


def check_and_record_page_browse(
    scope_key: str,
    page: int,
    auth_token: str,
    pow_ok: bool,
    settings: Settings,
) -> TupleResult:
    """
    检查翻页是否超出匿名浏览深度或累计配额：
    - 已登录（X-Lab-Auth 有效）或携带有效 X-PoW-Token：直接放行；
    - 匿名状态且 page > anon_max_page 或 current_views >= anon_max_views：拒绝并引导登录/PoW；
    - 否则累计数并返回最新配额快照。
    """
    username = get_mock_user(auth_token)
    logged_in = username is not None
    cache = get_cache()
    key = f"browse_views:{scope_key}"
    raw_cnt = cache.get(key)
    current_views = int(raw_cnt) if (raw_cnt and raw_cnt.isdigit()) else 0

    if logged_in or pow_ok:
        new_views = current_views + 1
        cache.set(key, str(new_views), ex=QUOTA_TTL_SECONDS)
        return TupleResult(
            allowed=True,
            reason="",
            quota={
                "logged_in": logged_in,
                "username": username,
                "max_anon_page": settings.anon_max_page,
                "max_anon_views": settings.anon_max_views,
                "current_views": new_views,
                "remaining_views": max(0, settings.anon_max_views - new_views),
                "require_login": False,
            },
        )

    if page > settings.anon_max_page:
        return TupleResult(
            allowed=False,
            reason=f"匿名会话最多允许免费浏览第 {settings.anon_max_page} 页，访问第 {page} 页需先模拟登录或完成 PoW 挑战",
            quota=get_browse_quota_status(scope_key, auth_token, settings),
        )

    if current_views >= settings.anon_max_views:
        return TupleResult(
            allowed=False,
            reason=f"匿名累计浏览额度（{settings.anon_max_views} 次）已耗尽，请先模拟登录或完成 PoW 挑战",
            quota=get_browse_quota_status(scope_key, auth_token, settings),
        )

    new_views = current_views + 1
    cache.set(key, str(new_views), ex=QUOTA_TTL_SECONDS)
    return TupleResult(
        allowed=True,
        reason="",
        quota={
            "logged_in": False,
            "username": None,
            "max_anon_page": settings.anon_max_page,
            "max_anon_views": settings.anon_max_views,
            "current_views": new_views,
            "remaining_views": max(0, settings.anon_max_views - new_views),
            "require_login": False,
        },
    )


class TupleResult:
    """浏览配额检查结果。"""

    def __init__(self, allowed: bool, reason: str, quota: Dict[str, Any]) -> None:
        self.allowed = allowed
        self.reason = reason
        self.quota = quota
