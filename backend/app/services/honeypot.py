"""
蜜罐封禁、状态查询与一键解封服务（honeypot.py，模块一）。

检测什么：
- 客户端访问了隐藏蜜罐路径（/api/v1/trap）或提交了非空的隐藏表单域（/api/v1/trap/form）。
- 流水线首步检查 effective_ip 是否处于有效封禁状态（缓存黑名单 + SQLite bans 表）。
为什么可疑：
- 正常用户通过可见 UI 绝不会点击 display:none、opacity:0 视口外或 CSS ::before 伪元素链接，也不会填写隐藏表单字段；
  任何命中均表明自动化 DOM 解析或目录扫描行为。
阈值依据：
- 零容忍策略：触发即刻写入 bans 表并缓存封禁 BAN_SECONDS（默认 600s），后续所有业务请求在步骤 ① 直接返回 403 BANNED。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from app.cache import get_cache
from app.constants import ReasonCode
from app.models.tables import Ban

TZ_SHANGHAI = timezone(timedelta(hours=8))


def now_iso() -> str:
    """生成带 +08:00 时区的 ISO 8601 时间戳（对齐 7.2 SSE 契约格式）。"""
    return datetime.now(TZ_SHANGHAI).isoformat(timespec="milliseconds")


def ban_ip(
    db: Session,
    ip: str,
    reason_code: str = ReasonCode.HONEYPOT_TRIGGERED.value,
    duration_seconds: int = 600,
) -> Ban:
    """将指定 IP 写入 bans 表并同步写入缓存黑名单。"""
    now = datetime.now(TZ_SHANGHAI)
    until = now + timedelta(seconds=duration_seconds)

    ban_row = Ban(
        ip=ip,
        reason_code=reason_code,
        banned_at=now.isoformat(timespec="milliseconds"),
        ban_until=until.isoformat(timespec="milliseconds"),
        lifted_at=None,
        lifted_by=None,
    )
    db.add(ban_row)
    db.commit()
    db.refresh(ban_row)

    cache = get_cache()
    cache.set(f"ban:{ip}", reason_code, ex=max(1, duration_seconds))
    cache.set(f"trap_hit:{ip}", "1", ex=max(1, duration_seconds))
    return ban_row


def is_ip_banned(db: Session, ip: str) -> Optional[str]:
    """
    检查 IP 是否处于封禁期。优先读缓存，缓存未命中则回查 bans 表并回填缓存。
    返回生效中的 reason_code，未封禁返回 None。
    """
    cache = get_cache()
    cached_reason = cache.get(f"ban:{ip}")
    if cached_reason:
        return cached_reason

    now = datetime.now(TZ_SHANGHAI)
    now_str = now.isoformat(timespec="milliseconds")
    active = (
        db.query(Ban)
        .filter(Ban.ip == ip, Ban.lifted_at.is_(None), Ban.ban_until > now_str)
        .order_by(Ban.id.desc())
        .first()
    )
    if active is None:
        return None

    try:
        remaining = int((datetime.fromisoformat(active.ban_until) - now).total_seconds())
    except ValueError:
        remaining = 60
    if remaining > 0:
        cache.set(f"ban:{ip}", active.reason_code, ex=remaining)
        return active.reason_code
    return None


def has_trap_history(ip: str) -> bool:
    """步骤 ⑤：检查当前 IP 是否近期触发过蜜罐标记。"""
    return get_cache().get(f"trap_hit:{ip}") == "1"


def unban_ip(db: Session, ip: str, operator: str = "dashboard") -> int:
    """解除指定 IP 的全部有效封禁并落审计字段（lifted_at, lifted_by）。"""
    now_str = now_iso()
    rows: List[Ban] = (
        db.query(Ban)
        .filter(Ban.ip == ip, Ban.lifted_at.is_(None))
        .all()
    )
    for row in rows:
        row.lifted_at = now_str
        row.lifted_by = operator
    db.commit()

    cache = get_cache()
    cache.delete(f"ban:{ip}", f"trap_hit:{ip}")
    return len(rows)


def reset_ip_state(ip: str) -> None:
    """清空指定 IP 的限流计数、节奏窗口、行为/指纹告警缓存与访问序列（端点 12）。"""
    cache = get_cache()
    cache.delete(
        f"rl:{ip}",
        f"tb:public:{ip}",
        f"tb:sensitive:{ip}",
        f"cadence:{ip}",
        f"browse_views:{ip}",
        f"fp_risk_ip:{ip}",
        f"fp_reasons_ip:{ip}",
        f"fp_conflicts_ip:{ip}",
        f"beh_risk_ip:{ip}",
        f"beh_flags_ip:{ip}",
        f"visit:ip:{ip}",
        f"trap_hit:{ip}",
    )
