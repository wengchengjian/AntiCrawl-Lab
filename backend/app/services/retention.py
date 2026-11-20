"""
数据留存滚动清理服务（retention.py，第 5 章与第 17 章安全边界）。

安全边界：
- 指纹、行为与日志数据仅存于本地 SQLite，按 DATA_RETENTION_DAYS（默认 7 天）自动滚动清理。
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_session_factory
from app.models.tables import Fingerprint, Nonce, RiskLog

logger = logging.getLogger("anticrawl.retention")
TZ_SHANGHAI = timezone(timedelta(hours=8))


def cleanup_expired_records(db: Session, retention_days: int) -> dict[str, int]:
    """清理超出保留天数的 risk_logs、fingerprints 与过期 nonces。"""
    cutoff = (datetime.now(TZ_SHANGHAI) - timedelta(days=max(1, retention_days))).isoformat(
        timespec="milliseconds"
    )
    now_str = datetime.now(TZ_SHANGHAI).isoformat(timespec="milliseconds")

    logs_deleted = db.query(RiskLog).filter(RiskLog.ts < cutoff).delete(synchronize_session=False)
    fps_deleted = db.query(Fingerprint).filter(Fingerprint.last_seen_at < cutoff).delete(
        synchronize_session=False
    )
    nonces_deleted = db.query(Nonce).filter(Nonce.expired_at < now_str).delete(
        synchronize_session=False
    )
    db.commit()
    return {
        "risk_logs": int(logs_deleted),
        "fingerprints": int(fps_deleted),
        "nonces": int(nonces_deleted),
    }


async def retention_worker(stop_event: asyncio.Event) -> None:
    """后台每日定时滚动清理协程。"""
    while not stop_event.is_set():
        try:
            settings = get_settings()
            factory = get_session_factory()
            with factory() as db:
                counts = cleanup_expired_records(db, settings.data_retention_days)
                if sum(counts.values()) > 0:
                    logger.info("Retention cleanup completed: %s", counts)
        except Exception as exc:  # pragma: no cover
            logger.warning("Retention cleanup failed: %s", exc)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=86400.0)
        except asyncio.TimeoutError:
            continue
