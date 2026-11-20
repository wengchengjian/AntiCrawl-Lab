"""
统一风控日志落库与 SSE 实时事件发布服务（risk_logger.py）。
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.events import get_event_bus
from app.models.tables import RiskLog
from app.services.honeypot import now_iso


def record_risk_event(
    db: Session,
    *,
    client_ip: str,
    effective_ip: str,
    path: str,
    module: str,
    action: str,
    risk_score: int,
    reasons: List[str],
    ua: str,
    fingerprint_id: str = "",
    decoy_served: bool = False,
    latency_ms: float = 0.0,
    extra: Dict[str, Any] | None = None,
) -> RiskLog:
    """
    将风控决策写入 risk_logs 表并即时通过 SSE 广播 `event: risk`。
    事件字段严格对齐提示词第 7.2 节契约。
    """
    ts_str = now_iso()
    dedup_reasons = list(dict.fromkeys(reasons))
    capped_score = max(0, min(100, int(risk_score)))

    row = RiskLog(
        ts=ts_str,
        client_ip=client_ip,
        effective_ip=effective_ip,
        path=path,
        module=module,
        action=action,
        risk_score=capped_score,
        reasons=json.dumps(dedup_reasons, ensure_ascii=False),
        ua=ua,
        fingerprint_id=fingerprint_id,
        decoy_served=1 if decoy_served else 0,
        latency_ms=round(float(latency_ms), 2),
        extra_json=json.dumps(extra or {}, ensure_ascii=False),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    # 7.2 标准 SSE 事件结构
    sse_payload: Dict[str, Any] = {
        "id": row.id,
        "ts": row.ts,
        "client_ip": row.client_ip,
        "effective_ip": row.effective_ip,
        "path": row.path,
        "module": row.module,
        "action": row.action,
        "risk_score": row.risk_score,
        "reasons": dedup_reasons,
        "ua": row.ua,
        "fingerprint_id": row.fingerprint_id,
        "decoy_served": bool(row.decoy_served),
        "latency_ms": row.latency_ms,
    }
    get_event_bus().publish(sse_payload)
    return row
