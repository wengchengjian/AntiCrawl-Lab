"""
管理与仪表盘查询端点（端点 10/11/12 及统计/封禁/本地导出）。
安全边界（第 2 章 & 第 17 章）：
- 仅在 LAB_MODE=1 时开放管理端点；LAB_MODE=0 时全部拒绝（返回 403）。
- 导出功能仅支持前端本地落盘 JSON，禁止外发。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.config import get_settings
from app.constants import ReasonCode
from app.db import get_db
from app.models.tables import Ban, Fingerprint, RiskLog
from app.services.honeypot import reset_ip_state, unban_ip
from app.services.risk_logger import record_risk_event

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])
TZ_SHANGHAI = timezone(timedelta(hours=8))


def _require_lab_mode() -> None:
    if not get_settings().lab_mode:
        raise HTTPException(
            status_code=403,
            detail={
                "code": 403,
                "message": "生产模式（LAB_MODE=0）已关闭未鉴权管理端点",
                "risk_reason": ReasonCode.BANNED.value,
            },
        )


class IpActionBody(BaseModel):
    """管理动作请求体（解封 / 重置）。"""

    ip: str
    operator: str = "dashboard"


def _parse_json_safe(raw: str, default: Any) -> Any:
    try:
        return json.loads(raw)
    except Exception:
        return default


def _serialize_log_row(row: RiskLog) -> Dict[str, Any]:
    return {
        "id": row.id,
        "ts": row.ts,
        "client_ip": row.client_ip,
        "effective_ip": row.effective_ip,
        "path": row.path,
        "module": row.module,
        "action": row.action,
        "risk_score": row.risk_score,
        "reasons": _parse_json_safe(row.reasons, []),
        "ua": row.ua,
        "fingerprint_id": row.fingerprint_id,
        "decoy_served": bool(row.decoy_served),
        "latency_ms": row.latency_ms,
        "extra": _parse_json_safe(row.extra_json, {}),
    }


@router.get("/requests", dependencies=[Depends(_require_lab_mode)])
def list_or_get_requests(
    id: Optional[int] = Query(default=None),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
    module: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    端点 10：
    - 传入 `?id=` 时返回单条风控请求全量详情 + 关联浏览器指纹画像（含环境伪装破绽分组）；
    - 否则返回按 id 倒序的分页风控日志列表。
    """
    if id is not None:
        row = db.get(RiskLog, id)
        if row is None:
            raise HTTPException(status_code=404, detail="风控日志记录不存在")
        data = _serialize_log_row(row)
        fp_profile: Optional[Dict[str, Any]] = None
        if row.fingerprint_id:
            fp = db.query(Fingerprint).filter(Fingerprint.fp_id == row.fingerprint_id).first()
            if fp is not None:
                fp_profile = {
                    "fp_id": fp.fp_id,
                    "ua": fp.ua,
                    "platform": fp.platform,
                    "languages": _parse_json_safe(fp.languages, []),
                    "timezone": fp.timezone,
                    "screen": {
                        "width": fp.screen_width,
                        "height": fp.screen_height,
                        "color_depth": fp.color_depth,
                        "device_pixel_ratio": fp.device_pixel_ratio,
                    },
                    "device_memory": fp.device_memory,
                    "hardware_concurrency": fp.hardware_concurrency,
                    "touch_points": fp.touch_points,
                    "canvas_hash": fp.canvas_hash,
                    "webgl": {
                        "vendor": fp.webgl_vendor,
                        "renderer": fp.webgl_renderer,
                        "masked": bool(fp.webgl_masked),
                    },
                    "audio_hash": fp.audio_hash,
                    "font_count": fp.font_count,
                    "fonts_hash": fp.fonts_hash,
                    "automation_flags": _parse_json_safe(fp.automation_flags, {}),
                    "extra_probes": _parse_json_safe(fp.extra_probes, {}),
                    "hit_ips": fp.hit_ips,
                    "created_at": fp.created_at,
                    "last_seen_at": fp.last_seen_at,
                }
        return {"item": data, "fingerprint": fp_profile}

    query = db.query(RiskLog)
    if module:
        query = query.filter(RiskLog.module == module)
    if action:
        query = query.filter(RiskLog.action == action)

    total = query.count()
    rows = (
        query.order_by(desc(RiskLog.id))
        .offset((page - 1) * size)
        .limit(size)
        .all()
    )
    return {
        "items": [_serialize_log_row(r) for r in rows],
        "total": total,
        "page": page,
        "size": size,
    }


@router.post("/unban", dependencies=[Depends(_require_lab_mode)])
def admin_unban(body: IpActionBody, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """端点 11：解封指定 IP 并写入审计字段（lifted_by=dashboard）。"""
    lifted_count = unban_ip(db, body.ip.strip(), operator=body.operator or "dashboard")
    record_risk_event(
        db,
        client_ip="127.0.0.1",
        effective_ip=body.ip.strip(),
        path="/api/v1/admin/unban",
        module="network",
        action="pass",
        risk_score=0,
        reasons=[],
        ua="Admin-Dashboard",
        extra={"audit": True, "operator": body.operator, "lifted_records": lifted_count},
    )
    return {"lifted": body.ip.strip(), "lifted_count": lifted_count}


@router.post("/reset", dependencies=[Depends(_require_lab_mode)])
def admin_reset(body: IpActionBody, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """端点 12：清空指定 IP 的限流计数、指纹/行为风险缓存与访问顺序缓存。"""
    target_ip = body.ip.strip()
    reset_ip_state(target_ip)
    record_risk_event(
        db,
        client_ip="127.0.0.1",
        effective_ip=target_ip,
        path="/api/v1/admin/reset",
        module="network",
        action="pass",
        risk_score=0,
        reasons=[],
        ua="Admin-Dashboard",
        extra={"audit": True, "operator": body.operator, "reset_ip": target_ip},
    )
    return {"reset": target_ip}


@router.get("/bans", dependencies=[Depends(_require_lab_mode)])
def list_bans(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """查询封禁记录列表（含当前有效与已解封历史）。"""
    now_str = datetime.now(TZ_SHANGHAI).isoformat(timespec="milliseconds")
    rows = db.query(Ban).order_by(desc(Ban.id)).limit(100).all()
    items = [
        {
            "id": b.id,
            "ip": b.ip,
            "reason_code": b.reason_code,
            "banned_at": b.banned_at,
            "ban_until": b.ban_until,
            "lifted_at": b.lifted_at,
            "lifted_by": b.lifted_by,
            "active": b.lifted_at is None and b.ban_until > now_str,
        }
        for b in rows
    ]
    return {"items": items}


@router.get("/stats", dependencies=[Depends(_require_lab_mode)])
def dashboard_stats(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """仪表盘顶部 5 张统计卡片指标：今日请求量、拦截率、警告率、活跃指纹数、诱饵投喂数。"""
    today_prefix = datetime.now(TZ_SHANGHAI).strftime("%Y-%m-%d")
    total_today = (
        db.query(func.count(RiskLog.id)).filter(RiskLog.ts.like(f"{today_prefix}%")).scalar() or 0
    )
    blocked_today = (
        db.query(func.count(RiskLog.id))
        .filter(RiskLog.ts.like(f"{today_prefix}%"), RiskLog.action == "block")
        .scalar()
        or 0
    )
    warn_today = (
        db.query(func.count(RiskLog.id))
        .filter(RiskLog.ts.like(f"{today_prefix}%"), RiskLog.action.in_(["warn", "challenge"]))
        .scalar()
        or 0
    )
    decoy_today = (
        db.query(func.count(RiskLog.id))
        .filter(RiskLog.ts.like(f"{today_prefix}%"), RiskLog.decoy_served == 1)
        .scalar()
        or 0
    )
    active_fps = db.query(func.count(Fingerprint.id)).scalar() or 0

    block_rate = round((blocked_today / total_today) * 100, 1) if total_today else 0.0
    warn_rate = round((warn_today / total_today) * 100, 1) if total_today else 0.0

    return {
        "today_requests": int(total_today),
        "block_rate": block_rate,
        "warn_rate": warn_rate,
        "active_fingerprints": int(active_fps),
        "decoy_served_count": int(decoy_today),
    }


@router.get("/export", dependencies=[Depends(_require_lab_mode)])
def export_local_logs(limit: int = Query(default=200, ge=1, le=1000), db: Session = Depends(get_db)) -> JSONResponse:
    """导出本地风险日志 JSON（第 17.4 节：仅允许本地下载落盘）。"""
    rows = db.query(RiskLog).order_by(desc(RiskLog.id)).limit(limit).all()
    payload = {
        "exported_at": datetime.now(TZ_SHANGHAI).isoformat(timespec="seconds"),
        "count": len(rows),
        "logs": [_serialize_log_row(r) for r in rows],
    }
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": 'attachment; filename="anticrawl-logs-local.json"'},
    )
