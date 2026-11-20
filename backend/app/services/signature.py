"""
接口 HMAC-SHA256 签名校验与 Nonce 防重放服务（signature.py，模块四）。

检测什么：
1. 核心数据接口（/api/v1/products 与 /api/v1/products/{id}/price）必须携带 X-Signature、X-Timestamp、X-Nonce。
2. 时间窗校验：|now - X-Timestamp| <= SIGN_WINDOW_SECONDS（默认 ±120s），超时返回 401 SIGNATURE_EXPIRED。
3. 签名校验：HMAC_SHA256_HEX(SIGN_SECRET, METHOD + "\\n" + PATH + "\\n" + X-Timestamp + "\\n" + X-Nonce)，不符返回 401 SIGNATURE_INVALID。
4. Nonce 去重：经由 cache.setnx() 在 NONCE_TTL_SECONDS（默认 300s）内原子去重，并镜像写入 nonces 表审计；重放返回 401 NONCE_REUSED。
为什么可疑：
- 抓包脚本常直接复制一次请求参数反复重放，或伪造参数绕过前端签名逻辑。
阈值依据：
- 时间窗 ±120s、Nonce 去重窗口 300s，严格对齐提示词第 4 章与 11.1 节契约。
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping, Optional

from sqlalchemy.orm import Session

from app.cache import get_cache
from app.config import Settings
from app.constants import ReasonCode
from app.models.tables import Nonce

TZ_SHANGHAI = timezone(timedelta(hours=8))


@dataclass(frozen=True)
class SignatureCheckResult:
    """签名校验结果。"""

    ok: bool
    status_code: int = 200
    reason_code: Optional[str] = None
    message: str = ""


def compute_signature(secret: str, method: str, path: str, timestamp: str, nonce: str) -> str:
    """按 11.1 节标准算法计算 HMAC-SHA256 十六进制签名。"""
    canonical = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}"
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_request_signature(
    method: str,
    path: str,
    headers: Mapping[str, str],
    settings: Settings,
    db: Session,
) -> SignatureCheckResult:
    """执行四步签名校验（缺失 → 时间窗 → 摘要比对 → Nonce 去重）。"""
    norm = {k.lower(): v.strip() for k, v in headers.items()}
    sig = norm.get("x-signature", "")
    ts_raw = norm.get("x-timestamp", "")
    nonce = norm.get("x-nonce", "")

    if not sig or not ts_raw or not nonce:
        return SignatureCheckResult(
            ok=False,
            status_code=401,
            reason_code=ReasonCode.SIGNATURE_MISSING.value,
            message="缺少必要签名头（X-Signature / X-Timestamp / X-Nonce）",
        )

    try:
        ts_val = int(ts_raw)
    except ValueError:
        return SignatureCheckResult(
            ok=False,
            status_code=401,
            reason_code=ReasonCode.SIGNATURE_INVALID.value,
            message="X-Timestamp 格式无效",
        )

    now_sec = int(time.time())
    if abs(now_sec - ts_val) > settings.sign_window_seconds:
        return SignatureCheckResult(
            ok=False,
            status_code=401,
            reason_code=ReasonCode.SIGNATURE_EXPIRED.value,
            message=f"请求签名时间戳超出 ±{settings.sign_window_seconds}s 允许窗口",
        )

    expected_sig = compute_signature(settings.sign_secret, method, path, ts_raw, nonce)
    if not hmac.compare_digest(sig.lower(), expected_sig.lower()):
        return SignatureCheckResult(
            ok=False,
            status_code=401,
            reason_code=ReasonCode.SIGNATURE_INVALID.value,
            message="X-Signature HMAC-SHA256 校验失败",
        )

    # 先查缓存 SETNX；同时写入 SQLite nonces 表作为审计镜像
    cache = get_cache()
    nonce_key = f"nonce:{nonce}"
    acquired = cache.setnx(nonce_key, "1", ttl=settings.nonce_ttl_seconds)
    if not acquired:
        return SignatureCheckResult(
            ok=False,
            status_code=401,
            reason_code=ReasonCode.NONCE_REUSED.value,
            message="检测到 X-Nonce 重放攻击，该一次性随机数已被使用",
        )

    try:
        expired_dt = datetime.now(TZ_SHANGHAI) + timedelta(seconds=settings.nonce_ttl_seconds)
        if db.get(Nonce, nonce) is None:
            db.add(
                Nonce(
                    nonce=nonce,
                    ts=ts_val,
                    expired_at=expired_dt.isoformat(timespec="milliseconds"),
                )
            )
            db.commit()
    except Exception:
        db.rollback()

    return SignatureCheckResult(ok=True)
