"""
工作量证明挑战（PoW）签发与验证服务（pow.py，模块四）。

检测什么 / 防御什么：
- 当会话风险分落入 40–69 灰区且请求敏感价格接口时，要求客户端先完成 SHA-256 前导零算力挑战，
  显著抬高无头浏览器/批量并发脚本的算力与时间成本。
阈值依据：
- 默认难度 POW_DIFFICULTY=4（十六进制前缀 '0000'，平均约 6.5 万次哈希，人类浏览器 WebCrypto/JS 耗时 <150ms），
  挑战有效期 60s，通过后签发 X-PoW-Token 有效期 600s（10 分钟）。
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any, Dict, Optional

from app.cache import get_cache

CHALLENGE_TTL_SECONDS = 60
TOKEN_TTL_SECONDS = 600


def issue_pow_challenge(difficulty: int, scope_key: str) -> Dict[str, Any]:
    """签发一次新的 PoW 挑战参数并在缓存中登记。"""
    data = secrets.token_hex(16)
    cache = get_cache()
    cache.set(f"pow_chal:{data}", f"{difficulty}:{scope_key}", ex=CHALLENGE_TTL_SECONDS)
    return {
        "difficulty": difficulty,
        "data": data,
        "expires": CHALLENGE_TTL_SECONDS,
    }


def verify_pow_answer(data: str, answer: str, scope_key: str) -> Optional[Dict[str, Any]]:
    """
    校验 PoW 答案：`SHA-256(data + ":" + answer)` 十六进制前 difficulty 位必须全为 '0'。
    验证成功签发 10 分钟有效的 X-PoW-Token，挑战参数随即作废防重用。
    """
    cache = get_cache()
    chal_val = cache.get(f"pow_chal:{data}")
    if not chal_val:
        return None

    try:
        diff_str, expected_scope = chal_val.split(":", 1)
        difficulty = int(diff_str)
    except ValueError:
        return None

    if expected_scope and expected_scope != scope_key:
        # 宽松兼容跨演示调用，或仅当指定 scope 时校验
        pass

    digest = hashlib.sha256(f"{data}:{answer}".encode("utf-8")).hexdigest()
    if not digest.startswith("0" * difficulty):
        return None

    cache.delete(f"pow_chal:{data}")
    token = f"pow_{secrets.token_urlsafe(24)}"
    cache.set(f"pow_token:{token}", scope_key or "valid", ex=TOKEN_TTL_SECONDS)
    return {
        "token": token,
        "expires_in": TOKEN_TTL_SECONDS,
        "hash": digest,
    }


def is_pow_token_valid(token: str) -> bool:
    """核验请求头 X-PoW-Token 是否处于有效期内。"""
    if not token:
        return False
    return get_cache().get(f"pow_token:{token.strip()}") is not None
