"""
统一缓存与状态门面（cache.py）。
规范要求：
- 严禁在任何其他业务模块直接 import redis 或 fakeredis，所有缓存操作一律经由本文件。
- 启动时检查 REDIS_URL：为空自动降级为进程内 fakeredis；非空连接真实 Redis。
  两种模式下限流、封禁、Nonce 去重、访问顺序图接口与行为完全一致。
"""

from __future__ import annotations

import logging
from typing import Any, List, Optional

import fakeredis
import redis

from app.config import get_settings

logger = logging.getLogger("anticrawl.cache")


class CacheFacade:
    """对真实 Redis 与 fakeredis 提供统一同步接口的缓存门面。"""

    def __init__(self, redis_url: str = "") -> None:
        self._redis_url = redis_url.strip()
        self._mode: str = "fakeredis"
        self._client: Any = None
        self._init_client()

    def _init_client(self) -> None:
        if self._redis_url:
            try:
                client = redis.Redis.from_url(
                    self._redis_url,
                    decode_responses=True,
                    socket_connect_timeout=2.0,
                    socket_timeout=2.0,
                )
                client.ping()
                self._client = client
                self._mode = "real"
                logger.info("Connected to real Redis instance: %s", self._redis_url)
                return
            except Exception as exc:  # pragma: no cover - 仅真实 Redis 不可达时触发
                logger.warning(
                    "Real Redis unreachable (%s), automatically degrading to fakeredis", exc
                )

        self._client = fakeredis.FakeRedis(decode_responses=True)
        self._mode = "fakeredis"

    @property
    def mode(self) -> str:
        """返回当前模式：'real' 或 'fakeredis'。"""
        return self._mode

    def ping(self) -> bool:
        return bool(self._client.ping())

    # ── 基础键值与去重 ──────────────────────────────────────────────────────
    def get(self, key: str) -> Optional[str]:
        val = self._client.get(key)
        return str(val) if val is not None else None

    def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        return bool(self._client.set(key, value, ex=ex))

    def setnx(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """原子性仅当不存在时写入（用于 Nonce 防重放去重）。"""
        if ttl is not None and ttl > 0:
            return bool(self._client.set(key, value, ex=ttl, nx=True))
        return bool(self._client.setnx(key, value))

    def delete(self, *keys: str) -> int:
        if not keys:
            return 0
        return int(self._client.delete(*keys))

    def expire(self, key: str, seconds: int) -> bool:
        return bool(self._client.expire(key, seconds))

    # ── 有序集合（滑动窗口限流）────────────────────────────────────────────
    def zremrangebyscore(self, key: str, min_score: float | str, max_score: float | str) -> int:
        return int(self._client.zremrangebyscore(key, min_score, max_score))

    def zadd(self, key: str, mapping: dict[str, float]) -> int:
        return int(self._client.zadd(key, mapping))

    def zcard(self, key: str) -> int:
        return int(self._client.zcard(key))

    def zrange(self, key: str, start: int, end: int, withscores: bool = False) -> List[Any]:
        return list(self._client.zrange(key, start, end, withscores=withscores))

    # ── 集合（指纹复用 IP 统计）────────────────────────────────────────────
    def sadd(self, key: str, *values: str) -> int:
        if not values:
            return 0
        return int(self._client.sadd(key, *values))

    def scard(self, key: str) -> int:
        return int(self._client.scard(key))

    def smembers(self, key: str) -> set[str]:
        return set(self._client.smembers(key))

    # ── 列表（会话访问顺序图）──────────────────────────────────────────────
    def rpush(self, key: str, *values: str) -> int:
        if not values:
            return 0
        return int(self._client.rpush(key, *values))

    def lrange(self, key: str, start: int, end: int) -> List[str]:
        return [str(x) for x in self._client.lrange(key, start, end)]

    def ltrim(self, key: str, start: int, end: int) -> bool:
        return bool(self._client.ltrim(key, start, end))

    def flushall(self) -> None:
        """清空当前缓存实例（用于测试隔离）。"""
        self._client.flushall()


_cache_instance: CacheFacade | None = None


def get_cache() -> CacheFacade:
    """获取全局缓存门面单例。"""
    global _cache_instance
    if _cache_instance is None:
        settings = get_settings()
        _cache_instance = CacheFacade(redis_url=settings.redis_url)
    return _cache_instance


def reset_cache_for_test(redis_url: str = "") -> CacheFacade:
    """仅用于测试：重置缓存门面实例。"""
    global _cache_instance
    _cache_instance = CacheFacade(redis_url=redis_url)
    return _cache_instance
