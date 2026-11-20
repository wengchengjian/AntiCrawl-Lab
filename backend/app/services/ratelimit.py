"""
滑动窗口限流与定频节律检测服务（ratelimit.py，模块一）。

检测什么：
1. 基于有序集合（ZSET）的 1 秒滑动窗口 IP 限流（rl:{effective_ip}）。
2. 基于同算法的企业级指纹维度限流（rl:fp:{fp_id}），对抗「换 IP 不换环境」的代理池采集。
3. 增强实验：定频轮询节律检测（cadence:{effective_ip}），识破低频但等间隔的 sleep() 脚本。
为什么可疑：
- 人类用户浏览网页存在思考与渲染间隔，极少在 1 秒内并发 >10 次业务 API 请求；
- 即使将 QPS 压低到阈值以下，自动化循环脚本（如固定 sleep(0.3)）的请求间隔方差也远小于人类交互。
阈值依据：
- IP QPS 默认阈值 RATE_LIMIT_QPS=10，指纹 QPS 默认阈值 FP_RATE_LIMIT_QPS=30；
- 定频变异系数 CV = std/mean < 0.08 且样本数 >= 6 判定为机械定频轮询（+15 分）。
"""

from __future__ import annotations

import json
import math
import time
import uuid
from dataclasses import dataclass
from typing import List

from app.cache import get_cache
from app.config import Settings
from app.constants import BEHAVIOR_THRESHOLDS, SCORE_WEIGHTS


@dataclass(frozen=True)
class RateLimitResult:
    """限流检测结果。"""

    exceeded: bool
    count: int
    limit: int
    retry_after: int = 1


def _sliding_window_hit(key: str, limit: int, window_ms: int = 1000) -> RateLimitResult:
    """
    通用 ZSET 滑动窗口计数器。
    注意：member 使用 `毫秒时间戳:随机后缀` 避免同毫秒多请求相互覆盖导致漏计。
    """
    cache = get_cache()
    now_ms = int(time.time() * 1000)
    cutoff = now_ms - window_ms
    member = f"{now_ms}:{uuid.uuid4().hex[:8]}"

    cache.zremrangebyscore(key, 0, cutoff)
    cache.zadd(key, {member: float(now_ms)})
    cache.expire(key, max(5, window_ms // 1000 + 2))
    count = cache.zcard(key)

    exceeded = count > limit
    return RateLimitResult(exceeded=exceeded, count=count, limit=limit, retry_after=1)


def check_ip_rate_limit(effective_ip: str, limit_qps: int) -> RateLimitResult:
    """检查单 IP（含模拟 IP）1 秒滑动窗口是否超过 RATE_LIMIT_QPS。"""
    return _sliding_window_hit(f"rl:{effective_ip}", limit_qps, window_ms=1000)


def check_fp_rate_limit(fp_id: str, limit_qps: int) -> RateLimitResult:
    """检查单指纹 1 秒滑动窗口是否超过 FP_RATE_LIMIT_QPS。"""
    return _sliding_window_hit(f"rl:fp:{fp_id}", limit_qps, window_ms=1000)


@dataclass(frozen=True)
class CadenceResult:
    """请求时间节律分析结果（增强实验）。"""

    robotic: bool
    cv: float | None
    sample_count: int
    score: int


def analyze_request_cadence(effective_ip: str) -> CadenceResult:
    """
    增强检测：分析同一 IP 最近请求的时间间隔变异系数（CV = 标准差 / 均值）。
    当样本 >= 6、平均间隔 >= 80ms（避开浏览器并发加载静态资源）且 CV < 0.08 时，
    说明客户端以极其稳定的 sleep() 周期发起请求，疑似定频自动化采集脚本。
    """
    cache = get_cache()
    key = f"cadence:{effective_ip}"
    now_ms = int(time.time() * 1000)
    cache.zremrangebyscore(key, 0, now_ms - 30_000)
    cache.zadd(key, {f"{now_ms}:{uuid.uuid4().hex[:8]}": float(now_ms)})
    cache.expire(key, 35)

    entries = cache.zrange(key, -12, -1, withscores=True)
    if len(entries) < 6:
        return CadenceResult(robotic=False, cv=None, sample_count=len(entries), score=0)

    timestamps = sorted(float(score) for _, score in entries)
    intervals: List[float] = [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
        if timestamps[i] - timestamps[i - 1] > 1.0
    ]
    if len(intervals) < 5:
        return CadenceResult(robotic=False, cv=None, sample_count=len(entries), score=0)

    mean_iv = sum(intervals) / len(intervals)
    if mean_iv < 80.0:
        # 80ms 以内的并发批请求不视作固定周期轮询
        return CadenceResult(robotic=False, cv=None, sample_count=len(entries), score=0)

    variance = sum((x - mean_iv) ** 2 for x in intervals) / len(intervals)
    std_iv = math.sqrt(variance)
    cv = std_iv / mean_iv if mean_iv > 0 else 1.0

    max_cv = BEHAVIOR_THRESHOLDS["MAX_CADENCE_CV"]
    if cv < max_cv:
        return CadenceResult(
            robotic=True,
            cv=round(cv, 4),
            sample_count=len(entries),
            score=SCORE_WEIGHTS["CADENCE_ROBOTIC"],
        )

    return CadenceResult(robotic=False, cv=round(cv, 4), sample_count=len(entries), score=0)


@dataclass(frozen=True)
class TokenBucketResult:
    """网关分级令牌桶限流结果（复刻 Spring Cloud Gateway RedisRateLimiter 模型）。"""

    tier: str
    burst_capacity: int
    replenish_rate: int
    remaining: int
    requested_tokens: int
    exceeded: bool
    retry_after: int = 1


def _resolve_rate_limit_tier(path: str, settings: Settings) -> tuple[str, int, int]:
    """
    根据接口敏感度划分限流档位：
    - sensitive：单品底价、PoW 挑战、WAF 动态挑战流（更严格突发上限与补充速率）
    - public：其他普通业务接口
    """
    is_sensitive = (
        path.startswith("/api/v1/challenge/pow")
        or path.startswith("/api/v1/waf/")
        or (path.startswith("/api/v1/products/") and path.endswith("/price"))
    )
    if is_sensitive:
        return "sensitive", settings.sensitive_bucket_burst, settings.sensitive_bucket_rate
    return "public", settings.public_bucket_burst, settings.public_bucket_rate


def check_tiered_token_bucket(
    effective_ip: str,
    path: str,
    settings: Settings,
) -> TokenBucketResult:
    """
    分级令牌桶限流：
    - 检测什么：在固定 IP 滑动窗口之外，按路径敏感度使用不同令牌桶配额，防止慢速耗尽高敏计算资源。
    - 为什么可疑：高敏接口（底价/PoW/WAF）突发请求应显著低于普通列表读取，超额突发即为脚本压测特征。
    - 阈值依据：默认 public=(60 burst, 30/s)，sensitive=(8 burst, 4/s)。
    """
    tier, burst, replenish = _resolve_rate_limit_tier(path, settings)
    cache = get_cache()
    key = f"tb:{tier}:{effective_ip}"
    now_ms = int(time.time() * 1000)

    tokens = float(burst)
    last_ms = now_ms
    raw = cache.get(key)
    if raw:
        try:
            state = json.loads(raw)
            prev_tokens = float(state.get("tokens", burst))
            prev_ms = int(state.get("last_ms", now_ms))
            elapsed_sec = max(0.0, (now_ms - prev_ms) / 1000.0)
            tokens = min(float(burst), prev_tokens + elapsed_sec * float(replenish))
        except Exception:
            tokens = float(burst)

    requested = 1
    if tokens >= float(requested):
        tokens -= float(requested)
        exceeded = False
        retry_after = 0
    else:
        exceeded = True
        deficit = float(requested) - tokens
        retry_after = max(1, math.ceil(deficit / max(1, replenish)))

    cache.set(key, json.dumps({"tokens": round(tokens, 4), "last_ms": now_ms}), ex=120)
    return TokenBucketResult(
        tier=tier,
        burst_capacity=burst,
        replenish_rate=replenish,
        remaining=max(0, int(math.floor(tokens))),
        requested_tokens=requested,
        exceeded=exceeded,
        retry_after=retry_after,
    )
