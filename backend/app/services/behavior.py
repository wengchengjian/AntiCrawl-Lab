"""
用户行为轨迹量化分析与访问顺序图服务（behavior.py，模块三）。

检测什么：
1. 鼠标轨迹点数（<30 点即请求敏感接口 → BOT_TRAJECTORY）。
2. 轨迹直线度与匀速度：方向变化次数 <8 或相邻点速度标准差 <0.05 px/ms → BOT_TRAJECTORY。
3. 合成事件识别：任一 mouse/key/scroll 事件 isTrusted === false → SYNTHETIC_EVENT (+40)。
4. 零交互直奔深层：鼠标/键盘/滚动事件总数为 0 → NO_INTERACTION_DEEP_ACCESS (+30)。
5. 页面停留时间：<2 秒即发起敏感请求 → +15（BOT_TRAJECTORY）。
6. 键盘动力学：击键间隔方差 <30 ms²（样本 >=3）→ KEYBOARD_ROBOTIC (+20)。
7. 访问顺序图（10.3）：访问单品价格接口前必须先经过 `/` 与 `/api/v1/products`，否则记 VISIT_ORDER_VIOLATION (+30)。
为什么可疑：
- 人类移动鼠标受生物力学微颤与加速减速控制，存在大量微小曲率与速度波动；脚本注入往往直线插值、等间隔发键或跳过浏览直接抓包。
阈值依据：
- 全部量化阈值严格对应提示词 10.2 与 10.3 节规范，单测覆盖精确边界值。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List

from app.cache import get_cache
from app.constants import BEHAVIOR_THRESHOLDS, ReasonCode, SCORE_WEIGHTS


@dataclass
class BehaviorResult:
    """行为分析与量化指标输出。"""

    score: int = 0
    flags: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    details: List[str] = field(default_factory=list)


def _count_direction_changes(points: List[Dict[str, Any]]) -> int:
    """
    计算轨迹相邻位移向量之间夹角超过 12° 的方向转折次数。
    严格直线插值的位移向量夹角恒为 0°，返回值严格为 0（<8 触发告警）。
    """
    if len(points) < 3:
        return 0

    changes = 0
    prev_dx: float | None = None
    prev_dy: float | None = None

    for i in range(1, len(points)):
        dx = float(points[i].get("x", 0)) - float(points[i - 1].get("x", 0))
        dy = float(points[i].get("y", 0)) - float(points[i - 1].get("y", 0))
        mag = math.hypot(dx, dy)
        if mag < 1e-6:
            continue
        if prev_dx is not None and prev_dy is not None:
            prev_mag = math.hypot(prev_dx, prev_dy)
            if prev_mag > 1e-6:
                cos_theta = (dx * prev_dx + dy * prev_dy) / (mag * prev_mag)
                cos_theta = max(-1.0, min(1.0, cos_theta))
                angle_deg = math.degrees(math.acos(cos_theta))
                if angle_deg > 12.0:
                    changes += 1
        prev_dx, prev_dy = dx, dy
    return changes


def _compute_velocity_std(points: List[Dict[str, Any]]) -> float:
    """计算相邻轨迹点瞬时速度（px/ms）的总体标准差。"""
    if len(points) < 3:
        return 0.0
    velocities: List[float] = []
    for i in range(1, len(points)):
        dx = float(points[i].get("x", 0)) - float(points[i - 1].get("x", 0))
        dy = float(points[i].get("y", 0)) - float(points[i - 1].get("y", 0))
        dt = float(points[i].get("t", 0)) - float(points[i - 1].get("t", 0))
        if dt <= 0:
            dt = 1.0
        velocities.append(math.hypot(dx, dy) / dt)
    if len(velocities) < 2:
        return 0.0
    mean_v = sum(velocities) / len(velocities)
    var_v = sum((v - mean_v) ** 2 for v in velocities) / len(velocities)
    return math.sqrt(var_v)


def _compute_key_interval_variance(keys: List[Dict[str, Any]]) -> float | None:
    """计算相邻按键 downTs 间隔序列的方差（ms²）。"""
    if len(keys) < 3:
        return None
    down_times = sorted(float(k.get("downTs", 0)) for k in keys)
    intervals = [down_times[i] - down_times[i - 1] for i in range(1, len(down_times))]
    if len(intervals) < 2:
        return None
    mean_iv = sum(intervals) / len(intervals)
    return sum((iv - mean_iv) ** 2 for iv in intervals) / len(intervals)


def evaluate_behavior(payload: Dict[str, Any]) -> BehaviorResult:
    """按 10.2 节量化阈值对前端上报轨迹进行评分并输出指标。"""
    points = list(payload.get("points") or [])
    keys = list(payload.get("keys") or [])
    scrolls = list(payload.get("scrolls") or [])
    page_seconds = float(payload.get("page_seconds") or 0.0)

    res = BehaviorResult()
    total_events = len(points) + len(keys) + len(scrolls)

    # 统计 isTrusted 比例（覆盖鼠标/键盘/滚动全事件）
    all_events = points + keys + scrolls
    untrusted_count = sum(1 for ev in all_events if ev.get("isTrusted") is False)
    trusted_ratio = 1.0 if not all_events else round((len(all_events) - untrusted_count) / len(all_events), 4)

    dir_changes = _count_direction_changes(points)
    vel_std = round(_compute_velocity_std(points), 4)
    key_var = _compute_key_interval_variance(keys)

    # 1. 合成事件检测（只要 isTrusted=false 占比 >0 立即计 +40）
    if untrusted_count > 0:
        res.score += SCORE_WEIGHTS["SYNTHETIC_EVENT"]
        res.flags.append(ReasonCode.SYNTHETIC_EVENT.value)
        res.details.append(f"存在 {untrusted_count} 个 isTrusted=false 合成事件 (+40)")

    # 2. 无交互直奔深层（鼠标/键盘/滚动事件总数为 0）
    if total_events == 0:
        res.score += SCORE_WEIGHTS["NO_INTERACTION_DEEP_ACCESS"]
        res.flags.append(ReasonCode.NO_INTERACTION_DEEP_ACCESS.value)
        res.details.append("鼠标/键盘/滚动事件总数为 0 (+30)")
    else:
        # 3. 轨迹点数 < 30
        min_pts = int(BEHAVIOR_THRESHOLDS["MIN_TRAJECTORY_POINTS"])
        if len(points) < min_pts:
            res.score += SCORE_WEIGHTS["TRAJECTORY_FEW_POINTS"]
            res.flags.append(ReasonCode.BOT_TRAJECTORY.value)
            res.details.append(f"轨迹采样点数 {len(points)} < {min_pts} (+20)")
        else:
            # 4. 直线度：方向变化次数 < 8 或相邻点速度标准差 < 0.05 px/ms
            min_dir = int(BEHAVIOR_THRESHOLDS["MIN_DIRECTION_CHANGES"])
            min_vel_std = float(BEHAVIOR_THRESHOLDS["MIN_VELOCITY_STD_PX_MS"])
            if dir_changes < min_dir or vel_std < min_vel_std:
                res.score += SCORE_WEIGHTS["TRAJECTORY_LINEAR"]
                res.flags.append(ReasonCode.BOT_TRAJECTORY.value)
                res.details.append(
                    f"轨迹机械直线/匀速（方向变化={dir_changes}<{min_dir} 或 速度标准差={vel_std}<{min_vel_std}）(+25)"
                )

    # 5. 页面停留 < 2 秒
    min_stay = float(BEHAVIOR_THRESHOLDS["MIN_PAGE_SECONDS"])
    if page_seconds < min_stay:
        res.score += SCORE_WEIGHTS["PAGE_STAY_TOO_SHORT"]
        if ReasonCode.BOT_TRAJECTORY.value not in res.flags:
            res.flags.append(ReasonCode.BOT_TRAJECTORY.value)
        res.details.append(f"页面停留 {page_seconds:.2f}s < {min_stay}s (+15)")

    # 6. 键盘动力学：击键间隔方差 < 30 ms²
    min_key_var = float(BEHAVIOR_THRESHOLDS["MIN_KEY_VARIANCE_MS2"])
    if key_var is not None and key_var < min_key_var:
        res.score += SCORE_WEIGHTS["KEYBOARD_ROBOTIC"]
        res.flags.append(ReasonCode.KEYBOARD_ROBOTIC.value)
        res.details.append(f"击键间隔方差 {key_var:.2f} ms² < {min_key_var} ms² (+20)")

    res.flags = list(dict.fromkeys(res.flags))
    res.metrics = {
        "point_count": len(points),
        "key_count": len(keys),
        "scroll_count": len(scrolls),
        "trusted_ratio": trusted_ratio,
        "untrusted_count": untrusted_count,
        "direction_changes": dir_changes,
        "velocity_std": vel_std,
        "key_interval_variance": round(key_var, 2) if key_var is not None else None,
        "page_seconds": round(page_seconds, 2),
    }
    return res


# ── 10.3 会话访问顺序图（基于 cache.py 列表维护）──────────────────────────────

def record_visit(session_key: str, path: str) -> List[str]:
    """记录会话访问路径节点到有序列表，最多保留最近 30 步。"""
    if not session_key or not path:
        return []
    cache = get_cache()
    key = f"visit:{session_key}"
    cache.rpush(key, path)
    cache.ltrim(key, -30, -1)
    cache.expire(key, 1800)
    return cache.lrange(key, 0, -1)


def check_price_visit_order(session_key: str) -> bool:
    """
    校验访问单品价格接口前的导航顺序：
    要求会话访问历史中存在 '/' 与 '/api/v1/products'，且 '/' 不晚于 '/api/v1/products'。
    满足返回 True，违规返回 False（触发 VISIT_ORDER_VIOLATION）。
    """
    history = get_cache().lrange(f"visit:{session_key}", 0, -1)
    try:
        idx_home = history.index("/")
        idx_products = history.index("/api/v1/products")
    except ValueError:
        return False
    return idx_home <= idx_products
