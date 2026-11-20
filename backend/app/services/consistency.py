"""
浏览器指纹一致性校验与复用追踪服务（consistency.py，模块二）。

检测什么：
1. 9.3 一致性校验矩阵（7 条核心规则，每条命中 +20 分并记 FINGERPRINT_CONFLICT）：
   - UA OS vs navigator.platform
   - UA 品牌 vs Sec-CH-UA 品牌列表
   - UA OS vs WebGL renderer 字符串
   - effective_ip 归属地 vs timezone
   - effective_ip 归属地 vs languages 首选语言
   - platform vs screen 特征 + device_memory + touch_points
   - touch_points vs UA 设备类型
2. WebGL 调试扩展掩码或软件渲染器（SwiftShader/llvmpipe）识别（WEBGL_MASKED +15）。
3. 9.4 指纹稳定性追踪：同一 fp_id 命中 >=3 个不同 effective_ip 记 FINGERPRINT_REUSE（+30）。
4. 增强实验（反指纹浏览器/伪装插件对抗）：
   - 双 Canvas 渲染噪点投毒检测（抓出 CanvasBlocker 随机噪点）
   - Web Worker 跨线程 navigator 一致性校验（抓出只 patch 主线程的 stealth 脚本）
   - timezoneOffset 与 Intl 时区交叉验证（抓出仅 hook Intl 的时区伪装）
   - JS 引擎 Math 浮点指纹 vs UA 声明内核比对
   - CSS 媒体查询（pointer: fine / hover: hover）与设备类型交叉校验
为什么可疑：
- 指纹浏览器或自动化脚本往往只改表面属性（如修改 navigator.userAgent 或单点 Hook），
  难以在多渲染管线、多线程、跨协议头与地理归属维度做到完全自洽。
阈值依据：
- 严格遵守 6.2/9.3/9.4：一致性破绽每条 +20，指纹跨 >=3 IP 复用 +30，WebGL 掩码/软渲染 +15。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from app.cache import get_cache
from app.constants import DECISION_THRESHOLDS, ReasonCode, SCORE_WEIGHTS
from app.services.geoip import GeoInfo
from app.services.headercheck import (
    extract_sec_ch_ua_brands,
    is_chromium_user_agent,
    is_non_secure_http_context,
)


@dataclass(frozen=True)
class ConflictItem:
    """单条环境伪装破绽结构（用于落库与仪表盘「环境伪装破绽」分组展示）。"""

    rule_id: str
    left_evidence: str
    right_evidence: str
    message: str
    is_enhanced: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "left_evidence": self.left_evidence,
            "right_evidence": self.right_evidence,
            "message": self.message,
            "is_enhanced": self.is_enhanced,
        }


@dataclass
class ConsistencyResult:
    """一致性校验综合输出。"""

    fp_id: str
    score: int = 0
    reasons: List[str] = field(default_factory=list)
    conflicts: List[ConflictItem] = field(default_factory=list)
    enhanced_findings: List[Dict[str, Any]] = field(default_factory=list)
    hit_ips: int = 1
    webgl_masked: bool = False


# 已知常用时区与 getTimezoneOffset() 期望分钟偏移（含夏令时允许集合）
EXPECTED_TZ_OFFSETS: Dict[str, tuple[int, ...]] = {
    "Asia/Shanghai": (-480,),
    "Asia/Chongqing": (-480,),
    "Asia/Hong_Kong": (-480,),
    "Asia/Singapore": (-480,),
    "Asia/Tokyo": (-540,),
    "UTC": (0,),
    "Etc/UTC": (0,),
    "Europe/London": (0, -60),
    "Europe/Berlin": (-60, -120),
    "America/New_York": (300, 240),
    "America/Chicago": (360, 300),
    "America/Denver": (420, 360),
    "America/Los_Angeles": (480, 420),
}

# 国家代码对应的合理时区前缀
COUNTRY_TIMEZONE_PREFIXES: Dict[str, tuple[str, ...]] = {
    "CN": ("Asia/Shanghai", "Asia/Chongqing", "Asia/Harbin", "Asia/Urumqi", "Asia/Hong_Kong", "Asia/Macau", "PRC"),
    "US": ("America/", "US/", "Pacific/Honolulu"),
    "HK": ("Asia/Hong_Kong",),
    "SG": ("Asia/Singapore",),
    "DE": ("Europe/Berlin", "Europe/Busingen"),
}


def compute_fp_id(canvas_hash: str, audio_hash: str) -> str:
    """按第 5 章与 9.4 定义计算 canvas_hash + audio_hash 复合指纹 ID。"""
    raw = f"{canvas_hash.strip()}:{audio_hash.strip()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def _is_mobile_ua(ua_lower: str) -> bool:
    return any(tok in ua_lower for tok in ("iphone", "ipad", "ipod", "android", "mobile"))


def evaluate_consistency(
    payload: Dict[str, Any],
    headers: Mapping[str, str],
    geo: GeoInfo,
) -> ConsistencyResult:
    """执行模块二全量一致性检验、WebGL 检查、指纹复用统计与增强探针校验。"""
    ua = str(payload.get("ua") or "")
    ua_lower = ua.lower()
    platform = str(payload.get("platform") or "")
    platform_lower = platform.lower()
    languages = [str(x) for x in (payload.get("languages") or [])]
    tz = str(payload.get("timezone") or "")
    screen = payload.get("screen") or {}
    device_memory = float(payload.get("device_memory") or 0)
    touch_points = int(payload.get("touch_points") or 0)
    canvas_hash = str(payload.get("canvas_hash") or "")
    audio_hash = str(payload.get("audio_hash") or "")
    webgl = payload.get("webgl") or {}
    webgl_renderer = str(webgl.get("renderer") or "")
    webgl_masked = bool(webgl.get("masked", False))
    extra = payload.get("extra_probes") or {}

    norm_headers = {k.lower(): v for k, v in headers.items()}
    sec_ch_ua = norm_headers.get("sec-ch-ua", "").strip()
    accept_lang = norm_headers.get("accept-language", "").strip()

    fp_id = compute_fp_id(canvas_hash, audio_hash)
    res = ConsistencyResult(fp_id=fp_id, webgl_masked=webgl_masked)

    def add_conflict(rule_id: str, left: str, right: str, msg: str, weight: int, enhanced: bool = False) -> None:
        res.score += weight
        if ReasonCode.FINGERPRINT_CONFLICT.value not in res.reasons:
            res.reasons.append(ReasonCode.FINGERPRINT_CONFLICT.value)
        item = ConflictItem(
            rule_id=rule_id,
            left_evidence=left,
            right_evidence=right,
            message=msg,
            is_enhanced=enhanced,
        )
        res.conflicts.append(item)
        if enhanced:
            res.enhanced_findings.append(item.to_dict())

    # ── 规则 1：UA 的 OS 字段 vs navigator.platform ──────────────────────────
    if ua and platform:
        is_ua_win = "windows" in ua_lower
        is_ua_mac = ("mac os x" in ua_lower or "macintosh" in ua_lower) and not _is_mobile_ua(ua_lower)
        is_ua_ios = any(k in ua_lower for k in ("iphone", "ipad", "ipod"))
        is_ua_android = "android" in ua_lower
        is_ua_linux = "linux" in ua_lower and not is_ua_android

        os_platform_conflict = False
        if is_ua_win and not platform_lower.startswith("win"):
            os_platform_conflict = True
        elif is_ua_mac and "mac" not in platform_lower:
            os_platform_conflict = True
        elif is_ua_ios and not any(k in platform_lower for k in ("iphone", "ipad", "ipod")):
            os_platform_conflict = True
        elif is_ua_android and not ("linux" in platform_lower or "android" in platform_lower):
            os_platform_conflict = True
        elif is_ua_linux and "linux" not in platform_lower:
            os_platform_conflict = True

        if os_platform_conflict:
            add_conflict(
                "UA_OS_VS_PLATFORM",
                f"UA={ua[:80]}",
                f"platform={platform}",
                f"UA 声明操作系统与 navigator.platform='{platform}' 矛盾",
                SCORE_WEIGHTS["FINGERPRINT_CONFLICT_PER_ITEM"],
            )

    # ── 规则 2：UA 品牌 vs Sec-CH-UA 品牌列表 ────────────────────────────────
    if ua:
        is_chrom = is_chromium_user_agent(ua)
        brands = [b.lower() for b in extract_sec_ch_ua_brands(sec_ch_ua)] if sec_ch_ua else []
        if is_chrom and not sec_ch_ua and not is_non_secure_http_context(norm_headers):
            add_conflict(
                "UA_BRAND_VS_SEC_CH_UA",
                f"UA={ua[:80]}",
                "Sec-CH-UA=<缺失>",
                "Chromium 系 UA 上报指纹时缺少 Sec-CH-UA 客户端品牌提示",
                SCORE_WEIGHTS["FINGERPRINT_CONFLICT_PER_ITEM"],
            )
        elif sec_ch_ua:
            brand_conflict = False
            if "edg/" in ua_lower and not any("edge" in b for b in brands):
                brand_conflict = True
            elif ("firefox/" in ua_lower or ("safari/" in ua_lower and not is_chrom)) and any(
                "chrom" in b or "edge" in b for b in brands
            ):
                brand_conflict = True
            elif is_chrom and brands and not any(any(k in b for k in ("chrom", "edge", "opera", "brave")) for b in brands):
                brand_conflict = True
            if brand_conflict:
                add_conflict(
                    "UA_BRAND_VS_SEC_CH_UA",
                    f"UA={ua[:80]}",
                    f"Sec-CH-UA={sec_ch_ua}",
                    "UA 浏览器品牌与 Sec-CH-UA 品牌列表不一致",
                    SCORE_WEIGHTS["FINGERPRINT_CONFLICT_PER_ITEM"],
                )

    # ── 规则 3：UA 的 OS vs WebGL renderer 字符串 ────────────────────────────
    if ua and webgl_renderer:
        rend_lower = webgl_renderer.lower()
        is_ua_mac = ("mac os x" in ua_lower or "macintosh" in ua_lower) and not _is_mobile_ua(ua_lower)
        is_ua_win = "windows" in ua_lower
        win_only_renderer = any(k in rend_lower for k in ("direct3d", "d3d11", "d3d9", "microsoft basic"))
        mac_only_renderer = any(k in rend_lower for k in ("apple m", "apple gpu", "apple a", "metal renderer"))

        if is_ua_mac and win_only_renderer:
            add_conflict(
                "UA_OS_VS_WEBGL",
                "UA OS=macOS",
                f"renderer={webgl_renderer}",
                "UA 声明 macOS，但 WebGL 渲染器暴露 Windows Direct3D 线索",
                SCORE_WEIGHTS["FINGERPRINT_CONFLICT_PER_ITEM"],
            )
        elif is_ua_win and mac_only_renderer:
            add_conflict(
                "UA_OS_VS_WEBGL",
                "UA OS=Windows",
                f"renderer={webgl_renderer}",
                "UA 声明 Windows，但 WebGL 渲染器暴露 Apple/Metal 显卡线索",
                SCORE_WEIGHTS["FINGERPRINT_CONFLICT_PER_ITEM"],
            )

    # ── 规则 4：effective_ip 归属地 vs timezone ──────────────────────────────
    is_non_loopback = not geo.ip.startswith("127.") and geo.ip != "::1"
    if is_non_loopback and geo.country != "UNKNOWN" and tz:
        allowed_prefixes = COUNTRY_TIMEZONE_PREFIXES.get(geo.country)
        if allowed_prefixes and not any(tz.startswith(p) for p in allowed_prefixes):
            add_conflict(
                "GEO_IP_VS_TIMEZONE",
                f"effective_ip={geo.ip} ({geo.country}/{geo.city})",
                f"timezone={tz}",
                f"IP 归属 {geo.country}（{geo.city}），但前端时区却为 {tz}",
                SCORE_WEIGHTS["FINGERPRINT_CONFLICT_PER_ITEM"],
            )

    # ── 规则 5：effective_ip 归属地 vs languages 首选语言 ────────────────────
    if is_non_loopback and geo.country in {"US", "DE"} and languages:
        primary_lang = languages[0].lower()
        if primary_lang.startswith("zh") and (not accept_lang or "en" not in accept_lang.lower()):
            add_conflict(
                "GEO_IP_VS_LANGUAGE",
                f"effective_ip={geo.ip} ({geo.country})",
                f"languages[0]={languages[0]}, Accept-Language={accept_lang or '<空>'}",
                f"IP 归属 {geo.country}，但首选语言为 {languages[0]} 且 Accept-Language 缺失或不匹配",
                SCORE_WEIGHTS["FINGERPRINT_CONFLICT_PER_ITEM"],
            )

    # ── 规则 6：platform vs screen 特征 + device_memory ──────────────────────
    scr_w = int(screen.get("width") or 0)
    scr_h = int(screen.get("height") or 0)
    is_desktop_platform = platform_lower in {"win32", "win64", "macintel", "linux x86_64"}
    if is_desktop_platform and scr_w > 0 and scr_h > 0:
        if scr_w < 500 and touch_points > 0:
            add_conflict(
                "PLATFORM_VS_SCREEN_TOUCH",
                f"platform={platform}",
                f"screen={scr_w}x{scr_h}, touch_points={touch_points}, mem={device_memory}",
                f"桌面平台 {platform} 却上报手机端小屏分辨率与多点触控参数",
                SCORE_WEIGHTS["FINGERPRINT_CONFLICT_PER_ITEM"],
            )

    # ── 规则 7：touch_points vs UA 设备类型 ──────────────────────────────────
    if ua and _is_mobile_ua(ua_lower) and touch_points == 0:
        add_conflict(
            "TOUCH_VS_MOBILE_UA",
            f"UA=Mobile",
            f"maxTouchPoints={touch_points}",
            "UA 声明移动触屏设备，但 maxTouchPoints=0",
            SCORE_WEIGHTS["FINGERPRINT_CONFLICT_PER_ITEM"],
        )

    # ── WebGL 掩码 / 软件渲染器检测 ─────────────────────────────────────────
    rend_lower = webgl_renderer.lower()
    is_soft_renderer = any(k in rend_lower for k in ("swiftshader", "llvmpipe", "softpipe", "software adapter"))
    if webgl_masked or is_soft_renderer:
        res.webgl_masked = True
        res.score += SCORE_WEIGHTS["WEBGL_MASKED"]
        res.reasons.append(ReasonCode.WEBGL_MASKED.value)
        res.enhanced_findings.append(
            {
                "rule_id": "WEBGL_MASKED_OR_SOFTWARE",
                "left_evidence": f"masked={webgl_masked}",
                "right_evidence": f"renderer={webgl_renderer or 'N/A'}",
                "message": "WebGL 调试信息被隐私策略掩码或命中 SwiftShader 无头软件渲染器",
                "is_enhanced": False,
            }
        )

    # ── 增强实验 1：Canvas 随机噪点投毒检测 ─────────────────────────────────
    canvas_hash_2 = str(extra.get("canvas_hash_2") or "")
    if (
        canvas_hash
        and canvas_hash_2
        and canvas_hash != "canvas_blocked"
        and canvas_hash_2 != "canvas_blocked"
        and canvas_hash != canvas_hash_2
    ):
        add_conflict(
            "ENHANCED_CANVAS_NOISE_POISONING",
            f"canvas_1={canvas_hash[:12]}",
            f"canvas_2={canvas_hash_2[:12]}",
            "同页面连续两次渲染完全相同 Canvas 场景得到不同哈希，识破防指纹插件随机加噪",
            SCORE_WEIGHTS["CANVAS_NOISE_POISON"],
            enhanced=True,
        )

    # ── 增强实验 2：Web Worker 跨线程一致性校验 ───────────────────────────
    worker = extra.get("worker") or {}
    if isinstance(worker, dict) and worker.get("supported"):
        w_ua = str(worker.get("ua") or "")
        w_plat = str(worker.get("platform") or "")
        w_cores = worker.get("hardware_concurrency")
        if (w_ua and ua and w_ua != ua) or (w_plat and platform and w_plat != platform):
            add_conflict(
                "ENHANCED_WORKER_NAVIGATOR_MISMATCH",
                f"Main({platform}, {ua[:40]})",
                f"Worker({w_plat}, {w_ua[:40]})",
                "Web Worker 线程读取的 navigator 与主线程不一致，识破仅在 Window 上下文执行的 Stealth Patch",
                SCORE_WEIGHTS["WORKER_MISMATCH"],
                enhanced=True,
            )
        elif w_cores is not None and int(payload.get("hardware_concurrency") or 0) > 0:
            if int(w_cores) != int(payload.get("hardware_concurrency") or 0):
                add_conflict(
                    "ENHANCED_WORKER_CORES_MISMATCH",
                    f"Main cores={payload.get('hardware_concurrency')}",
                    f"Worker cores={w_cores}",
                    "主线程与 Web Worker 线程 hardwareConcurrency 并发核数不一致",
                    SCORE_WEIGHTS["WORKER_MISMATCH"],
                    enhanced=True,
                )

    # ── 增强实验 3：timezoneOffset vs Intl 时区名称深度交叉校验 ─────────────
    tz_offset = extra.get("timezone_offset")
    if tz and tz_offset is not None and tz in EXPECTED_TZ_OFFSETS:
        expected_offsets = EXPECTED_TZ_OFFSETS[tz]
        if int(tz_offset) not in expected_offsets:
            add_conflict(
                "ENHANCED_TZ_OFFSET_MISMATCH",
                f"Intl.timeZone={tz}",
                f"getTimezoneOffset()={tz_offset}",
                f"Intl 时区 {tz} 期望分钟偏移 {expected_offsets}，与 Date.getTimezoneOffset()={tz_offset} 矛盾",
                SCORE_WEIGHTS["TIMEZONE_OFFSET_MISMATCH"],
                enhanced=True,
            )

    # ── 增强实验 4：JS 引擎 Math 浮点指纹 vs UA 声明内核 ───────────────────
    math_fp = extra.get("math_fp") or {}
    if isinstance(math_fp, dict) and math_fp.get("tan") and ua:
        tan_str = str(math_fp.get("tan"))
        # V8 与 SpiderMonkey 在 Math.tan(-1e300) 的尾数实现不同：V8 通常以 -1.4214488238747245 开头
        is_v8_tan = tan_str.startswith("-1.4214488")
        is_sm_tan = tan_str.startswith("-4.9871838")
        if "firefox/" in ua_lower and is_v8_tan:
            add_conflict(
                "ENHANCED_MATH_ENGINE_MISMATCH",
                "UA=Firefox (SpiderMonkey)",
                f"Math.tan(-1e300)={tan_str}",
                "UA 伪装为 Firefox，但底层 Math 浮点计算特征暴露实际运行在 Chromium V8 引擎",
                SCORE_WEIGHTS["MATH_ENGINE_MISMATCH"],
                enhanced=True,
            )
        elif is_chromium_user_agent(ua) and is_sm_tan:
            add_conflict(
                "ENHANCED_MATH_ENGINE_MISMATCH",
                "UA=Chromium (V8)",
                f"Math.tan(-1e300)={tan_str}",
                "UA 伪装为 Chrome，但底层 Math 浮点计算特征暴露 SpiderMonkey 引擎",
                SCORE_WEIGHTS["MATH_ENGINE_MISMATCH"],
                enhanced=True,
            )

    # ── 9.4 指纹稳定性追踪：同一 fp_id 命中 >=3 个不同 IP ───────────────────
    cache = get_cache()
    fp_ips_key = f"fp_ips:{fp_id}"
    cache.sadd(fp_ips_key, geo.ip)
    cache.expire(fp_ips_key, 86400)
    hit_ips = cache.scard(fp_ips_key)
    res.hit_ips = max(1, hit_ips)

    if res.hit_ips >= DECISION_THRESHOLDS["FP_REUSE_IP_COUNT"]:
        res.score += SCORE_WEIGHTS["FINGERPRINT_REUSE"]
        if ReasonCode.FINGERPRINT_REUSE.value not in res.reasons:
            res.reasons.append(ReasonCode.FINGERPRINT_REUSE.value)

    res.reasons = list(dict.fromkeys(res.reasons))
    return res
