"""
AntiCrawl Lab 合规自动化检测回归共享场景库（regression_scenarios.py）。

职责：
- 作为单一数据源，同时驱动 pytest 自动化回归套件（`test_detection_regression_matrix.py`）
  与命令行回归运行器（`scripts/regression_runner.py`）。
- 覆盖 5 大检测维度：
  1. 8 类真实人类多终端基线（Windows/macOS/Linux/iOS/Android × Chrome/Edge/Safari/Firefox × HTTPS/公网HTTP），
     用于严格验证零误报（FPR = 0%）。
  2. 12 类对抗/自动化/伪装/穿透样本（curl、JA4 伪造、HeadlessChrome、Stealth 补丁、$cdc_+CDP、
     跨 OS + Worker 泄露、V8/SpiderMonkey 引擎矛盾、Canvas/ClientRects 加噪、无硬件 Docker 容器、
     机械轨迹/合成事件、WebRTC STUN 穿透、Clash 规则分流），用于严格验证高检出（TPR = 100%）。
  3. 10 家国内主流云厂商机房 IP（阿里云/腾讯云/华为云/火山引擎/百度云/京东云/UCloud/金山云/青云/网易云）。
  4. IP 穿透与分流演练场景（干净住宅 / WebRTC STUN 穿透 / Clash 规则分流）。
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class BenignPersona:
    """真实人类多终端良性画像基线。"""

    id: str
    name: str
    ip: str
    headers: Dict[str, str]
    payload: Dict[str, Any]
    max_bot_confidence: float = 24.9
    expected_bot_confidence: float = 0.0


@dataclass(frozen=True)
class AdversarialCase:
    """自动化/伪装/泄露对抗回归样本。"""

    id: str
    dimension: str
    name: str
    method: str  # "GET" | "POST"
    path: str
    ip: str
    headers: Dict[str, str]
    payload: Optional[Dict[str, Any]]
    expected_verdicts: Tuple[str, ...]
    min_bot_confidence: float
    required_reason_ids: Tuple[str, ...]


# 国内 10 家主流云厂商核心网段回归样本（ip, vendor_code, vendor_keyword）
CN_CLOUD_REGRESSION_SAMPLES: Tuple[Tuple[str, str, str], ...] = (
    ("47.96.10.20", "aliyun", "阿里云"),
    ("119.29.10.20", "tencent", "腾讯云"),
    ("114.115.10.20", "huawei", "华为云"),
    ("180.184.10.20", "volcengine", "火山引擎"),
    ("180.76.10.20", "baidu", "百度智能云"),
    ("114.67.10.20", "jdcloud", "京东云"),
    ("106.75.10.20", "ucloud", "UCloud"),
    ("120.92.10.20", "ksyun", "金山云"),
    ("139.198.10.20", "qingcloud", "青云"),
    ("59.111.10.20", "netease", "网易"),
)

WIN_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
WIN_EDGE_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0"
)
MAC_SAFARI_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
)
MAC_FIREFOX_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) "
    "Gecko/20100101 Firefox/128.0"
)
LINUX_CHROME_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
IOS_SAFARI_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
)
ANDROID_CHROME_UA = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36"
)
CHROME_SEC_CH_UA = '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"'
EDGE_SEC_CH_UA = '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"'


def make_human_behavior() -> Dict[str, Any]:
    """构造满足 10.2 人类基线的交互轨迹：>=30 点、方向变化 >=8、速度方差自然、isTrusted=True。"""
    pts: List[Dict[str, Any]] = []
    x = 120.0
    y = 240.0
    t = 1000
    dt_cycle = (14, 28, 46, 19, 62)
    for i in range(36):
        dx = 6.0 + (i % 5) * 3.0
        dy = (1.0 if i % 2 == 0 else -1.0) * (5.0 + (i % 4) * 3.5)
        x += dx
        y += dy
        t += dt_cycle[i % len(dt_cycle)]
        pts.append({"x": round(x, 1), "y": round(y, 1), "t": t, "isTrusted": True})

    return {
        "points": pts,
        "keys": [
            {"key": "*", "downTs": 100, "upTs": 142, "isTrusted": True},
            {"key": "*", "downTs": 215, "upTs": 258, "isTrusted": True},
            {"key": "*", "downTs": 430, "upTs": 476, "isTrusted": True},
        ],
        "scrolls": [{"y": 180, "t": 1520, "isTrusted": True}],
        "page_seconds": 5.4,
        "visit_path": ["/", "/bot-check"],
    }


def make_base_human_payload(seed: str, *, run_tag: str = "reg") -> Dict[str, Any]:
    """
    构造完整且自洽的 Windows 桌面 Chrome 人类探针载荷。
    注：每个用例使用独立 `canvas_hash`/`audio_hash`（由 `run_tag` 与 `seed` 决定），
    避免多 IP 用例共享同一指纹哈希而触发 FINGERPRINT_REUSE 交叉污染。
    """
    cv = f"cv_{run_tag}_{seed}"
    au = f"au_{run_tag}_{seed}"
    cr = f"rect_{run_tag}_{seed}"
    return {
        "ua": WIN_CHROME_UA,
        "platform": "Win32",
        "languages": ["zh-CN", "zh", "en"],
        "timezone": "Asia/Shanghai",
        "screen": {
            "width": 1920,
            "height": 1080,
            "availWidth": 1920,
            "availHeight": 1040,
            "colorDepth": 24,
            "devicePixelRatio": 1,
        },
        "device_memory": 8,
        "hardware_concurrency": 12,
        "touch_points": 0,
        "canvas_hash": cv,
        "audio_hash": au,
        "webgl": {
            "vendor": "Google Inc. (Intel)",
            "renderer": "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0)",
            "masked": False,
        },
        "fonts": {
            "detected": ["Arial", "Microsoft YaHei", "Consolas", "SimSun"],
            "count": 4,
        },
        "automation": {
            "webdriver": False,
            "webdriver_getter_tampered": False,
            "cdc_keys": [],
            "selenium_keys": [],
            "legacy_keys": [],
            "cdp_console_probe": False,
            "has_window_chrome": True,
            "plugins_length": 5,
            "hooked_native": False,
            "iframe_mismatch": False,
            "stack_automation_frame": False,
        },
        "extra_probes": {
            "canvas_hash_2": cv,
            "timezone_offset": -480,
            "worker": {
                "supported": True,
                "ua": WIN_CHROME_UA,
                "platform": "Win32",
                "hardware_concurrency": 12,
            },
            "math_fp": {"tan": "-1.4214488238747245"},
            "user_agent_data": {"platform": "Windows", "mobile": False},
            "window_dims": {"outerWidth": 1920, "outerHeight": 1040, "innerWidth": 1900, "innerHeight": 960},
            "css_media": {"pointer_fine": True, "hover_hover": True},
            "sannysoft": {
                "chrome_subprops": {"present": True, "runtime": True},
                "permissions_inconsistent": False,
                "plugins_proto_valid": True,
                "mime_types_length": 2,
                "mime_types_proto_valid": True,
                "language": "zh-CN",
                "broken_image_ok": True,
                "get_image_data_hooked": False,
            },
            "browserleaks": {
                "client_rects_hash": cr,
                "client_rects_hash_2": cr,
                "webgl_extensions_count": 32,
                "webgl_max_texture_size": 16384,
                "media_devices_count": 3,
                "speech_voices_count": 4,
            },
        },
        "behavior": make_human_behavior(),
    }


def _deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in patch.items():
        # 显式传入空字典 {} 时视为清空该字段（例如 Safari/Firefox 不存在 userAgentData）
        if isinstance(v, dict) and v and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def build_benign_personas(*, octet: int = 201, run_tag: str = "reg") -> List[BenignPersona]:
    """构建 8 类覆盖桌面端与移动端的真实人类终端画像（均分配本地预置住宅宽带前缀）。"""
    personas: List[BenignPersona] = []

    # 1. Windows Chrome (HTTPS 安全上下文)
    p1_payload = make_base_human_payload("b1_win_chrome_https", run_tag=run_tag)
    personas.append(
        BenignPersona(
            id="win_chrome_https",
            name="Windows Chrome 126 (HTTPS 安全上下文)",
            ip=f"116.228.{octet}.1",
            headers={
                "User-Agent": WIN_CHROME_UA,
                "Sec-CH-UA": CHROME_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Origin": "https://lab.example.com",
                "X-Forwarded-Proto": "https",
                "X-Simulated-IP": f"116.228.{octet}.1",
            },
            payload=p1_payload,
        )
    )

    # 2. Windows Chrome (公网明文 HTTP：无 Sec-CH-UA 与 Sec-Fetch-Site，验证非安全上下文零误报)
    p2_payload = make_base_human_payload("b2_win_chrome_http", run_tag=run_tag)
    p2_payload["extra_probes"]["user_agent_data"] = {}
    personas.append(
        BenignPersona(
            id="win_chrome_public_http",
            name="Windows Chrome 126 (公网明文 HTTP 无 Client Hints)",
            ip=f"116.228.{octet}.2",
            headers={
                "User-Agent": WIN_CHROME_UA,
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Origin": "http://119.29.10.20:8090",
                "Referer": "http://119.29.10.20:8090/bot-check",
                "X-Forwarded-Proto": "http",
                "X-Simulated-IP": f"116.228.{octet}.2",
            },
            payload=p2_payload,
        )
    )

    # 3. Windows Edge (HTTPS)
    p3_payload = _deep_merge(
        make_base_human_payload("b3_win_edge", run_tag=run_tag),
        {
            "ua": WIN_EDGE_UA,
            "webgl": {
                "vendor": "Google Inc. (NVIDIA)",
                "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0)",
                "masked": False,
            },
            "extra_probes": {"worker": {"ua": WIN_EDGE_UA}},
        },
    )
    personas.append(
        BenignPersona(
            id="win_edge_https",
            name="Windows Edge 126 (HTTPS + NVIDIA D3D11)",
            ip=f"180.168.{octet}.3",
            headers={
                "User-Agent": WIN_EDGE_UA,
                "Sec-CH-UA": EDGE_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "X-Simulated-IP": f"180.168.{octet}.3",
            },
            payload=p3_payload,
        )
    )

    # 4. macOS Safari 17
    p4_payload = _deep_merge(
        make_base_human_payload("b4_mac_safari", run_tag=run_tag),
        {
            "ua": MAC_SAFARI_UA,
            "platform": "MacIntel",
            "webgl": {"vendor": "Apple Inc.", "renderer": "Apple M2", "masked": False},
            "fonts": {"detected": ["PingFang SC", "Helvetica Neue", "Arial", "Menlo"], "count": 4},
            "automation": {"has_window_chrome": False},
            "extra_probes": {
                "worker": {"ua": MAC_SAFARI_UA, "platform": "MacIntel", "hardware_concurrency": 8},
                "math_fp": {"tan": "-0.174351903728"},
                "user_agent_data": {},
                "sannysoft": {"chrome_subprops": {"present": False, "runtime": False}},
            },
            "hardware_concurrency": 8,
        },
    )
    personas.append(
        BenignPersona(
            id="macos_safari",
            name="macOS Safari 17 (Apple M2 / 无 Sec-CH-UA)",
            ip=f"123.125.{octet}.4",
            headers={
                "User-Agent": MAC_SAFARI_UA,
                "Accept-Language": "zh-CN,zh-Hans;q=0.9",
                "X-Simulated-IP": f"123.125.{octet}.4",
            },
            payload=p4_payload,
        )
    )

    # 5. macOS Firefox 128 (SpiderMonkey Math + Firefox JA4)
    p5_payload = _deep_merge(
        make_base_human_payload("b5_mac_firefox", run_tag=run_tag),
        {
            "ua": MAC_FIREFOX_UA,
            "platform": "MacIntel",
            "webgl": {"vendor": "Mozilla", "renderer": "Apple M2", "masked": False},
            "fonts": {"detected": ["PingFang SC", "Helvetica", "Monaco"], "count": 3},
            "automation": {"has_window_chrome": False},
            "extra_probes": {
                "worker": {"ua": MAC_FIREFOX_UA, "platform": "MacIntel", "hardware_concurrency": 8},
                "math_fp": {"tan": "-4.987183847192"},
                "user_agent_data": {},
                "sannysoft": {"chrome_subprops": {"present": False, "runtime": False}},
            },
            "hardware_concurrency": 8,
        },
    )
    personas.append(
        BenignPersona(
            id="macos_firefox",
            name="macOS Firefox 128 (SpiderMonkey 浮点引擎)",
            ip=f"114.242.{octet}.5",
            headers={
                "User-Agent": MAC_FIREFOX_UA,
                "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                "X-JA4": "t13d1715h2_1a2b3c4d5e6f_7a8b9c0d1e2f",
                "X-Simulated-IP": f"114.242.{octet}.5",
            },
            payload=p5_payload,
        )
    )

    # 6. Linux 桌面 Chrome
    p6_payload = _deep_merge(
        make_base_human_payload("b6_linux_chrome", run_tag=run_tag),
        {
            "ua": LINUX_CHROME_UA,
            "platform": "Linux x86_64",
            "webgl": {"vendor": "Intel", "renderer": "Mesa Intel(R) Graphics (ADL GT2)", "masked": False},
            "fonts": {"detected": ["DejaVu Sans", "Liberation Sans", "Ubuntu", "Noto Sans CJK SC"], "count": 4},
            "extra_probes": {
                "worker": {"ua": LINUX_CHROME_UA, "platform": "Linux x86_64", "hardware_concurrency": 8},
                "user_agent_data": {"platform": "Linux", "mobile": False},
            },
            "hardware_concurrency": 8,
        },
    )
    personas.append(
        BenignPersona(
            id="linux_desktop_chrome",
            name="Linux Desktop Chrome 126 (Mesa Intel 核显)",
            ip=f"113.108.{octet}.6",
            headers={
                "User-Agent": LINUX_CHROME_UA,
                "Sec-CH-UA": CHROME_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "X-Simulated-IP": f"113.108.{octet}.6",
            },
            payload=p6_payload,
        )
    )

    # 7. iOS iPhone Safari 移动端
    p7_payload = _deep_merge(
        make_base_human_payload("b7_ios_safari", run_tag=run_tag),
        {
            "ua": IOS_SAFARI_UA,
            "platform": "iPhone",
            "touch_points": 5,
            "device_memory": 4,
            "hardware_concurrency": 6,
            "screen": {
                "width": 390,
                "height": 844,
                "availWidth": 390,
                "availHeight": 844,
                "colorDepth": 24,
                "devicePixelRatio": 3,
            },
            "webgl": {"vendor": "Apple Inc.", "renderer": "Apple GPU", "masked": False},
            "fonts": {"detected": ["PingFang SC", "Helvetica Neue"], "count": 2},
            "automation": {"has_window_chrome": False, "plugins_length": 0},
            "extra_probes": {
                "worker": {"ua": IOS_SAFARI_UA, "platform": "iPhone", "hardware_concurrency": 6},
                "math_fp": {"tan": "-0.174351903728"},
                "user_agent_data": {},
                "window_dims": {"outerWidth": 390, "outerHeight": 844, "innerWidth": 390, "innerHeight": 664},
                "css_media": {"pointer_fine": False, "hover_hover": False},
                "sannysoft": {
                    "chrome_subprops": {"present": False, "runtime": False},
                    "mime_types_length": 0,
                },
            },
        },
    )
    personas.append(
        BenignPersona(
            id="ios_iphone_safari",
            name="iOS iPhone Safari 17 移动端 (触屏 + Apple GPU)",
            ip=f"116.228.{octet}.7",
            headers={
                "User-Agent": IOS_SAFARI_UA,
                "Accept-Language": "zh-CN,zh-Hans;q=0.9",
                "X-Simulated-IP": f"116.228.{octet}.7",
            },
            payload=p7_payload,
        )
    )

    # 8. Android Chrome 移动端
    p8_payload = _deep_merge(
        make_base_human_payload("b8_android_chrome", run_tag=run_tag),
        {
            "ua": ANDROID_CHROME_UA,
            "platform": "Linux armv8l",
            "touch_points": 5,
            "device_memory": 8,
            "hardware_concurrency": 8,
            "screen": {
                "width": 412,
                "height": 915,
                "availWidth": 412,
                "availHeight": 915,
                "colorDepth": 24,
                "devicePixelRatio": 2.625,
            },
            "webgl": {"vendor": "Qualcomm", "renderer": "Adreno (TM) 740", "masked": False},
            "fonts": {"detected": ["Roboto", "Noto Sans CJK SC"], "count": 2},
            "automation": {"has_window_chrome": True, "plugins_length": 0},
            "extra_probes": {
                "worker": {"ua": ANDROID_CHROME_UA, "platform": "Linux armv8l", "hardware_concurrency": 8},
                "user_agent_data": {"platform": "Android", "mobile": True},
                "window_dims": {"outerWidth": 412, "outerHeight": 915, "innerWidth": 412, "innerHeight": 830},
                "css_media": {"pointer_fine": False, "hover_hover": False},
                "sannysoft": {
                    "chrome_subprops": {"present": True, "runtime": False},
                    "mime_types_length": 0,
                },
            },
        },
    )
    personas.append(
        BenignPersona(
            id="android_chrome_mobile",
            name="Android Chrome 126 移动端 (触屏 + Adreno GPU)",
            ip=f"113.108.{octet}.8",
            headers={
                "User-Agent": ANDROID_CHROME_UA,
                "Sec-CH-UA": CHROME_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "X-Simulated-IP": f"113.108.{octet}.8",
            },
            payload=p8_payload,
        )
    )

    return personas


def build_adversarial_bot_cases(*, octet: int = 202, run_tag: str = "reg") -> List[AdversarialCase]:
    """构建覆盖 5 大维度的 12 类对抗/自动化/泄露回归样本。"""
    cases: List[AdversarialCase] = []

    # 1. 原生 curl + AWS 机房 IP (纯 HTTP GET)
    cases.append(
        AdversarialCase(
            id="http_curl_aws",
            dimension="Network",
            name="curl 原生脚本 + AWS 机房出口",
            method="GET",
            path="/api/v1/bot/check",
            ip=f"52.95.{octet}.1",
            headers={
                "User-Agent": "curl/8.5.0",
                "X-Simulated-IP": f"52.95.{octet}.1",
            },
            payload=None,
            expected_verdicts=("likely_bot",),
            min_bot_confidence=55.0,
            required_reason_ids=("http_headers", "ip_reputation"),
        )
    )

    # 2. 伪造 Chrome UA 但携带 python-requests OpenSSL JA4 + 乱序 Header + 腾讯云 IP (纯 HTTP GET)
    cases.append(
        AdversarialCase(
            id="http_python_ja4_spoof",
            dimension="Network",
            name="伪造 Chrome UA + OpenSSL JA4 + 腾讯云机房",
            method="GET",
            path="/api/v1/bot/check",
            ip="119.29.10.20",
            headers={
                "User-Agent": WIN_CHROME_UA,
                "X-JA4": "t13d1516h2_8daaf6152771_b0da82dd1658",
                "X-Header-Order": "host,accept-encoding,user-agent",
                "X-Simulated-IP": "119.29.10.20",
            },
            payload=None,
            expected_verdicts=("likely_bot",),
            min_bot_confidence=55.0,
            required_reason_ids=("http_headers", "ip_reputation"),
        )
    )

    # 3. 标准无头 Playwright / HeadlessChrome（Sannysoft 全线告警）
    c3_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/126.0.0.0 Safari/537.36"
    c3_payload = _deep_merge(
        make_base_human_payload("a3_headless", run_tag=run_tag),
        {
            "ua": c3_ua,
            "platform": "Linux x86_64",
            "webgl": {"vendor": "Google Inc.", "renderer": "ANGLE (Google, SwiftShader Device)", "masked": False},
            "automation": {"webdriver": True, "plugins_length": 0, "has_window_chrome": False},
            "extra_probes": {
                "worker": {"ua": c3_ua, "platform": "Linux x86_64", "hardware_concurrency": 12},
                "window_dims": {"outerWidth": 0, "outerHeight": 0},
                "sannysoft": {"permissions_inconsistent": True, "mime_types_length": 0},
            },
        },
    )
    cases.append(
        AdversarialCase(
            id="headless_playwright_std",
            dimension="Sannysoft",
            name="标准 HeadlessChrome + webdriver=true + SwiftShader + outerWidth=0",
            method="POST",
            path="/api/v1/bot/check",
            ip=f"116.228.{octet}.3",
            headers={
                "User-Agent": c3_ua,
                "Sec-CH-UA": CHROME_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "X-Simulated-IP": f"116.228.{octet}.3",
            },
            payload=c3_payload,
            expected_verdicts=("likely_bot",),
            min_bot_confidence=95.0,
            required_reason_ids=(
                "user_agent_headless",
                "webdriver_flag",
                "webgl_software_renderer",
                "window_outer_dimensions",
                "permissions_notification_mismatch",
            ),
        )
    )

    # 4. 初级 Stealth 补丁（隐藏了 navigator.webdriver 但暴露原型篡改 + Iframe 不一致 + 原生函数 Hook）
    c4_payload = _deep_merge(
        make_base_human_payload("a4_stealth", run_tag=run_tag),
        {
            "automation": {
                "webdriver": False,
                "webdriver_getter_tampered": True,
                "iframe_mismatch": True,
                "hooked_native": True,
            }
        },
    )
    cases.append(
        AdversarialCase(
            id="basic_stealth_patch",
            dimension="Sannysoft",
            name="初级 Stealth 脚本（getter 篡改 + Iframe 跨 Realm + 原生 Hook）",
            method="POST",
            path="/api/v1/bot/check",
            ip=f"116.228.{octet}.4",
            headers={
                "User-Agent": WIN_CHROME_UA,
                "Sec-CH-UA": CHROME_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "X-Simulated-IP": f"116.228.{octet}.4",
            },
            payload=c4_payload,
            expected_verdicts=("likely_bot",),
            min_bot_confidence=85.0,
            required_reason_ids=(
                "webdriver_proto_tampered",
                "iframe_cross_realm",
                "native_to_string_integrity",
            ),
        )
    )

    # 5. ChromeDriver $cdc_ 全局注入符 + CDP Runtime.enable 序列化探针
    c5_payload = _deep_merge(
        make_base_human_payload("a5_cdp", run_tag=run_tag),
        {
            "automation": {
                "cdc_keys": ["$cdc_asdjflasutopfhvcZLmcfl_"],
                "cdp_console_probe": True,
            }
        },
    )
    cases.append(
        AdversarialCase(
            id="chromedriver_cdp",
            dimension="Sannysoft",
            name="ChromeDriver $cdc_ 全局符号 + CDP Runtime.enable",
            method="POST",
            path="/api/v1/bot/check",
            ip=f"116.228.{octet}.5",
            headers={
                "User-Agent": WIN_CHROME_UA,
                "Sec-CH-UA": CHROME_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "X-Simulated-IP": f"116.228.{octet}.5",
            },
            payload=c5_payload,
            expected_verdicts=("likely_bot",),
            min_bot_confidence=65.0,
            required_reason_ids=("driver_globals", "cdp_runtime_probe"),
        )
    )

    # 6. 跨 OS 伪装 + Web Worker 暴露真实 Windows 宿主机
    mac_chrome_ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    )
    c6_payload = _deep_merge(
        make_base_human_payload("a6_cross_os", run_tag=run_tag),
        {
            "ua": mac_chrome_ua,
            "platform": "Win32",
            "extra_probes": {
                "user_agent_data": {"platform": "macOS", "mobile": False},
                "worker": {"ua": WIN_CHROME_UA, "platform": "Win32", "hardware_concurrency": 12},
            },
        },
    )
    cases.append(
        AdversarialCase(
            id="cross_os_worker_spoof",
            dimension="BrowserScan",
            name="macOS UA 跨维度伪装暴露 Windows Platform/D3D11/Worker",
            method="POST",
            path="/api/v1/bot/check",
            ip=f"116.228.{octet}.6",
            headers={
                "User-Agent": mac_chrome_ua,
                "Sec-CH-UA": CHROME_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "X-Simulated-IP": f"116.228.{octet}.6",
            },
            payload=c6_payload,
            expected_verdicts=("likely_bot",),
            min_bot_confidence=65.0,
            required_reason_ids=("os_platform_webgl_triangulation", "worker_cross_thread"),
        )
    )

    # 7. JS 引擎 Math 浮点矛盾 + Client Hints 品牌矛盾
    win_ff_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
    c7_payload = _deep_merge(
        make_base_human_payload("a7_math_ch", run_tag=run_tag),
        {
            "ua": win_ff_ua,
            "extra_probes": {
                "worker": {"ua": win_ff_ua, "platform": "Win32", "hardware_concurrency": 12},
                "math_fp": {"tan": "-1.4214488238747245"},
            },
        },
    )
    cases.append(
        AdversarialCase(
            id="engine_math_ch_spoof",
            dimension="BrowserScan",
            name="Firefox UA 伪装暴露 V8 Math.tan + Chrome Sec-CH-UA",
            method="POST",
            path="/api/v1/bot/check",
            ip=f"116.228.{octet}.7",
            headers={
                "User-Agent": win_ff_ua,
                "Sec-CH-UA": CHROME_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "X-Simulated-IP": f"116.228.{octet}.7",
            },
            payload=c7_payload,
            expected_verdicts=("likely_bot",),
            min_bot_confidence=55.0,
            required_reason_ids=("js_math_engine", "ua_vs_client_hints", "http_headers"),
        )
    )

    # 8. 反指纹加噪插件对抗（Canvas 双渲染漂移 + ClientRects 漂移 + 时区偏移冲突）
    c8_payload = _deep_merge(
        make_base_human_payload("a8_noise", run_tag=run_tag),
        {
            "extra_probes": {
                "canvas_hash_2": f"cv_mutated_{run_tag}",
                "timezone_offset": 0,
                "browserleaks": {"client_rects_hash_2": f"rect_mutated_{run_tag}"},
            }
        },
    )
    cases.append(
        AdversarialCase(
            id="antidetect_noise_poison",
            dimension="BrowserLeaks",
            name="防指纹随机加噪（Canvas 漂移 + ClientRects 漂移 + 时区倒挂）",
            method="POST",
            path="/api/v1/bot/check",
            ip=f"116.228.{octet}.8",
            headers={
                "User-Agent": WIN_CHROME_UA,
                "Sec-CH-UA": CHROME_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "X-Simulated-IP": f"116.228.{octet}.8",
            },
            payload=c8_payload,
            expected_verdicts=("likely_bot",),
            min_bot_confidence=65.0,
            required_reason_ids=(
                "canvas_noise_poisoning",
                "client_rects_subpixel_noise",
                "timezone_name_vs_offset",
            ),
        )
    )

    # 9. 无硬件 Docker 容器无头浏览器 + 阿里云机房 IP
    c9_payload = _deep_merge(
        make_base_human_payload("a9_docker", run_tag=run_tag),
        {
            "hardware_concurrency": 0,
            "fonts": {"detected": [], "count": 0},
            "extra_probes": {
                "worker": {"ua": WIN_CHROME_UA, "platform": "Win32", "hardware_concurrency": 0},
                "browserleaks": {
                    "webgl_extensions_count": 3,
                    "media_devices_count": 0,
                    "speech_voices_count": 0,
                },
            },
        },
    )
    cases.append(
        AdversarialCase(
            id="docker_headless_container",
            dimension="BrowserLeaks",
            name="Docker 无硬件虚拟容器 + 阿里云机房 IP (47.96.10.20)",
            method="POST",
            path="/api/v1/bot/check",
            ip="47.96.10.20",
            headers={
                "User-Agent": WIN_CHROME_UA,
                "Sec-CH-UA": CHROME_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "X-Simulated-IP": "47.96.10.20",
            },
            payload=c9_payload,
            expected_verdicts=("likely_bot",),
            min_bot_confidence=70.0,
            required_reason_ids=(
                "media_devices_probe",
                "speech_voices_probe",
                "webgl_params_and_extensions",
                "fonts_os_plausibility",
                "hardware_sanity",
                "ip_reputation",
            ),
        )
    )

    # 10. 行为动力学异常（直线匀速 + 合成事件 + 等间隔击键 + 短停留）
    straight_pts = [
        {
            "x": 100 + i * 10,
            "y": 200,
            "t": 1000 + i * 20,
            "isTrusted": False if i == 5 else True,
        }
        for i in range(36)
    ]
    c10_payload = _deep_merge(
        make_base_human_payload("a10_behavior", run_tag=run_tag),
        {
            "behavior": {
                "points": straight_pts,
                "keys": [
                    {"key": "*", "downTs": 100, "upTs": 140, "isTrusted": True},
                    {"key": "*", "downTs": 200, "upTs": 240, "isTrusted": True},
                    {"key": "*", "downTs": 300, "upTs": 340, "isTrusted": True},
                ],
                "scrolls": [],
                "page_seconds": 0.4,
            }
        },
    )
    cases.append(
        AdversarialCase(
            id="robotic_behavior_combo",
            dimension="Behavior",
            name="直线匀速轨迹 + isTrusted=false + 机械击键 + 秒级访问",
            method="POST",
            path="/api/v1/bot/check",
            ip=f"116.228.{octet}.10",
            headers={
                "User-Agent": WIN_CHROME_UA,
                "Sec-CH-UA": CHROME_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "X-Simulated-IP": f"116.228.{octet}.10",
            },
            payload=c10_payload,
            expected_verdicts=("likely_bot",),
            min_bot_confidence=60.0,
            required_reason_ids=("behavior_telemetry",),
        )
    )

    # 11. WebRTC UDP STUN 穿透 VPN 捕获真实国内住宅 IP（即使浏览器已伪造美国时区/语言）
    c11_payload = _deep_merge(
        make_base_human_payload("a11_webrtc_leak", run_tag=run_tag),
        {
            "timezone": "America/New_York",
            "languages": ["en-US", "en"],
            "extra_probes": {
                "timezone_offset": 300,
                "sannysoft": {"language": "en-US"},
                "webrtc": {
                    "supported": True,
                    "mdnsMasked": False,
                    "publicIps": ["116.228.10.5"],
                    "candidates": ["116.228.10.5"],
                },
            },
        },
    )
    cases.append(
        AdversarialCase(
            id="webrtc_stun_vpn_leak",
            dimension="IP/VPN",
            name="AWS 美国代理出口 + WebRTC STUN 穿透捕获国内真实 IP",
            method="POST",
            path="/api/v1/bot/check",
            ip=f"52.95.{octet}.11",
            headers={
                "User-Agent": WIN_CHROME_UA,
                "Sec-CH-UA": CHROME_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "en-US,en;q=0.9",
                "X-Simulated-IP": f"52.95.{octet}.11",
            },
            payload=c11_payload,
            expected_verdicts=("likely_bot",),
            min_bot_confidence=60.0,
            required_reason_ids=("webrtc_ice_leak", "ip_reputation"),
        )
    )

    # 12. Clash / Mihomo 规则分流模式暴露国内外双出口
    c12_payload = _deep_merge(
        make_base_human_payload("a12_split_tunnel", run_tag=run_tag),
        {
            "extra_probes": {
                "ip_channels": {
                    "overseas_echo_ip": "52.95.10.20",
                    "domestic_echo_ip": f"116.228.{octet}.12",
                }
            }
        },
    )
    cases.append(
        AdversarialCase(
            id="split_tunnel_clash_rule",
            dimension="IP/VPN",
            name="Clash 规则分流多出口不一致（国内直连 vs 海外机房代理）",
            method="POST",
            path="/api/v1/bot/check",
            ip=f"116.228.{octet}.12",
            headers={
                "User-Agent": WIN_CHROME_UA,
                "Sec-CH-UA": CHROME_SEC_CH_UA,
                "Sec-Fetch-Site": "same-origin",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "X-Simulated-IP": f"116.228.{octet}.12",
            },
            payload=c12_payload,
            expected_verdicts=("suspicious", "likely_bot"),
            min_bot_confidence=30.0,
            required_reason_ids=("webrtc_ice_leak",),
        )
    )

    return cases
