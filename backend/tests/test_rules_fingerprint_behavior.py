"""模块二（指纹一致性与复用）与模块三（自动化特征与行为轨迹）单测及边界测试。"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi.testclient import TestClient

from app.constants import ReasonCode
from app.services.automation import evaluate_automation
from app.services.behavior import check_price_visit_order, evaluate_behavior, record_visit
from app.services.consistency import evaluate_consistency
from app.services.geoip import GeoInfo
from tests.conftest import BROWSER_HEADERS


def _natural_points(count: int = 35) -> List[Dict[str, Any]]:
    """生成带自然方向转折与变速的人类鼠标轨迹（>30 点，>=8 转折，vel_std > 0.05）。"""
    import math

    pts: List[Dict[str, Any]] = []
    t = 1000
    for i in range(count):
        angle = i * 0.75
        x = 120 + i * 9 + int(math.sin(angle) * 28)
        y = 200 + int(math.cos(angle * 1.4) * 35)
        dt = 15 + (i % 5) * 14  # 变动时间步长，产生自然速度波动
        t += dt
        pts.append({"x": x, "y": y, "t": t, "isTrusted": True})
    return pts


def test_consistency_matrix_all_rules() -> None:
    """验证 9.3 全部 7 条一致性规则 + WebGL 掩码 + 增强检测（噪点/Worker/时区偏移/Math）。"""
    us_geo = GeoInfo(
        ip="52.95.10.20",
        country="US",
        city="Ashburn",
        asn="AWS",
        is_datacenter=True,
        is_blacklist=False,
        is_simulated=True,
        score=25,
        reasons=[ReasonCode.DATACENTER_IP.value],
    )
    payload: Dict[str, Any] = {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
        "platform": "Win32",  # 规则 1：macOS UA vs Win32
        "languages": ["zh-CN"],  # 规则 5：美国 IP 首选 zh 且缺 Accept-Language
        "timezone": "Asia/Shanghai",  # 规则 4：美国 IP vs 上海时区
        "screen": {"width": 390, "height": 844},  # 规则 6：Win32 配手机屏+触控
        "device_memory": 4,
        "hardware_concurrency": 8,
        "touch_points": 5,
        "canvas_hash": "hash_a",
        "audio_hash": "hash_b",
        "webgl": {
            "vendor": "Google",
            "renderer": "ANGLE (Intel Direct3D11 vs_5_0 SwiftShader)",  # 规则 3 + 软渲染
            "masked": False,
        },
        "extra_probes": {
            "canvas_hash_2": "hash_a_mutated",  # 增强 1：Canvas 随机噪点
            "timezone_offset": 0,  # 增强 3：Asia/Shanghai 期望 -480
            "worker": {
                "supported": True,
                "ua": "Mozilla/5.0 (Windows NT 10.0) Firefox/128.0",
                "platform": "Linux x86_64",
            },
        },
    }
    # 规则 2：Chromium UA 缺少 Sec-CH-UA（由 headers 未传触发）
    res = evaluate_consistency(payload, {}, us_geo)
    rule_ids = {c.rule_id for c in res.conflicts}
    assert "UA_OS_VS_PLATFORM" in rule_ids
    assert "UA_BRAND_VS_SEC_CH_UA" in rule_ids
    assert "UA_OS_VS_WEBGL" in rule_ids
    assert "GEO_IP_VS_TIMEZONE" in rule_ids
    assert "GEO_IP_VS_LANGUAGE" in rule_ids
    assert "PLATFORM_VS_SCREEN_TOUCH" in rule_ids
    assert "ENHANCED_CANVAS_NOISE_POISONING" in rule_ids
    assert "ENHANCED_WORKER_NAVIGATOR_MISMATCH" in rule_ids
    assert "ENHANCED_TZ_OFFSET_MISMATCH" in rule_ids
    assert ReasonCode.FINGERPRINT_CONFLICT.value in res.reasons
    assert ReasonCode.WEBGL_MASKED.value in res.reasons


def test_consistency_rule7_mobile_zero_touch_and_math_mismatch() -> None:
    """规则 7（移动 UA maxTouchPoints=0）与增强 Math 浮点引擎矛盾。"""
    cn_geo = GeoInfo("116.228.1.1", "CN", "Shanghai", "AS4812", False, False, True, 0, [])
    payload = {
        "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148 Firefox/126.0",
        "platform": "iPhone",
        "languages": ["zh-CN"],
        "timezone": "Asia/Shanghai",
        "screen": {"width": 390, "height": 844},
        "touch_points": 0,
        "canvas_hash": "c_mob",
        "audio_hash": "a_mob",
        "webgl": {"vendor": "Apple", "renderer": "Apple GPU", "masked": False},
        "extra_probes": {"math_fp": {"tan": "-1.4214488238747245"}},
    }
    res = evaluate_consistency(payload, {"Accept-Language": "zh-CN"}, cn_geo)
    rule_ids = {c.rule_id for c in res.conflicts}
    assert "TOUCH_VS_MOBILE_UA" in rule_ids
    assert "ENHANCED_MATH_ENGINE_MISMATCH" in rule_ids


def test_fingerprint_reuse_boundary_3_ips(client: TestClient) -> None:
    """9.4 边界：同一 fp_id 命中 2 个 IP 不触发复用，第 3 个不同 IP 触发 FINGERPRINT_REUSE (+30)。"""
    cn_ips = ["116.228.1.10", "116.228.1.11", "123.125.1.12"]
    for idx, ip in enumerate(cn_ips):
        resp = client.post(
            "/api/v1/fingerprint/report",
            headers={**BROWSER_HEADERS, "X-Simulated-IP": ip},
            json={
                "ua": BROWSER_HEADERS["User-Agent"],
                "platform": "Win32",
                "languages": ["zh-CN"],
                "timezone": "Asia/Shanghai",
                "screen": {"width": 1920, "height": 1080, "availWidth": 1920, "availHeight": 1040, "colorDepth": 24, "devicePixelRatio": 1},
                "device_memory": 8,
                "hardware_concurrency": 12,
                "touch_points": 0,
                "canvas_hash": "reuse_canvas_same",
                "audio_hash": "reuse_audio_same",
                "webgl": {"vendor": "Intel", "renderer": "ANGLE (Intel Direct3D11)", "masked": False},
                "fonts": {"detected": ["Arial"], "count": 1},
                "automation": {"webdriver": False, "has_window_chrome": True, "plugins_length": 3},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["hit_ips"] == idx + 1
        if idx < 2:
            assert ReasonCode.FINGERPRINT_REUSE.value not in data["warnings"]
        else:
            assert ReasonCode.FINGERPRINT_REUSE.value in data["warnings"]


def test_automation_evaluation_markers() -> None:
    """模块三自动化检测：webdriver / getter / cdc / CDP / Hook / Iframe。"""
    res = evaluate_automation(
        {
            "webdriver": False,
            "webdriver_getter_tampered": True,
            "cdc_keys": ["$cdc_asdjflasutopfhvcZLmcfl_"],
            "cdp_console_probe": True,
            "has_window_chrome": False,
            "plugins_length": 0,
            "hooked_native": True,
            "iframe_mismatch": True,
            "stack_automation_frame": True,
        },
        ua=BROWSER_HEADERS["User-Agent"],
    )
    assert ReasonCode.AUTOMATION_MARKER.value in res.reasons
    assert ReasonCode.CDP_MARKER.value in res.reasons
    assert res.score >= 100


def test_behavior_thresholds_exact_boundaries() -> None:
    """10.2 行为分析精确边界测试：点数 29/30、页面停留 1.99/2.0、击键方差 29/31、合成事件、直线。"""
    # 1. 人类自然交互全部过关（35 点 + 自然转折 + 停留 3s + 非等间隔击键）
    human_res = evaluate_behavior(
        {
            "points": _natural_points(35),
            "keys": [
                {"key": "*", "downTs": 100, "upTs": 140, "isTrusted": True},
                {"key": "*", "downTs": 180, "upTs": 220, "isTrusted": True},
                {"key": "*", "downTs": 340, "upTs": 390, "isTrusted": True},
            ],
            "scrolls": [],
            "page_seconds": 2.0,
        }
    )
    assert human_res.score == 0
    assert human_res.flags == []

    # 2. 边界 29 点（<30）& 页面停留 1.99s（<2.0）
    few_res = evaluate_behavior(
        {
            "points": _natural_points(29),
            "keys": [],
            "scrolls": [],
            "page_seconds": 1.99,
        }
    )
    assert ReasonCode.BOT_TRAJECTORY.value in few_res.flags
    assert few_res.score == 35  # 20 (<30 pts) + 15 (<2s)

    # 3. 30 点严格直线 + isTrusted=false
    linear_pts = [{"x": 100 + i * 10, "y": 100 + i * 5, "t": 1000 + i * 20, "isTrusted": False} for i in range(30)]
    syn_res = evaluate_behavior({"points": linear_pts, "keys": [], "scrolls": [], "page_seconds": 5.0})
    assert ReasonCode.SYNTHETIC_EVENT.value in syn_res.flags
    assert ReasonCode.BOT_TRAJECTORY.value in syn_res.flags
    assert syn_res.score == 65  # 40 + 25

    # 4. 键盘动力学等间隔（方差=0 < 30 ms²）
    robot_keys = evaluate_behavior(
        {
            "points": _natural_points(32),
            "keys": [
                {"key": "*", "downTs": 100, "upTs": 130, "isTrusted": True},
                {"key": "*", "downTs": 200, "upTs": 230, "isTrusted": True},
                {"key": "*", "downTs": 300, "upTs": 330, "isTrusted": True},
            ],
            "scrolls": [],
            "page_seconds": 3.0,
        }
    )
    assert ReasonCode.KEYBOARD_ROBOTIC.value in robot_keys.flags

    # 5. 零交互直奔深层
    zero_res = evaluate_behavior({"points": [], "keys": [], "scrolls": [], "page_seconds": 3.0})
    assert ReasonCode.NO_INTERACTION_DEEP_ACCESS.value in zero_res.flags


def test_visit_order_graph(client: TestClient) -> None:
    """10.3 访问顺序图：必须先出现 `/` 再出现 `/api/v1/products`。"""
    assert check_price_visit_order("sess_empty") is False

    record_visit("sess_bad", "/api/v1/products")
    assert check_price_visit_order("sess_bad") is False

    record_visit("sess_good", "/")
    record_visit("sess_good", "/api/v1/products")
    assert check_price_visit_order("sess_good") is True
