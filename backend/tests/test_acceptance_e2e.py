"""
第 14 章 12 条验收清单端到端自动化验证套件（test_acceptance_e2e.py）。
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict

from fastapi.testclient import TestClient

from app.constants import ReasonCode
from app.events import get_event_bus
from tests.conftest import BROWSER_HEADERS, make_signed_headers


def test_acceptance_01_ip_rate_limit(client: TestClient) -> None:
    """验收 1：同一 X-Simulated-IP 1 秒内连打业务接口 11 次 → 第 11 次 429, risk_reason=RATE_LIMITED。"""
    ip = "116.228.101.1"
    for idx in range(10):
        r = client.get("/api/v1/font/session", headers={**BROWSER_HEADERS, "X-Simulated-IP": ip})
        assert r.status_code == 200, f"第 {idx + 1} 次应为 200"
    r11 = client.get("/api/v1/font/session", headers={**BROWSER_HEADERS, "X-Simulated-IP": ip})
    assert r11.status_code == 429
    assert r11.json()["risk_reason"] == ReasonCode.RATE_LIMITED.value


def test_acceptance_02_header_missing_warning(client: TestClient) -> None:
    """验收 2：空 User-Agent 请求业务接口 → 记 HEADER_MISSING 警告，状态 200。"""
    ip = "116.228.102.2"
    r = client.get("/api/v1/font/session", headers={"User-Agent": "", "X-Simulated-IP": ip})
    assert r.status_code == 200

    logs = client.get("/api/v1/admin/requests?page=1&size=10").json()["items"]
    matched = next(item for item in logs if item["effective_ip"] == ip)
    assert matched["action"] == "warn"
    assert ReasonCode.HEADER_MISSING.value in matched["reasons"]


def test_acceptance_03_datacenter_ip_recognition(client: TestClient) -> None:
    """验收 3：X-Simulated-IP 指向 mock 库机房段 → 记 DATACENTER_IP 并计入风险分。"""
    ip = "52.95.103.3"
    r = client.get("/api/v1/font/session", headers={**BROWSER_HEADERS, "X-Simulated-IP": ip})
    assert r.status_code == 200

    logs = client.get("/api/v1/admin/requests?page=1&size=10").json()["items"]
    matched = next(item for item in logs if item["effective_ip"] == ip)
    assert ReasonCode.DATACENTER_IP.value in matched["reasons"]
    assert matched["risk_score"] >= 25


def test_acceptance_04_honeypot_ban_and_unban(client: TestClient) -> None:
    """验收 4：请求 /api/v1/trap 后再请求业务接口 → 先 403+封禁记录；解封后恢复。"""
    ip = "123.125.104.4"
    r_trap = client.get("/api/v1/trap", headers={**BROWSER_HEADERS, "X-Simulated-IP": ip})
    assert r_trap.status_code == 403
    assert r_trap.json()["risk_reason"] == ReasonCode.HONEYPOT_TRIGGERED.value

    r_blocked = client.get("/api/v1/font/session", headers={**BROWSER_HEADERS, "X-Simulated-IP": ip})
    assert r_blocked.status_code == 403
    assert r_blocked.json()["risk_reason"] == ReasonCode.BANNED.value

    bans = client.get("/api/v1/admin/bans").json()["items"]
    assert any(b["ip"] == ip and b["active"] for b in bans)

    r_unban = client.post("/api/v1/admin/unban", json={"ip": ip, "operator": "dashboard"})
    assert r_unban.status_code == 200

    r_ok = client.get("/api/v1/font/session", headers={**BROWSER_HEADERS, "X-Simulated-IP": ip})
    assert r_ok.status_code == 200


def test_acceptance_05_webdriver_detection(client: TestClient) -> None:
    """验收 5：自动化环境（webdriver=true）上报 → 命中 AUTOMATION_MARKER，画像可见 webdriver=true。"""
    ip = "116.228.105.5"
    r = client.post(
        "/api/v1/fingerprint/report",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": ip},
        json={
            "ua": BROWSER_HEADERS["User-Agent"],
            "platform": "Win32",
            "languages": ["zh-CN"],
            "timezone": "Asia/Shanghai",
            "screen": {"width": 1920, "height": 1080, "availWidth": 1920, "availHeight": 1040, "colorDepth": 24, "devicePixelRatio": 1},
            "device_memory": 8,
            "hardware_concurrency": 8,
            "touch_points": 0,
            "canvas_hash": "wd_canvas_1",
            "audio_hash": "wd_audio_1",
            "webgl": {"vendor": "Google", "renderer": "ANGLE (Intel Direct3D11)", "masked": False},
            "fonts": {"detected": ["Arial"], "count": 1},
            "automation": {"webdriver": True, "cdc_keys": ["$cdc_test"], "cdp_console_probe": True},
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert ReasonCode.AUTOMATION_MARKER.value in data["warnings"]

    logs = client.get("/api/v1/admin/requests?module=automation&page=1&size=10").json()["items"]
    assert len(logs) >= 1
    detail = client.get(f"/api/v1/admin/requests?id={logs[0]['id']}").json()
    assert detail["fingerprint"]["automation_flags"]["webdriver"] is True


def test_acceptance_06_synthetic_event_detection(client: TestClient) -> None:
    """验收 6：合成事件（isTrusted=false）30 点轨迹上报 → 记 SYNTHETIC_EVENT。"""
    pts = [{"x": 10 + i * 5, "y": 20 + (i % 3) * 15, "t": 100 + i * 20, "isTrusted": False} for i in range(30)]
    r = client.post(
        "/api/v1/behavior/trace",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": "116.228.106.6"},
        json={"points": pts, "keys": [], "scrolls": [], "page_seconds": 4.0, "visit_path": ["/"]},
    )
    assert r.status_code == 200
    body = r.json()
    assert ReasonCode.SYNTHETIC_EVENT.value in body["flags"]
    assert body["metrics"]["trusted_ratio"] == 0.0


def test_acceptance_07_linear_trajectory_detection(client: TestClient) -> None:
    """验收 7：严格直线 30 点轨迹上报 → 记 BOT_TRAJECTORY。"""
    pts = [{"x": 100 + i * 10, "y": 100 + i * 5, "t": 100 + i * 25, "isTrusted": True} for i in range(30)]
    r = client.post(
        "/api/v1/behavior/trace",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": "116.228.107.7"},
        json={"points": pts, "keys": [], "scrolls": [], "page_seconds": 4.0, "visit_path": ["/"]},
    )
    assert r.status_code == 200
    assert ReasonCode.BOT_TRAJECTORY.value in r.json()["flags"]


def test_acceptance_08_signature_missing(client: TestClient) -> None:
    """验收 8：无签名头请求端点 4 → 401 SIGNATURE_MISSING。"""
    r = client.get("/api/v1/products", headers={**BROWSER_HEADERS, "X-Simulated-IP": "116.228.108.8"})
    assert r.status_code == 401
    assert r.json()["risk_reason"] == ReasonCode.SIGNATURE_MISSING.value


def test_acceptance_09_nonce_replay(client: TestClient) -> None:
    """验收 9：同签名 + nonce 请求原样重发 → 第二次 401 NONCE_REUSED。"""
    sig = make_signed_headers("GET", "/api/v1/products")
    hdrs = {**BROWSER_HEADERS, **sig, "X-Simulated-IP": "116.228.109.9"}
    r1 = client.get("/api/v1/products", headers=hdrs)
    assert r1.status_code == 200
    r2 = client.get("/api/v1/products", headers=hdrs)
    assert r2.status_code == 401
    assert r2.json()["risk_reason"] == ReasonCode.NONCE_REUSED.value


def test_acceptance_10_dynamic_font_pua_text(client: TestClient) -> None:
    """验收 10：直接抓取 /price 与签名价格接口，返回价格文本为 U+E000–U+E00A 私用区乱码。"""
    r_html = client.get("/price")
    assert r_html.status_code == 200
    assert any(0xE000 <= ord(ch) <= 0xE00A for ch in r_html.text)
    assert "¥3999" not in r_html.text

    # 同时验证 API 端点 5 经正常导航后返回 PUA 乱码价格
    ip = "116.228.110.10"
    hdrs: Dict[str, Any] = {**BROWSER_HEADERS, "X-Simulated-IP": ip, "X-Session-Id": "sess_acc_10"}
    client.get("/", headers=hdrs)
    client.get("/api/v1/products", headers={**hdrs, **make_signed_headers("GET", "/api/v1/products")})
    r_api = client.get(
        "/api/v1/products/1/price",
        headers={**hdrs, **make_signed_headers("GET", "/api/v1/products/1/price")},
    )
    assert r_api.status_code == 200
    price_pua = r_api.json()["price_pua"]
    assert all(0xE000 <= ord(ch) <= 0xE00A for ch in price_pua)


def test_acceptance_11_consistency_conflict(client: TestClient) -> None:
    """验收 11：模拟美国 IP + 前端时区 Asia/Shanghai 上报 → 记 FINGERPRINT_CONFLICT（环境伪装破绽）。"""
    r = client.post(
        "/api/v1/fingerprint/report",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": "52.95.111.11"},
        json={
            "ua": BROWSER_HEADERS["User-Agent"],
            "platform": "Win32",
            "languages": ["zh-CN", "en"],
            "timezone": "Asia/Shanghai",
            "screen": {"width": 1920, "height": 1080, "availWidth": 1920, "availHeight": 1040, "colorDepth": 24, "devicePixelRatio": 1},
            "device_memory": 8,
            "hardware_concurrency": 8,
            "touch_points": 0,
            "canvas_hash": "us_cn_c",
            "audio_hash": "us_cn_a",
            "webgl": {"vendor": "Intel", "renderer": "ANGLE (Intel Direct3D11)", "masked": False},
            "fonts": {"detected": ["Arial"], "count": 1},
            "automation": {"webdriver": False, "has_window_chrome": True, "plugins_length": 3},
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert ReasonCode.FINGERPRINT_CONFLICT.value in body["warnings"]
    assert any(c["rule_id"] == "GEO_IP_VS_TIMEZONE" for c in body["conflicts"])


def test_acceptance_12_sse_realtime_broadcast(client: TestClient) -> None:
    """验收 12：业务请求触发后，SSE 广播总线即时分发 event: risk 且可用 id 查出详情。"""
    bus = get_event_bus()
    queue = bus.subscribe()
    try:
        ip = "116.228.112.12"
        r = client.get("/api/v1/font/session", headers={**BROWSER_HEADERS, "X-Simulated-IP": ip})
        assert r.status_code == 200

        async def _pull() -> Dict[str, Any]:
            return await asyncio.wait_for(queue.get(), timeout=1.0)

        ev = asyncio.run(_pull())
        assert ev["effective_ip"] == ip
        assert ev["path"] == "/api/v1/font/session"
        assert isinstance(ev["id"], int)

        # 验证点击画像详情端点 10 返回一致记录
        detail = client.get(f"/api/v1/admin/requests?id={ev['id']}")
        assert detail.status_code == 200
        assert detail.json()["item"]["id"] == ev["id"]
    finally:
        bus.unsubscribe(queue)
