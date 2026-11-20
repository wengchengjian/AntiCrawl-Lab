"""
商业实战增强防线（WAF JS 挑战 / 匿名浏览配额 / 分级令牌桶 + 授时）
与全维度机器人检测置信分 API（BrowserScan / BrowserLeaks / Sannysoft）测试套件。
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict

from fastapi.testclient import TestClient

from app.constants import ReasonCode
from tests.conftest import BROWSER_HEADERS, make_signed_headers


def _solve_waf_html(html: str) -> tuple[str, str]:
    """解析 200 HTML/JS 挑战页内的异或编码参数并计算合法 timestamp__1366。"""
    arg_m = re.search(r"\}\)\((\d+),(\[[^\]]+\]),(\[[^\]]+\]),(\[[^\]]+\])\)", html)
    ts_m = re.search(r"ts='(\d+)'", html)
    assert arg_m is not None and ts_m is not None

    xor_key = int(arg_m.group(1))
    dec = lambda raw: "".join(chr(c ^ xor_key) for c in json.loads(raw))
    nid = dec(arg_m.group(2))
    salt = dec(arg_m.group(3))
    param_name = dec(arg_m.group(4))
    ts = ts_m.group(1)

    digest = hashlib.sha256(f"{nid}:{salt}:{ts}:dom1".encode("utf-8")).hexdigest()[:24]
    return param_name, f"{nid}-{ts}-{digest}-dom1"


def test_waf_transparent_200_html_js_challenge(client: TestClient) -> None:
    """复刻阿里云 ESA：无令牌返回 200 text/html JS 挑战，求解一次性令牌后放行 JSON，重放被拒。"""
    ip = "116.228.120.1"
    hdrs = {**BROWSER_HEADERS, "X-Simulated-IP": ip}

    # 1. 无参数直连 → 200 text/html 挑战页
    r1 = client.get("/api/v1/waf/protected-feed", headers=hdrs)
    assert r1.status_code == 200
    assert "text/html" in r1.headers.get("content-type", "")
    assert r1.headers.get("X-WAF-Challenge") == "js-dynamic-token"
    assert "timestamp__1366" in r1.text or "_0x" in r1.text

    # 2. 伪造 token → 仍回落到 200 HTML 挑战页
    r_bad = client.get("/api/v1/waf/protected-feed?timestamp__1366=fake-123-deadbeef-dom1", headers=hdrs)
    assert r_bad.status_code == 200
    assert "text/html" in r_bad.headers.get("content-type", "")

    # 3. 求解挑战 JS 后重试 → 200 JSON 放行
    param_name, token = _solve_waf_html(r1.text)
    r2 = client.get(f"/api/v1/waf/protected-feed?{param_name}={token}", headers=hdrs)
    assert r2.status_code == 200
    assert "application/json" in r2.headers.get("content-type", "")
    body = r2.json()
    assert body["waf_verified"] is True
    assert len(body["items"]) == 6

    # 4. 一次性原子消费：同 token 重放不能拿 JSON，重新退回挑战页
    r_replay = client.get(f"/api/v1/waf/protected-feed?{param_name}={token}", headers=hdrs)
    assert r_replay.status_code == 200
    assert "text/html" in r_replay.headers.get("content-type", "")


def test_browse_quota_and_mock_login(client: TestClient) -> None:
    """复刻 pxb7 queryBrowseLimit：匿名免费前 2 页，第 3 页拦截；模拟登录后解锁，退出后恢复拦截。"""
    ip = "116.228.121.2"
    hdrs = {**BROWSER_HEADERS, "X-Simulated-IP": ip}

    # 1. 第 1、2 页匿名放行
    for pg in (1, 2):
        r = client.get(
            f"/api/v1/products?page={pg}&size=6",
            headers={**hdrs, **make_signed_headers("GET", "/api/v1/products")},
        )
        assert r.status_code == 200
        assert r.json()["page"] == pg

    # 2. 第 3 页匿名拒绝（403 POW_REQUIRED / BROWSE_LIMIT_EXCEEDED）
    r3 = client.get(
        "/api/v1/products?page=3&size=6",
        headers={**hdrs, **make_signed_headers("GET", "/api/v1/products")},
    )
    assert r3.status_code == 403
    b3 = r3.json()
    assert b3["risk_reason"] == ReasonCode.POW_REQUIRED.value
    assert b3["detail_code"] == "BROWSE_LIMIT_EXCEEDED"

    # 3. 模拟登录获取 X-Lab-Auth 后访问第 3 页 → 200 放行
    r_login = client.post("/api/v1/browse/mock-login", json={"username": "alice_sec"})
    assert r_login.status_code == 200
    auth_token = r_login.json()["token"]

    r3_auth = client.get(
        "/api/v1/products?page=3&size=6",
        headers={**hdrs, **make_signed_headers("GET", "/api/v1/products"), "X-Lab-Auth": auth_token},
    )
    assert r3_auth.status_code == 200
    assert r3_auth.json()["browse_quota"]["logged_in"] is True
    assert r3_auth.json()["browse_quota"]["username"] == "alice_sec"

    # 4. 查询 limit 与注销恢复
    r_lim = client.get("/api/v1/browse/limit", headers={**hdrs, "X-Lab-Auth": auth_token})
    assert r_lim.status_code == 200
    assert r_lim.json()["logged_in"] is True

    r_out = client.post("/api/v1/browse/mock-logout", headers={**hdrs, "X-Lab-Auth": auth_token})
    assert r_out.status_code == 200 and r_out.json()["revoked"] is True

    r3_after_out = client.get(
        "/api/v1/products?page=3&size=6",
        headers={**hdrs, **make_signed_headers("GET", "/api/v1/products")},
    )
    assert r3_after_out.status_code == 403


def test_tiered_token_bucket_headers_and_server_time(client: TestClient) -> None:
    """复刻 pzds 网关分级令牌桶（public vs sensitive）与 /api/v1/time 服务端授时。"""
    # 1. /api/v1/time 授时端点免限流且返回毫秒与秒时间戳
    r_time = client.get("/api/v1/time")
    assert r_time.status_code == 200
    t_body = r_time.json()
    assert t_body["server_time_ms"] >= t_body["server_time_sec"] * 1000
    assert "sign_window_seconds" in t_body

    # 2. public 桶响应头验证
    ip_pub = "116.228.122.3"
    r_pub = client.get("/api/v1/font/session", headers={**BROWSER_HEADERS, "X-Simulated-IP": ip_pub})
    assert r_pub.status_code == 200
    assert r_pub.headers.get("X-RateLimit-Tier") == "public"
    assert r_pub.headers.get("X-RateLimit-Burst-Capacity") == "60"
    assert r_pub.headers.get("X-Request-Id", "").startswith("acl_")

    # 3. sensitive 桶突发上限为 8，第 9 次应提前触发 429（低于全局 10 QPS 滑动窗口）
    ip_sen = "116.228.122.4"
    for i in range(8):
        r = client.post("/api/v1/challenge/pow", headers={**BROWSER_HEADERS, "X-Simulated-IP": ip_sen})
        assert r.status_code == 200, f"sensitive 桶第 {i + 1} 次不应超限"
        assert r.headers.get("X-RateLimit-Tier") == "sensitive"
        assert r.headers.get("X-RateLimit-Burst-Capacity") == "8"

    r9 = client.post("/api/v1/challenge/pow", headers={**BROWSER_HEADERS, "X-Simulated-IP": ip_sen})
    assert r9.status_code == 429
    assert r9.json()["risk_reason"] == ReasonCode.RATE_LIMITED.value
    assert r9.headers.get("X-RateLimit-Remaining") == "0"


def _human_bot_audit_payload() -> Dict[str, Any]:
    """构造干净桌面 Chrome 人类用户的全维度探针载荷。"""
    pts = [
        {"x": 100 + i * 7 + (i % 4) * 9, "y": 200 + ((i * 13) % 45), "t": 1000 + i * (18 + (i % 5) * 9), "isTrusted": True}
        for i in range(34)
    ]
    return {
        "ua": BROWSER_HEADERS["User-Agent"],
        "platform": "Win32",
        "languages": ["zh-CN", "zh", "en"],
        "timezone": "Asia/Shanghai",
        "screen": {"width": 1920, "height": 1080, "availWidth": 1920, "availHeight": 1040, "colorDepth": 24, "devicePixelRatio": 1},
        "device_memory": 8,
        "hardware_concurrency": 12,
        "touch_points": 0,
        "canvas_hash": "clean_canvas_123",
        "audio_hash": "clean_audio_456",
        "webgl": {"vendor": "Google Inc. (Intel)", "renderer": "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11)", "masked": False},
        "fonts": {"detected": ["Arial", "Microsoft YaHei", "Consolas", "SimSun"], "count": 4},
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
            "canvas_hash_2": "clean_canvas_123",
            "timezone_offset": -480,
            "worker": {"supported": True, "ua": BROWSER_HEADERS["User-Agent"], "platform": "Win32", "hardware_concurrency": 12},
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
                "client_rects_hash": "rect_stable_aaa",
                "client_rects_hash_2": "rect_stable_aaa",
                "webgl_extensions_count": 32,
                "webgl_max_texture_size": 16384,
                "media_devices_count": 3,
                "speech_voices_count": 4,
            },
        },
        "behavior": {
            "points": pts,
            "keys": [
                {"key": "*", "downTs": 100, "upTs": 140, "isTrusted": True},
                {"key": "*", "downTs": 195, "upTs": 230, "isTrusted": True},
                {"key": "*", "downTs": 360, "upTs": 405, "isTrusted": True},
            ],
            "scrolls": [],
            "page_seconds": 5.2,
            "visit_path": ["/"],
        },
    }


def test_bot_detection_api_human_vs_bot_vs_spoof(client: TestClient) -> None:
    """验证 GET/POST /api/v1/bot/check 在真实人类、无头脚本、加噪伪装三类画像下的置信分与原因输出。"""
    # 1. GET 纯 HTTP 检测：模拟 curl + 机房 IP → likely_bot
    r_get_bot = client.get(
        "/api/v1/bot/check",
        headers={"User-Agent": "curl/8.5.0", "X-Simulated-IP": "52.95.125.1"},
    )
    assert r_get_bot.status_code == 200
    g_body = r_get_bot.json()
    assert g_body["verdict"] == "likely_bot"
    assert g_body["bot_confidence"] >= 55.0
    assert g_body["confidence_level"] == "low"
    assert len(g_body["reasons"]) >= 2

    # 2. POST 干净人类桌面浏览器 → likely_human (bot_confidence < 25)
    human_payload = _human_bot_audit_payload()
    r_human = client.post(
        "/api/v1/bot/check",
        headers={**BROWSER_HEADERS, "Sec-Fetch-Site": "same-origin", "X-Simulated-IP": "116.228.125.2"},
        json=human_payload,
    )
    assert r_human.status_code == 200
    h_body = r_human.json()
    assert h_body["verdict"] == "likely_human"
    assert h_body["bot_confidence"] < 25.0
    assert h_body["human_confidence"] > 75.0
    assert h_body["confidence_level"] == "high"
    assert h_body["telemetry_coverage"]["checked_items"] >= 25

    # 3. POST Sannysoft 无头机器人 → likely_bot (>=80)
    bot_payload = _human_bot_audit_payload()
    bot_payload["ua"] = "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/126.0.0.0 Safari/537.36"
    bot_payload["platform"] = "Linux x86_64"
    bot_payload["webgl"] = {"vendor": "Google", "renderer": "ANGLE (Google SwiftShader)", "masked": False}
    bot_payload["automation"]["webdriver"] = True
    bot_payload["automation"]["cdc_keys"] = ["$cdc_test"]
    bot_payload["automation"]["cdp_console_probe"] = True
    bot_payload["automation"]["iframe_mismatch"] = True
    bot_payload["extra_probes"]["sannysoft"]["permissions_inconsistent"] = True
    bot_payload["extra_probes"]["window_dims"]["outerWidth"] = 0

    r_bot = client.post(
        "/api/v1/bot/check",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": "52.95.125.3"},
        json=bot_payload,
    )
    assert r_bot.status_code == 200
    b_body = r_bot.json()
    assert b_body["verdict"] == "likely_bot"
    assert b_body["bot_confidence"] >= 80.0
    reason_ids = {r["id"] for r in b_body["reasons"]}
    assert "webdriver_flag" in reason_ids
    assert "driver_globals" in reason_ids
    assert "permissions_notification_mismatch" in reason_ids
    assert "webgl_software_renderer" in reason_ids

    # 4. POST BrowserLeaks + BrowserScan 加噪与跨维伪装 → 识别 Canvas 噪点 / ClientRects 噪点 / Worker / 时区偏移
    spoof_payload = _human_bot_audit_payload()
    spoof_payload["extra_probes"]["canvas_hash_2"] = "mutated_noise_hash"
    spoof_payload["extra_probes"]["browserleaks"]["client_rects_hash_2"] = "mutated_rect_hash"
    spoof_payload["extra_probes"]["timezone_offset"] = 0
    spoof_payload["extra_probes"]["worker"]["platform"] = "MacIntel"

    r_spoof = client.post(
        "/api/v1/bot/check",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": "52.95.125.4"},
        json=spoof_payload,
    )
    assert r_spoof.status_code == 200
    s_body = r_spoof.json()
    assert s_body["verdict"] == "likely_bot"
    s_ids = {r["id"] for r in s_body["reasons"]}
    assert "canvas_noise_poisoning" in s_ids
    assert "client_rects_subpixel_noise" in s_ids
    assert "worker_cross_thread" in s_ids
    assert "timezone_name_vs_offset" in s_ids
    assert "ip_geo_vs_timezone" in s_ids


def test_bot_detection_non_secure_http_no_false_positive_and_no_double_count(client: TestClient) -> None:
    """回归验证：1) 公网明文 HTTP 真实浏览器缺失 Sec-CH-UA/Sec-Fetch-Site 不误扣分；2) 安全上下文缺失 Sec-CH-UA 不重复扣两次分。"""
    payload = _human_bot_audit_payload()

    # 1. 公网明文 HTTP (Non-Secure Context)
    r_http = client.post(
        "/api/v1/bot/check",
        headers={
            "User-Agent": BROWSER_HEADERS["User-Agent"],
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Host": "119.29.10.20:8090",
            "Origin": "http://119.29.10.20:8090",
            "X-Forwarded-Proto": "http",
            "X-Simulated-IP": "116.228.125.9",
        },
        json=payload,
    )
    assert r_http.status_code == 200
    h_body = r_http.json()
    assert h_body["bot_confidence"] == 0.0
    assert h_body["human_confidence"] == 100.0
    assert h_body["verdict"] == "likely_human"

    # 2. HTTPS 安全上下文缺失 Sec-CH-UA：仅 Network 层扣 +20，BrowserScan 层不再重复扣 +20
    r_https = client.post(
        "/api/v1/bot/check",
        headers={
            "User-Agent": BROWSER_HEADERS["User-Agent"],
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Sec-Fetch-Site": "same-origin",
            "Host": "lab.example.com",
            "Origin": "https://lab.example.com",
            "X-Forwarded-Proto": "https",
            "X-Simulated-IP": "116.228.125.10",
        },
        json=payload,
    )
    assert r_https.status_code == 200
    s_body = r_https.json()
    assert s_body["bot_confidence"] == 20.0
    assert s_body["category_scores"]["network"] == 20.0
    assert s_body["category_scores"]["browserscan"] == 0.0


def test_ip_intel_rdns_and_vpn_penetration_channels(client: TestClient) -> None:
    """验证 IP 与地域穿透引擎：干净住宅 IP、WebRTC STUN 穿透、分流代理暴露、rDNS 云厂商识别与 /bot/check 联动。"""
    from app.services.ip_intel import analyze_rdns

    # 1. rDNS 云厂商/VPS 识别
    assert analyze_rdns("ec2-18-179-47-153.ap-northeast-1.compute.amazonaws.com") == "Amazon AWS EC2"
    assert analyze_rdns("host-116-228-10-5.static.chinanet.cn") is None

    # 2. GET /api/v1/ip/whoami 干净国内住宅 IP
    r_who = client.get(
        "/api/v1/ip/whoami",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": "116.228.10.5"},
    )
    assert r_who.status_code == 200
    w_body = r_who.json()
    assert w_body["effective_ip"] == "116.228.10.5"
    assert w_body["profile"]["country"] == "CN"
    assert w_body["profile"]["is_hosting"] is False

    # 3. POST /api/v1/ip/audit 干净住宅基线 → 无穿透，伪装度 100
    r_clean = client.post(
        "/api/v1/ip/audit",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": "116.228.10.5"},
        json={
            "browser_timezone": "Asia/Shanghai",
            "browser_tz_offset": -480,
            "browser_languages": ["zh-CN", "zh"],
            "webrtc_public_ips": ["116.228.10.5"],
            "domestic_echo_ip": "116.228.10.5",
        },
    )
    assert r_clean.status_code == 200
    c_body = r_clean.json()
    assert c_body["vpn_pierced"] is False
    assert c_body["risk_score"] == 0.0
    assert c_body["concealment_score"] == 100.0

    # 4. POST /api/v1/ip/audit WebRTC UDP STUN 穿透 + 机房 IP + 时区倒挂 + Via 代理头泄露
    r_stun = client.post(
        "/api/v1/ip/audit",
        headers={
            **BROWSER_HEADERS,
            "X-Simulated-IP": "52.95.10.20",
            "Via": "1.1 squid-proxy.internal",
        },
        json={
            "browser_timezone": "Asia/Shanghai",
            "browser_tz_offset": -480,
            "browser_languages": ["zh-CN", "zh"],
            "webrtc_public_ips": ["116.228.10.5"],
            "webrtc_local_candidates": ["192.168.1.108"],
        },
    )
    assert r_stun.status_code == 200
    st_body = r_stun.json()
    assert st_body["vpn_pierced"] is True
    assert st_body["suspected_real_ip"] == "116.228.10.5"
    assert st_body["suspected_proxy_ip"] == "52.95.10.20"
    assert st_body["risk_score"] >= 80.0
    st_ids = {f["id"] for f in st_body["findings"]}
    assert "WEBRTC_STUN_REAL_IP_LEAK" in st_ids
    assert "IP_HOSTING_OR_PROXY" in st_ids
    assert "IP_TZ_VS_BROWSER_TZ" in st_ids
    assert "PROXY_HEADER_LEAK" in st_ids

    # 5. POST /api/v1/ip/audit 分流模式（国内直连 + 海外走机房代理）
    r_split = client.post(
        "/api/v1/ip/audit",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": "116.228.10.5"},
        json={
            "browser_timezone": "Asia/Shanghai",
            "browser_languages": ["zh-CN"],
            "domestic_echo_ip": "116.228.10.5",
            "overseas_echo_ip": "52.95.10.20",
        },
    )
    assert r_split.status_code == 200
    sp_body = r_split.json()
    assert sp_body["vpn_pierced"] is True
    assert sp_body["suspected_real_ip"] == "116.228.10.5"
    assert sp_body["suspected_proxy_ip"] == "52.95.10.20"
    sp_ids = {f["id"] for f in sp_body["findings"]}
    assert "SPLIT_TUNNEL_VPN_DETECTED" in sp_ids

    # 6. /api/v1/bot/check 联动 WebRTC STUN 泄露扣分
    bot_payload = _human_bot_audit_payload()
    bot_payload["extra_probes"]["webrtc"] = {
        "supported": True,
        "publicIps": ["116.228.10.5"],
        "localCandidates": ["192.168.1.108"],
    }
    r_bot_leak = client.post(
        "/api/v1/bot/check",
        headers={**BROWSER_HEADERS, "Sec-Fetch-Site": "same-origin", "X-Simulated-IP": "52.95.10.20"},
        json=bot_payload,
    )
    assert r_bot_leak.status_code == 200
    bl_body = r_bot_leak.json()
    bl_ids = {r["id"] for r in bl_body["reasons"]}
    assert "webrtc_ice_leak" in bl_ids
    assert bl_body["bot_confidence"] >= 55.0


def test_domestic_cn_cloud_datacenter_ip_detection(client: TestClient) -> None:
    """验证国内主流云厂商与 IDC 机房四维识别（CIDR / ASN / ISP 关键词 / rDNS），且不误杀普通运营商家宽。"""
    from app.services.cn_cloud_ranges import match_cn_cloud_by_cidr, match_cn_cloud_by_metadata
    from app.services.ip_intel import analyze_rdns

    # 1. CIDR 精准识别国内主流云厂商
    samples = [
        ("47.96.10.20", "aliyun"),      # 阿里云
        ("119.29.10.20", "tencent"),   # 腾讯云
        ("114.115.10.20", "huawei"),    # 华为云
        ("180.184.10.20", "volcengine"),# 火山引擎
        ("180.76.10.20", "baidu"),      # 百度智能云
        ("114.67.10.20", "jdcloud"),    # 京东云
        ("106.75.10.20", "ucloud"),     # UCloud 优刻得
        ("120.92.10.20", "ksyun"),      # 金山云
        ("139.198.10.20", "qingcloud"), # 青云
        ("59.111.10.20", "netease"),    # 网易云
    ]
    for ip_addr, expected_code in samples:
        hit = match_cn_cloud_by_cidr(ip_addr)
        assert hit is not None, f"{ip_addr} 应命中 {expected_code}"
        assert hit.vendor_code == expected_code

    # 2. 不误杀普通运营商家宽 IP（成都联通 / 上海电信）
    assert match_cn_cloud_by_cidr("112.10.20.30") is None
    assert match_cn_cloud_by_cidr("116.228.10.5") is None

    # 3. ASN 与中英文 Org 关键词识别（含天翼云/移动云/联通云，且不误杀普通 AS4837 联通家宽）
    assert match_cn_cloud_by_metadata(asn="AS45090 Shenzhen Tencent") is not None
    assert match_cn_cloud_by_metadata(asn="AS137718 ByteDance") is not None
    assert match_cn_cloud_by_metadata(isp="China Telecom Cloud (CTYun)", asn="AS4134") is not None
    assert match_cn_cloud_by_metadata(isp="中国移动云 ECloud", asn="AS9808") is not None
    assert match_cn_cloud_by_metadata(isp="CHINA UNICOM China169 Backbone", asn="AS4837") is None

    # 4. 国内云 rDNS 识别
    assert analyze_rdns("ecs-114-115-10-20.compute.hwclouds-dns.com") is not None
    assert analyze_rdns("node1.volcengine.com") is not None

    # 5. API 端到端联动：腾讯云 IP 在 /api/v1/ip/audit 与 /api/v1/bot/check 中均被标记为机房 IP
    r_audit = client.post(
        "/api/v1/ip/audit",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": "119.29.10.20"},
        json={"browser_timezone": "Asia/Shanghai", "browser_languages": ["zh-CN"]},
    )
    assert r_audit.status_code == 200
    a_body = r_audit.json()
    assert a_body["primary_profile"]["is_hosting"] is True
    assert "腾讯云" in (a_body["primary_profile"].get("cloud_provider") or "")
    assert any(f["id"] == "IP_HOSTING_OR_PROXY" for f in a_body["findings"])

    r_bot = client.get(
        "/api/v1/bot/check",
        headers={**BROWSER_HEADERS, "Sec-Fetch-Site": "same-origin", "X-Simulated-IP": "180.184.10.20"},
    )
    assert r_bot.status_code == 200
    b_body = r_bot.json()
    assert b_body["ip_geo"]["is_datacenter"] is True
    assert any(r["id"] == "ip_reputation" for r in b_body["reasons"])

    # 6. GET /api/v1/ip/cn-clouds 目录接口
    r_list = client.get("/api/v1/ip/cn-clouds")
    assert r_list.status_code == 200
    assert r_list.json()["total_vendors"] >= 15
