"""
AntiCrawl Lab 全维度自动化检测回归矩阵（test_detection_regression_matrix.py）。

覆盖 5 大检测维度与校准门禁：
1. 8 类真实人类多终端基线（Windows/macOS/Linux/iOS/Android × Chrome/Edge/Safari/Firefox）→ 零误报（FPR = 0%）。
2. 12 类对抗/自动化/伪装/穿透样本（Network / Sannysoft / BrowserScan / BrowserLeaks / Behavior / IP-VPN）→ 100% 检出（TPR = 100%）。
3. 10 家国内主流云厂商机房 IP（阿里云/腾讯云/华为云/火山引擎/百度云/京东云/UCloud/金山云/青云/网易云）精准识别。
4. IP 地域透视与 VPN/分流穿透场景（干净住宅 / WebRTC STUN 穿透 / Clash 规则分流）。
5. Level 4 商业防线全回归（200 HTML/JS `timestamp__1366` 挑战、HMAC 签名 + Nonce 重放、匿名浏览深度配额、访问顺序图、动态 PUA 字体）。
6. 总体校准门禁（FPR == 0.0 与 TPR == 1.0）。
"""

from __future__ import annotations

import hashlib
import json
import re

import pytest
from fastapi.testclient import TestClient

from app.constants import ReasonCode
from tests.conftest import BROWSER_HEADERS, make_signed_headers
from tests.regression_scenarios import (
    CN_CLOUD_REGRESSION_SAMPLES,
    AdversarialCase,
    BenignPersona,
    build_adversarial_bot_cases,
    build_benign_personas,
    make_human_behavior,
)

BENIGN_PERSONAS = build_benign_personas()
ADVERSARIAL_CASES = build_adversarial_bot_cases()


def _solve_waf_html_token(html: str) -> tuple[str, str]:
    """解析并计算边缘 WAF 200 HTML 挑战页中的 timestamp__1366 动态令牌。"""
    arg_m = re.search(r"\}\)\((\d+),(\[[^\]]+\]),(\[[^\]]+\]),(\[[^\]]+\])\)", html)
    ts_m = re.search(r"ts='(\d+)'", html)
    assert arg_m is not None and ts_m is not None, "未能从 WAF 挑战页提取动态参数"

    xor_key = int(arg_m.group(1))
    dec = lambda raw: "".join(chr(c ^ xor_key) for c in json.loads(raw))
    nid = dec(arg_m.group(2))
    salt = dec(arg_m.group(3))
    param_name = dec(arg_m.group(4))
    ts = ts_m.group(1)

    digest = hashlib.sha256(f"{nid}:{salt}:{ts}:dom1".encode("utf-8")).hexdigest()[:24]
    return param_name, f"{nid}-{ts}-{digest}-dom1"


@pytest.mark.parametrize("persona", BENIGN_PERSONAS, ids=[p.id for p in BENIGN_PERSONAS])
def test_benign_human_zero_false_positive_matrix(client: TestClient, persona: BenignPersona) -> None:
    """维度回归 1：8 类真实人类多终端画像在 /api/v1/bot/check 中必须保持零误报（bot_confidence=0.0）。"""
    resp = client.post("/api/v1/bot/check", headers=persona.headers, json=persona.payload)
    assert resp.status_code == 200, f"[{persona.id}] 状态码异常: {resp.status_code}"
    body = resp.json()
    assert body["verdict"] == "likely_human", f"[{persona.id}] 误判为 {body['verdict']}: {body['reasons']}"
    assert body["bot_confidence"] == persona.expected_bot_confidence, (
        f"[{persona.id}] 出现非预期扣分 {body['bot_confidence']}: {body['reasons']}"
    )
    assert body["human_confidence"] == 100.0
    assert body["reasons"] == []


@pytest.mark.parametrize("case", ADVERSARIAL_CASES, ids=[c.id for c in ADVERSARIAL_CASES])
def test_adversarial_bot_detection_matrix(client: TestClient, case: AdversarialCase) -> None:
    """维度回归 2：12 类自动化/伪装/穿透样本必须在对应检测维度精准触发归因与高置信分。"""
    if case.method == "GET":
        resp = client.get(case.path, headers=case.headers)
    else:
        resp = client.post(case.path, headers=case.headers, json=case.payload)

    assert resp.status_code == 200, f"[{case.id}] 状态码异常: {resp.status_code}"
    body = resp.json()
    assert body["verdict"] in case.expected_verdicts, (
        f"[{case.id}] verdict={body['verdict']} 不在预期 {case.expected_verdicts} 内"
    )
    assert body["bot_confidence"] >= case.min_bot_confidence, (
        f"[{case.id}] bot_confidence={body['bot_confidence']} < {case.min_bot_confidence}"
    )
    hit_ids = {r["id"] for r in body["reasons"]}
    missing = set(case.required_reason_ids) - hit_ids
    assert not missing, f"[{case.id}] 漏检预期原因码 {missing}，实际命中={hit_ids}"


@pytest.mark.parametrize(
    ("ip_addr", "vendor_code", "vendor_keyword"),
    CN_CLOUD_REGRESSION_SAMPLES,
    ids=[f"{code}_{ip}" for ip, code, _ in CN_CLOUD_REGRESSION_SAMPLES],
)
def test_cn_cloud_datacenter_regression_matrix(
    client: TestClient,
    ip_addr: str,
    vendor_code: str,
    vendor_keyword: str,
) -> None:
    """维度回归 3：10 家国内主流云厂商机房网段必须在 /ip/audit 与 /bot/check 中稳定检出。"""
    r_audit = client.post(
        "/api/v1/ip/audit",
        headers={**BROWSER_HEADERS, "Sec-Fetch-Site": "same-origin", "X-Simulated-IP": ip_addr},
        json={"browser_timezone": "Asia/Shanghai", "browser_languages": ["zh-CN"]},
    )
    assert r_audit.status_code == 200, f"[{vendor_code}] /ip/audit 失败"
    audit_body = r_audit.json()
    profile = audit_body["primary_profile"]
    assert profile["is_hosting"] is True, f"[{vendor_code}] {ip_addr} 未标记 is_hosting=True"
    assert vendor_keyword in (profile.get("cloud_provider") or ""), (
        f"[{vendor_code}] cloud_provider={profile.get('cloud_provider')} 不包含 {vendor_keyword}"
    )
    assert any(f["id"] == "IP_HOSTING_OR_PROXY" for f in audit_body["findings"])

    r_bot = client.get(
        "/api/v1/bot/check",
        headers={**BROWSER_HEADERS, "Sec-Fetch-Site": "same-origin", "X-Simulated-IP": ip_addr},
    )
    assert r_bot.status_code == 200
    bot_body = r_bot.json()
    assert bot_body["ip_geo"]["is_datacenter"] is True
    assert any(r["id"] == "ip_reputation" for r in bot_body["reasons"])


def test_ip_vpn_penetration_regression_scenarios(client: TestClient) -> None:
    """维度回归 4：验证 /api/v1/ip/audit 在干净住宅、WebRTC STUN 穿透、Clash 规则分流三场景的表现。"""
    # 1. 干净住宅出口基线 → 无泄露
    r_clean = client.post(
        "/api/v1/ip/audit",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": "116.228.204.1"},
        json={
            "browser_timezone": "Asia/Shanghai",
            "browser_tz_offset": -480,
            "browser_languages": ["zh-CN", "zh"],
            "webrtc_public_ips": ["116.228.204.1"],
            "domestic_echo_ip": "116.228.204.1",
        },
    )
    assert r_clean.status_code == 200
    clean_body = r_clean.json()
    assert clean_body["vpn_pierced"] is False
    assert clean_body["risk_score"] == 0
    assert clean_body["concealment_score"] == 100

    # 2. WebRTC STUN 穿透 AWS 出口捕获真实国内 IP
    r_stun = client.post(
        "/api/v1/ip/audit",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": "52.95.204.2", "Via": "1.1 lab-proxy"},
        json={
            "browser_timezone": "Asia/Shanghai",
            "browser_tz_offset": -480,
            "browser_languages": ["zh-CN"],
            "webrtc_public_ips": ["116.228.10.5"],
        },
    )
    assert r_stun.status_code == 200
    stun_body = r_stun.json()
    assert stun_body["vpn_pierced"] is True
    assert stun_body["suspected_real_ip"] == "116.228.10.5"
    assert stun_body["suspected_proxy_ip"] == "52.95.204.2"
    assert any(f["id"] == "WEBRTC_STUN_REAL_IP_LEAK" for f in stun_body["findings"])

    # 3. Clash / Mihomo 规则分流多出口不一致
    r_split = client.post(
        "/api/v1/ip/audit",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": "116.228.204.3"},
        json={
            "browser_timezone": "Asia/Shanghai",
            "browser_languages": ["zh-CN"],
            "domestic_echo_ip": "116.228.204.3",
            "overseas_echo_ip": "52.95.10.20",
        },
    )
    assert r_split.status_code == 200
    split_body = r_split.json()
    assert split_body["vpn_pierced"] is True
    assert any(f["id"] == "SPLIT_TUNNEL_VPN_DETECTED" for f in split_body["findings"])


def test_business_and_waf_defense_regression(client: TestClient) -> None:
    """维度回归 5：验证 WAF 动态 JS 挑战、HMAC 签名 + Nonce 防重放、浏览配额、访问顺序图与动态 PUA 字体。"""
    # 1. WAF 200 HTML/JS 挑战（无令牌 → 挑战页；求解 → JSON；重放 → 退回挑战页）
    waf_ip = "116.228.205.1"
    waf_hdrs = {**BROWSER_HEADERS, "X-Simulated-IP": waf_ip}
    r_waf_1 = client.get("/api/v1/waf/protected-feed", headers=waf_hdrs)
    assert r_waf_1.status_code == 200
    assert "text/html" in r_waf_1.headers.get("content-type", "")
    assert r_waf_1.headers.get("X-WAF-Challenge") == "js-dynamic-token"

    param_name, token = _solve_waf_html_token(r_waf_1.text)
    r_waf_2 = client.get(f"/api/v1/waf/protected-feed?{param_name}={token}", headers=waf_hdrs)
    assert r_waf_2.status_code == 200
    assert r_waf_2.json()["waf_verified"] is True

    r_waf_replay = client.get(f"/api/v1/waf/protected-feed?{param_name}={token}", headers=waf_hdrs)
    assert r_waf_replay.status_code == 200
    assert "text/html" in r_waf_replay.headers.get("content-type", "")

    # 2. HMAC 签名、Nonce 重放与匿名深翻页配额
    prod_ip = "116.228.205.2"
    prod_hdrs = {**BROWSER_HEADERS, "X-Simulated-IP": prod_ip}
    r_unsig = client.get("/api/v1/products", headers=prod_hdrs)
    assert r_unsig.status_code == 401
    assert r_unsig.json()["risk_reason"] == ReasonCode.SIGNATURE_MISSING.value

    signed_hdrs = make_signed_headers("GET", "/api/v1/products")
    r_p1 = client.get("/api/v1/products?page=1&size=6", headers={**prod_hdrs, **signed_hdrs})
    assert r_p1.status_code == 200
    assert r_p1.json()["page"] == 1

    r_nonce = client.get("/api/v1/products?page=1&size=6", headers={**prod_hdrs, **signed_hdrs})
    assert r_nonce.status_code == 401
    assert r_nonce.json()["risk_reason"] == ReasonCode.NONCE_REUSED.value

    r_p3 = client.get(
        "/api/v1/products?page=3&size=6",
        headers={**prod_hdrs, **make_signed_headers("GET", "/api/v1/products")},
    )
    assert r_p3.status_code == 403
    assert r_p3.json()["detail_code"] == "BROWSE_LIMIT_EXCEEDED"

    # 3. 访问顺序图：直接请求 /products/1/price 未经 '/' 和 '/api/v1/products' → 拦截并记录 VISIT_ORDER_VIOLATION
    direct_ip = "116.228.205.3"
    r_direct_price = client.get(
        "/api/v1/products/1/price",
        headers={
            "User-Agent": BROWSER_HEADERS["User-Agent"],
            "Sec-CH-UA": BROWSER_HEADERS["Sec-CH-UA"],
            "X-Simulated-IP": direct_ip,
            **make_signed_headers("GET", "/api/v1/products/1/price"),
        },
    )
    assert r_direct_price.status_code == 403
    assert ReasonCode.VISIT_ORDER_VIOLATION.value in (r_direct_price.json().get("reasons") or [])

    # 正常先经首页 + 列表 + 行为上报后访问单品价格 → 放行并输出 PUA 编码价格
    flow_ip = "116.228.205.4"
    flow_hdrs = {**BROWSER_HEADERS, "X-Simulated-IP": flow_ip, "X-Session-Id": "sess-reg-flow"}
    client.post("/api/v1/behavior/trace", headers=flow_hdrs, json=make_human_behavior())
    client.get(
        "/api/v1/products?page=1&size=6",
        headers={**flow_hdrs, "X-Visit-Origin": "/", **make_signed_headers("GET", "/api/v1/products")},
    )
    r_flow_price = client.get(
        "/api/v1/products/1/price",
        headers={**flow_hdrs, **make_signed_headers("GET", "/api/v1/products/1/price")},
    )
    assert r_flow_price.status_code == 200
    assert any(0xE000 <= ord(ch) <= 0xE00A for ch in r_flow_price.json()["price_pua"])

    # 4. 动态字体 SSR 页包含私用区 PUA 乱码（不含明文价格）
    for ssr_path in ("/price", "/ssr/price"):
        r_ssr = client.get(ssr_path, headers=BROWSER_HEADERS)
        assert r_ssr.status_code == 200
        assert any(0xE000 <= ord(ch) <= 0xE00A for ch in r_ssr.text)


def test_calibration_fpr_and_tpr_thresholds(client: TestClient) -> None:
    """校准门禁验证：对全量良性与对抗画像统计误报率（FPR=0%）与检出率（TPR=100%）。"""
    benign = build_benign_personas(octet=211, run_tag="cal")
    adversarial = build_adversarial_bot_cases(octet=212, run_tag="cal")

    false_positives = 0
    for p in benign:
        r = client.post("/api/v1/bot/check", headers=p.headers, json=p.payload)
        assert r.status_code == 200
        if r.json()["verdict"] != "likely_human":
            false_positives += 1

    true_positives = 0
    for c in adversarial:
        r = client.get(c.path, headers=c.headers) if c.method == "GET" else client.post(c.path, headers=c.headers, json=c.payload)
        assert r.status_code == 200
        body = r.json()
        hit_ids = {item["id"] for item in body["reasons"]}
        if (
            body["verdict"] in c.expected_verdicts
            and body["bot_confidence"] >= c.min_bot_confidence
            and set(c.required_reason_ids) <= hit_ids
        ):
            true_positives += 1

    fpr = false_positives / len(benign)
    tpr = true_positives / len(adversarial)
    assert fpr == 0.0, f"误报率 FPR={fpr:.2%} > 0%"
    assert tpr == 1.0, f"检出率 TPR={tpr:.2%} < 100%"
