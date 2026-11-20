"""模块一（网络与协议层）单元测试与边界值验证。"""

from __future__ import annotations

import time
from typing import Dict

import pytest
from fastapi.testclient import TestClient

from app.constants import ReasonCode
from app.services.headercheck import check_headers
from app.services.ratelimit import analyze_request_cadence, check_fp_rate_limit, check_ip_rate_limit
from tests.conftest import BROWSER_HEADERS


def test_rate_limit_boundary_10_pass_11_block(client: TestClient) -> None:
    """边界值：RATE_LIMIT_QPS=10 时，第 10 次放行，第 11 次触发 429 RATE_LIMITED。"""
    ip = "116.228.12.34"
    for idx in range(10):
        res = check_ip_rate_limit(ip, 10)
        assert not res.exceeded, f"第 {idx + 1} 次不应超限"
    res11 = check_ip_rate_limit(ip, 10)
    assert res11.exceeded is True
    assert res11.count == 11
    assert res11.retry_after == 1


def test_fp_rate_limit_dimension(client: TestClient) -> None:
    """指纹维度限流边界验证。"""
    fp = "fp_test_limit"
    for _ in range(3):
        assert not check_fp_rate_limit(fp, 3).exceeded
    assert check_fp_rate_limit(fp, 3).exceeded is True


def test_cadence_robotic_detection(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """增强实验：等间隔 sleep 请求应被识别为机械定频节律（CV < 0.08）。"""
    fake_now = [1000.0]
    monkeypatch.setattr(time, "time", lambda: fake_now[0])

    ip = "116.228.50.50"
    for i in range(6):
        fake_now[0] = 1000.0 + i * 0.250  # 严格 250ms 间隔
        res = analyze_request_cadence(ip)

    assert res.robotic is True
    assert res.cv is not None and res.cv < 0.08
    assert res.score == 15


def test_header_rules_and_conditional_sec_ch_ua() -> None:
    """Header 规则：空 UA、工具特征、Chromium 条件缺失、非 Chromium 不误判、JA4 冲突。"""
    # 1. 空 UA + 缺 Accept-Language
    r_empty = check_headers({})
    assert r_empty.score == 55
    assert ReasonCode.HEADER_MISSING.value in r_empty.reasons

    # 2. python-requests 工具特征 + 缺 Accept-Language
    r_bot = check_headers({"User-Agent": "python-requests/2.31.0"})
    assert ReasonCode.HEADER_INCONSISTENT.value in r_bot.reasons
    assert r_bot.score >= 50

    # 3. 条件规则：Firefox 缺 Sec-CH-UA 不得扣分
    r_ff = check_headers({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Accept-Language": "zh-CN,zh;q=0.9",
    })
    assert r_ff.score == 0
    assert r_ff.reasons == []

    # 4. Chromium UA 缺 Sec-CH-UA +20
    r_chr_no_ch = check_headers({
        "User-Agent": BROWSER_HEADERS["User-Agent"],
        "Accept-Language": "zh-CN,zh;q=0.9",
    })
    assert r_chr_no_ch.score == 20
    assert ReasonCode.HEADER_MISSING.value in r_chr_no_ch.reasons

    # 5. Edge UA 配非 Edge Sec-CH-UA -> 品牌矛盾 +25
    r_edge_bad = check_headers({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
        "Sec-CH-UA": '"Google Chrome";v="126"',
        "Accept-Language": "zh-CN",
    })
    assert r_edge_bad.score == 25
    assert ReasonCode.HEADER_INCONSISTENT.value in r_edge_bad.reasons

    # 6. 增强 JA4 指纹异常
    r_ja4 = check_headers({
        **BROWSER_HEADERS,
        "X-JA4": "t13d1516h2_8daaf6152771_b0da82dd1658",
    })
    assert r_ja4.score == 20
    assert ReasonCode.HEADER_INCONSISTENT.value in r_ja4.reasons


def test_lab_mode_0_ignores_simulated_ip_and_disables_admin(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """安全边界：LAB_MODE=0 时忽略 X-Simulated-IP 且关闭管理端点（返回 403）。"""
    monkeypatch.setenv("LAB_MODE", "0")

    resp_admin = client.get("/api/v1/admin/requests")
    assert resp_admin.status_code == 403

    # 即使传入机房模拟 IP，LAB_MODE=0 下也必须忽略，不记录机房 IP 风险
    resp_fp = client.post(
        "/api/v1/fingerprint/report",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": "52.95.10.20"},
        json={
            "ua": BROWSER_HEADERS["User-Agent"],
            "platform": "Win32",
            "languages": ["zh-CN"],
            "timezone": "Asia/Shanghai",
            "canvas_hash": "c1",
            "audio_hash": "a1",
        },
    )
    assert resp_fp.status_code == 200
    assert ReasonCode.DATACENTER_IP.value not in resp_fp.json()["warnings"]


def test_hidden_form_honeypot_trap(client: TestClient) -> None:
    """隐藏表单域蜜罐：空提交放行，非空即封禁。"""
    ip = "116.228.44.44"
    ok_resp = client.post(
        "/api/v1/trap/form",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": ip},
        json={"honeypot_field": "", "email_trap": ""},
    )
    assert ok_resp.status_code == 200

    trap_resp = client.post(
        "/api/v1/trap/form",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": ip},
        json={"honeypot_field": "bot@spam.test", "email_trap": ""},
    )
    assert trap_resp.status_code == 403
    assert trap_resp.json()["risk_reason"] == ReasonCode.HONEYPOT_TRIGGERED.value
