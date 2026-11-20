"""模块四（签名、动态字体、PoW、诱饵、数据留存清理）单测。"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.constants import ReasonCode
from app.db import get_session_factory
from app.models.tables import RiskLog
from app.services.fonts import encode_price_pua, load_variants, select_variant_for_session
from app.services.retention import cleanup_expired_records
from tests.conftest import BROWSER_HEADERS, make_signed_headers


def test_signature_missing_expired_invalid_and_replay(client: TestClient) -> None:
    """验证 401 SIGNATURE_MISSING / SIGNATURE_EXPIRED / SIGNATURE_INVALID / NONCE_REUSED。"""
    ip = "116.228.20.1"
    # 1. 缺失
    r_miss = client.get("/api/v1/products", headers={**BROWSER_HEADERS, "X-Simulated-IP": ip})
    assert r_miss.status_code == 401
    assert r_miss.json()["risk_reason"] == ReasonCode.SIGNATURE_MISSING.value

    # 2. 过期（超出 ±120s）
    expired_hdrs = make_signed_headers("GET", "/api/v1/products", ts=int(time.time()) - 300)
    r_exp = client.get(
        "/api/v1/products",
        headers={**BROWSER_HEADERS, **expired_hdrs, "X-Simulated-IP": ip},
    )
    assert r_exp.status_code == 401
    assert r_exp.json()["risk_reason"] == ReasonCode.SIGNATURE_EXPIRED.value

    # 3. 签名篡改
    bad_hdrs = make_signed_headers("GET", "/api/v1/products", secret="wrong-secret")
    r_bad = client.get(
        "/api/v1/products",
        headers={**BROWSER_HEADERS, **bad_hdrs, "X-Simulated-IP": ip},
    )
    assert r_bad.status_code == 401
    assert r_bad.json()["risk_reason"] == ReasonCode.SIGNATURE_INVALID.value

    # 4. 合法签名首放行，原样重放拦截
    good_hdrs = make_signed_headers("GET", "/api/v1/products")
    r_ok = client.get(
        "/api/v1/products",
        headers={**BROWSER_HEADERS, **good_hdrs, "X-Simulated-IP": ip},
    )
    assert r_ok.status_code == 200

    r_replay = client.get(
        "/api/v1/products",
        headers={**BROWSER_HEADERS, **good_hdrs, "X-Simulated-IP": ip},
    )
    assert r_replay.status_code == 401
    assert r_replay.json()["risk_reason"] == ReasonCode.NONCE_REUSED.value


def test_dynamic_fonts_variants_and_pua_encoding(client: TestClient) -> None:
    """验证 8 个动态字体变体加载、会话绑定与 PUA 乱码编码。"""
    variants = load_variants()
    assert len(variants) == 8

    v = select_variant_for_session("session_alpha")
    encoded = encode_price_pua("¥3999", v)
    assert len(encoded) == 5
    # 编码后绝不包含明文阿拉伯数字或 ¥
    assert all(0xE000 <= ord(ch) <= 0xE00A for ch in encoded)

    r_font = client.get("/api/v1/font/session?sid=session_alpha", headers=BROWSER_HEADERS)
    assert r_font.status_code == 200
    assert r_font.headers.get("X-Font-Seed") == v.seed
    assert len(r_font.content) > 200


def test_decoy_and_pow_challenge_flow(client: TestClient) -> None:
    """验证灰区（40-69）返回诱饵列表并在单品价格接口触发 PoW 挑战，求解后解锁。"""
    ip = "52.95.20.20"  # 机房 IP (+25)
    # 先用缺少 Accept-Language (+15) 使其单次总分=40（进入 40-69 灰区）
    gray_headers = {
        "User-Agent": BROWSER_HEADERS["User-Agent"],
        "Sec-CH-UA": BROWSER_HEADERS["Sec-CH-UA"],
        "X-Simulated-IP": ip,
        "X-Session-Id": "sess-pow-demo",
    }
    client.get("/", headers=gray_headers)

    # 1. 商品列表应返回诱饵数据
    sig_list = make_signed_headers("GET", "/api/v1/products")
    r_list = client.get("/api/v1/products", headers={**gray_headers, **sig_list})
    assert r_list.status_code == 200
    body_list = r_list.json()
    assert "decoy_hint" in body_list
    assert body_list["items"][0]["decoy"] is True

    # 2. 单品价格接口应返回 403 POW_REQUIRED 并签发挑战
    sig_price1 = make_signed_headers("GET", "/api/v1/products/1/price")
    r_price_chal = client.get("/api/v1/products/1/price", headers={**gray_headers, **sig_price1})
    assert r_price_chal.status_code == 403
    chal_body = r_price_chal.json()
    assert chal_body["risk_reason"] == ReasonCode.POW_REQUIRED.value
    chal = chal_body["challenge"]

    # 3. 求解 SHA-256 前导零（测试配置 difficulty=2）
    nonce = 0
    prefix = "0" * chal["difficulty"]
    while not hashlib.sha256(f"{chal['data']}:{nonce}".encode()).hexdigest().startswith(prefix):
        nonce += 1

    r_verify = client.post(
        "/api/v1/challenge/pow",
        headers=gray_headers,
        json={"data": chal["data"], "answer": str(nonce)},
    )
    assert r_verify.status_code == 200
    pow_token = r_verify.json()["token"]

    # 4. 携带 X-PoW-Token 重放，成功放行
    sig_price2 = make_signed_headers("GET", "/api/v1/products/1/price")
    r_price_ok = client.get(
        "/api/v1/products/1/price",
        headers={**gray_headers, **sig_price2, "X-PoW-Token": pow_token},
    )
    assert r_price_ok.status_code == 200
    assert r_price_ok.json()["pow_verified"] is True


def test_data_retention_cleanup(client: TestClient) -> None:
    """验证超过 DATA_RETENTION_DAYS 的旧日志会被滚动清理。"""
    tz_sh = timezone(timedelta(hours=8))
    old_ts = (datetime.now(tz_sh) - timedelta(days=10)).isoformat(timespec="milliseconds")
    new_ts = datetime.now(tz_sh).isoformat(timespec="milliseconds")

    with get_session_factory()() as db:
        db.add(
            RiskLog(
                ts=old_ts,
                client_ip="127.0.0.1",
                effective_ip="127.0.0.1",
                path="/api/v1/font/session",
                module="network",
                action="pass",
                risk_score=0,
                reasons="[]",
                ua="old",
            )
        )
        db.add(
            RiskLog(
                ts=new_ts,
                client_ip="127.0.0.1",
                effective_ip="127.0.0.1",
                path="/api/v1/font/session",
                module="network",
                action="pass",
                risk_score=0,
                reasons="[]",
                ua="new",
            )
        )
        db.commit()

        deleted = cleanup_expired_records(db, retention_days=7)
        assert deleted["risk_logs"] >= 1
        remaining_uas = [r.ua for r in db.query(RiskLog).all()]
        assert "old" not in remaining_uas
        assert "new" in remaining_uas
