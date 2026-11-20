#!/usr/bin/env python3
"""
AntiCrawl Lab 合规自动化检测回归运行器与报告生成器（scripts/regression_runner.py）。

安全声明：
- 本工具仅面向本地隔离或用户明确授权的自有 AntiCrawl Lab 靶场运行检测与回归校准。
- `--mode inprocess`（默认）：完全在进程内通过 FastAPI TestClient 与临时 SQLite + fakeredis 运行，
  且强制设置 `ENABLE_LIVE_GEOIP=0`，零外部网络通信。
- `--mode live`：默认仅允许指向 `127.0.0.1` / `localhost`；指向自有云端实验室时必须显式传入
  `--allow-own-lab`，且运行前强制验证 `GET /api/v1/health` 确认目标确为 `LAB_MODE=1` 的 AntiCrawl Lab。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import random
import re
import sys
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from tests.conftest import BROWSER_HEADERS  # noqa: E402
from tests.regression_scenarios import (  # noqa: E402
    CN_CLOUD_REGRESSION_SAMPLES,
    build_adversarial_bot_cases,
    build_benign_personas,
    make_human_behavior,
)


@dataclass
class CheckOutcome:
    """单项回归检查的执行结果记录。"""

    id: str
    dimension: str
    name: str
    passed: bool
    latency_ms: float
    detail: str
    score: Optional[float] = None
    verdict: Optional[str] = None


def _sign_headers(method: str, path: str, secret: str) -> Dict[str, str]:
    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex
    canonical = f"{method.upper()}\n{path}\n{ts}\n{nonce}"
    sig = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "X-Signature": sig,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
    }


def _solve_waf_html_token(html: str) -> tuple[str, str]:
    arg_m = re.search(r"\}\)\((\d+),(\[[^\]]+\]),(\[[^\]]+\]),(\[[^\]]+\])\)", html)
    ts_m = re.search(r"ts='(\d+)'", html)
    if arg_m is None or ts_m is None:
        raise ValueError("WAF HTML 挑战页未包含预期的动态参数结构")

    xor_key = int(arg_m.group(1))
    dec = lambda raw: "".join(chr(c ^ xor_key) for c in json.loads(raw))
    nid = dec(arg_m.group(2))
    salt = dec(arg_m.group(3))
    param_name = dec(arg_m.group(4))
    ts = ts_m.group(1)

    digest = hashlib.sha256(f"{nid}:{salt}:{ts}:dom1".encode("utf-8")).hexdigest()[:24]
    return param_name, f"{nid}-{ts}-{digest}-dom1"


def _validate_live_target(base_url: str, allow_own_lab: bool) -> httpx.Client:
    """校验 live 目标域名/IP 安全边界并核验目标确实为 LAB_MODE=1 的 AntiCrawl Lab。"""
    parsed = urlparse(base_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        print(f"[安全中止] 非法目标地址: {base_url}", file=sys.stderr)
        raise SystemExit(2)

    if host not in {"127.0.0.1", "localhost", "::1"} and not allow_own_lab:
        print(
            f"[安全中止] live 模式默认仅允许请求本地靶场 (127.0.0.1 / localhost)，拒绝指向 {host}。\n"
            "若确认目标是您自有部署的 AntiCrawl Lab，请显式追加 --allow-own-lab 参数。",
            file=sys.stderr,
        )
        raise SystemExit(2)

    client = httpx.Client(base_url=base_url.rstrip("/"), timeout=10.0, trust_env=False)
    try:
        resp = client.get("/api/v1/health")
    except Exception as exc:
        client.close()
        print(f"[健康检查失败] 无法连接目标 {base_url}: {exc}", file=sys.stderr)
        raise SystemExit(2)

    if resp.status_code != 200:
        client.close()
        print(f"[健康检查失败] GET /api/v1/health 返回 HTTP {resp.status_code}", file=sys.stderr)
        raise SystemExit(2)

    try:
        health = resp.json()
    except Exception:
        client.close()
        print("[健康检查失败] /api/v1/health 返回非 JSON 响应，终止运行。", file=sys.stderr)
        raise SystemExit(2)

    if health.get("status") != "ok" or not isinstance(health.get("rules_meta"), dict):
        client.close()
        print("[身份核验失败] 目标服务未提供有效的 AntiCrawl Lab health/rules_meta 契约，拒绝执行。", file=sys.stderr)
        raise SystemExit(2)

    if not health.get("lab_mode"):
        client.close()
        print("[身份核验失败] 目标靶场 LAB_MODE 未开启（需要 LAB_MODE=1 才能使用模拟 IP 演练）。", file=sys.stderr)
        raise SystemExit(2)

    return client


def _run_suite_with_client(
    client: Any,
    *,
    sign_secret: str,
    octet: int,
    run_tag: str,
) -> Dict[str, Any]:
    """针对任意支持 .get()/.post() 的 Client（TestClient 或 httpx.Client）执行全量 37 项回归。"""
    results: List[CheckOutcome] = []
    suite_start = time.perf_counter()

    # ── 1. 良性真实人类多终端基线（8 项，FPR 门禁）───────────────────────────
    benign_personas = build_benign_personas(octet=octet, run_tag=run_tag)
    false_positives = 0
    for p in benign_personas:
        t0 = time.perf_counter()
        r = client.post("/api/v1/bot/check", headers=p.headers, json=p.payload)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        if r.status_code != 200:
            false_positives += 1
            results.append(
                CheckOutcome(p.id, "Benign(FPR)", p.name, False, ms, f"HTTP {r.status_code}")
            )
            continue
        body = r.json()
        score = float(body["bot_confidence"])
        verdict = str(body["verdict"])
        ok = verdict == "likely_human" and score == p.expected_bot_confidence and body.get("reasons") == []
        if not ok:
            false_positives += 1
        reason_ids = [item["id"] for item in body.get("reasons", [])]
        detail = f"human={body['human_confidence']}%, bot={score}%"
        if reason_ids:
            detail += f", 误触发={reason_ids}"
        results.append(CheckOutcome(p.id, "Benign(FPR)", p.name, ok, ms, detail, score=score, verdict=verdict))

    # ── 2. 自动化/伪装/泄露对抗矩阵（12 项，TPR 门禁）────────────────────────
    adv_cases = build_adversarial_bot_cases(octet=(octet + 1) % 240 + 10, run_tag=run_tag)
    true_positives = 0
    for c in adv_cases:
        t0 = time.perf_counter()
        r = client.get(c.path, headers=c.headers) if c.method == "GET" else client.post(c.path, headers=c.headers, json=c.payload)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        if r.status_code != 200:
            results.append(
                CheckOutcome(c.id, "Adversarial(TPR)", c.name, False, ms, f"HTTP {r.status_code}")
            )
            continue
        body = r.json()
        score = float(body["bot_confidence"])
        verdict = str(body["verdict"])
        hit_ids = {item["id"] for item in body.get("reasons", [])}
        missing = sorted(set(c.required_reason_ids) - hit_ids)
        ok = verdict in c.expected_verdicts and score >= c.min_bot_confidence and not missing
        if ok:
            true_positives += 1
        detail = f"verdict={verdict}, bot={score}%"
        if missing:
            detail += f", 漏检={missing}"
        results.append(
            CheckOutcome(c.id, f"Adversarial({c.dimension})", c.name, ok, ms, detail, score=score, verdict=verdict)
        )

    # ── 3. 国内 10 家主流云厂商机房 IP 识别矩阵 ─────────────────────────────
    for ip_addr, code, vendor_kw in CN_CLOUD_REGRESSION_SAMPLES:
        t0 = time.perf_counter()
        r_aud = client.post(
            "/api/v1/ip/audit",
            headers={**BROWSER_HEADERS, "Sec-Fetch-Site": "same-origin", "X-Simulated-IP": ip_addr},
            json={"browser_timezone": "Asia/Shanghai", "browser_languages": ["zh-CN"]},
        )
        r_bot = client.get(
            "/api/v1/bot/check",
            headers={**BROWSER_HEADERS, "Sec-Fetch-Site": "same-origin", "X-Simulated-IP": ip_addr},
        )
        ms = round((time.perf_counter() - t0) * 1000, 1)
        ok = False
        detail = ""
        risk_val: Optional[float] = None
        if r_aud.status_code == 200 and r_bot.status_code == 200:
            ab = r_aud.json()
            bb = r_bot.json()
            prof = ab["primary_profile"]
            provider = str(prof.get("cloud_provider") or "")
            risk_val = float(ab["risk_score"])
            ok = (
                bool(prof.get("is_hosting"))
                and vendor_kw in provider
                and bool(bb["ip_geo"].get("is_datacenter"))
            )
            detail = f"{ip_addr} -> {provider or prof.get('asn')} ({prof.get('cloud_match_by') or 'cidr'})"
        else:
            detail = f"HTTP audit={r_aud.status_code}, bot={r_bot.status_code}"
        results.append(
            CheckOutcome(f"cn_cloud_{code}", "CN-Cloud", f"国内云机房: {vendor_kw}", ok, ms, detail, score=risk_val)
        )

    # ── 4. IP 地域与 VPN/分流穿透场景（3 项）────────────────────────────────
    vpn_octet = (octet + 2) % 240 + 10
    # 4.1 干净住宅
    t0 = time.perf_counter()
    clean_ip = f"116.228.{vpn_octet}.1"
    r_clean = client.post(
        "/api/v1/ip/audit",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": clean_ip},
        json={
            "browser_timezone": "Asia/Shanghai",
            "browser_tz_offset": -480,
            "browser_languages": ["zh-CN"],
            "webrtc_public_ips": [clean_ip],
            "domestic_echo_ip": clean_ip,
        },
    )
    ms = round((time.perf_counter() - t0) * 1000, 1)
    b_clean = r_clean.json() if r_clean.status_code == 200 else {}
    ok_clean = r_clean.status_code == 200 and b_clean.get("vpn_pierced") is False and b_clean.get("risk_score") == 0
    results.append(
        CheckOutcome(
            "ip_clean_residential",
            "IP/VPN",
            "干净住宅宽带无穿透误报",
            ok_clean,
            ms,
            f"pierced={b_clean.get('vpn_pierced')}, concealment={b_clean.get('concealment_score')}%",
            score=float(b_clean.get("risk_score", 0)),
        )
    )

    # 4.2 WebRTC STUN 穿透
    t0 = time.perf_counter()
    proxy_ip = f"52.95.{vpn_octet}.2"
    r_stun = client.post(
        "/api/v1/ip/audit",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": proxy_ip, "Via": "1.1 lab-proxy"},
        json={
            "browser_timezone": "Asia/Shanghai",
            "browser_tz_offset": -480,
            "browser_languages": ["zh-CN"],
            "webrtc_public_ips": ["116.228.10.5"],
        },
    )
    ms = round((time.perf_counter() - t0) * 1000, 1)
    b_stun = r_stun.json() if r_stun.status_code == 200 else {}
    ok_stun = (
        r_stun.status_code == 200
        and b_stun.get("vpn_pierced") is True
        and b_stun.get("suspected_real_ip") == "116.228.10.5"
        and any(f["id"] == "WEBRTC_STUN_REAL_IP_LEAK" for f in b_stun.get("findings", []))
    )
    results.append(
        CheckOutcome(
            "ip_webrtc_stun_pierce",
            "IP/VPN",
            "WebRTC UDP STUN 穿透代理捕获真实 IP",
            ok_stun,
            ms,
            f"real_ip={b_stun.get('suspected_real_ip')}, proxy_ip={b_stun.get('suspected_proxy_ip')}",
            score=float(b_stun.get("risk_score", 0)),
        )
    )

    # 4.3 Clash 规则分流
    t0 = time.perf_counter()
    direct_ip = f"116.228.{vpn_octet}.3"
    r_split = client.post(
        "/api/v1/ip/audit",
        headers={**BROWSER_HEADERS, "X-Simulated-IP": direct_ip},
        json={
            "browser_timezone": "Asia/Shanghai",
            "browser_languages": ["zh-CN"],
            "domestic_echo_ip": direct_ip,
            "overseas_echo_ip": "52.95.10.20",
        },
    )
    ms = round((time.perf_counter() - t0) * 1000, 1)
    b_split = r_split.json() if r_split.status_code == 200 else {}
    ok_split = (
        r_split.status_code == 200
        and b_split.get("vpn_pierced") is True
        and any(f["id"] == "SPLIT_TUNNEL_VPN_DETECTED" for f in b_split.get("findings", []))
    )
    results.append(
        CheckOutcome(
            "ip_split_tunnel",
            "IP/VPN",
            "国内外双信道暴露 Clash 规则分流",
            ok_split,
            ms,
            f"pierced={b_split.get('vpn_pierced')}, risk={b_split.get('risk_score')}",
            score=float(b_split.get("risk_score", 0)),
        )
    )

    # ── 5. Level 4 商业防线与反逆向回归（4 项）──────────────────────────────
    biz_octet = (octet + 3) % 240 + 10

    # 5.1 WAF 200 HTML/JS 挑战 + 一次性令牌消费
    t0 = time.perf_counter()
    waf_hdrs = {**BROWSER_HEADERS, "X-Simulated-IP": f"116.228.{biz_octet}.1"}
    ok_waf = False
    detail_waf = ""
    try:
        r_w1 = client.get("/api/v1/waf/protected-feed", headers=waf_hdrs)
        param_name, token = _solve_waf_html_token(r_w1.text)
        r_w2 = client.get(f"/api/v1/waf/protected-feed?{param_name}={token}", headers=waf_hdrs)
        r_w3 = client.get(f"/api/v1/waf/protected-feed?{param_name}={token}", headers=waf_hdrs)
        ok_waf = (
            r_w1.status_code == 200
            and "text/html" in r_w1.headers.get("content-type", "")
            and r_w2.status_code == 200
            and r_w2.json().get("waf_verified") is True
            and "text/html" in r_w3.headers.get("content-type", "")
        )
        detail_waf = f"challenge->solve({r_w2.json().get('waf_verified')})->replay_blocked(html)"
    except Exception as exc:
        detail_waf = f"异常: {exc}"
    results.append(
        CheckOutcome("biz_waf_challenge", "Business/WAF", "WAF 200 HTML/JS 动态挑战与一次性放行", ok_waf, round((time.perf_counter() - t0) * 1000, 1), detail_waf)
    )

    # 5.2 HMAC 签名 + Nonce 防重放 + 匿名深翻页配额
    t0 = time.perf_counter()
    prod_ip = f"116.228.{biz_octet}.2"
    prod_hdrs = {**BROWSER_HEADERS, "X-Simulated-IP": prod_ip}
    r_unsig = client.get("/api/v1/products", headers=prod_hdrs)
    sig_hdrs = _sign_headers("GET", "/api/v1/products", sign_secret)
    r_p1 = client.get("/api/v1/products?page=1&size=6", headers={**prod_hdrs, **sig_hdrs})
    r_rep = client.get("/api/v1/products?page=1&size=6", headers={**prod_hdrs, **sig_hdrs})
    r_p3 = client.get(
        "/api/v1/products?page=3&size=6",
        headers={**prod_hdrs, **_sign_headers("GET", "/api/v1/products", sign_secret)},
    )
    ok_sig = (
        r_unsig.status_code == 401
        and r_unsig.json().get("risk_reason") == "SIGNATURE_MISSING"
        and r_p1.status_code == 200
        and r_rep.status_code == 401
        and r_rep.json().get("risk_reason") == "NONCE_REUSED"
        and r_p3.status_code == 403
        and r_p3.json().get("detail_code") == "BROWSE_LIMIT_EXCEEDED"
    )
    results.append(
        CheckOutcome(
            "biz_sig_nonce_quota",
            "Business/WAF",
            "HMAC 签名 + Nonce 重放拦截 + 第 3 页配额拒绝",
            ok_sig,
            round((time.perf_counter() - t0) * 1000, 1),
            f"unsig={r_unsig.status_code}, ok={r_p1.status_code}, replay={r_rep.status_code}, p3={r_p3.status_code}",
        )
    )

    # 5.3 访问顺序图：跳过导航直接抓价 → 拦截；按序导航后 → PUA 放行
    t0 = time.perf_counter()
    r_skip = client.get(
        "/api/v1/products/1/price",
        headers={
            "User-Agent": BROWSER_HEADERS["User-Agent"],
            "Sec-CH-UA": BROWSER_HEADERS["Sec-CH-UA"],
            "X-Simulated-IP": f"116.228.{biz_octet}.3",
            **_sign_headers("GET", "/api/v1/products/1/price", sign_secret),
        },
    )
    flow_ip = f"116.228.{biz_octet}.4"
    flow_hdrs = {**BROWSER_HEADERS, "X-Simulated-IP": flow_ip, "X-Session-Id": f"reg-flow-{run_tag}"}
    client.post("/api/v1/behavior/trace", headers=flow_hdrs, json=make_human_behavior())
    client.get(
        "/api/v1/products?page=1&size=6",
        headers={**flow_hdrs, "X-Visit-Origin": "/", **_sign_headers("GET", "/api/v1/products", sign_secret)},
    )
    r_ok_price = client.get(
        "/api/v1/products/1/price",
        headers={**flow_hdrs, **_sign_headers("GET", "/api/v1/products/1/price", sign_secret)},
    )
    ok_order = (
        r_skip.status_code == 403
        and "VISIT_ORDER_VIOLATION" in (r_skip.json().get("reasons") or [])
        and r_ok_price.status_code == 200
        and any(0xE000 <= ord(ch) <= 0xE00A for ch in r_ok_price.json().get("price_pua", ""))
    )
    results.append(
        CheckOutcome(
            "biz_visit_order_graph",
            "Business/WAF",
            "10.3 访问顺序图拦截跳步抓价与正常路径 PUA 放行",
            ok_order,
            round((time.perf_counter() - t0) * 1000, 1),
            f"skip={r_skip.status_code}, normal={r_ok_price.status_code}",
        )
    )

    # 5.4 动态字体 SSR 源码 PUA 私用区验证
    t0 = time.perf_counter()
    r_ssr = client.get("/ssr/price", headers=BROWSER_HEADERS)
    has_pua = r_ssr.status_code == 200 and any(0xE000 <= ord(ch) <= 0xE00A for ch in r_ssr.text)
    results.append(
        CheckOutcome(
            "biz_dynamic_font_pua",
            "Business/WAF",
            "动态字体 /ssr/price 源码含 U+E000–U+E00A 私用区编码",
            has_pua,
            round((time.perf_counter() - t0) * 1000, 1),
            f"HTTP {r_ssr.status_code}, pua_detected={has_pua}",
        )
    )

    total_ms = round((time.perf_counter() - suite_start) * 1000, 1)
    passed_cnt = sum(1 for item in results if item.passed)
    fpr = round(false_positives / len(benign_personas), 4)
    tpr = round(true_positives / len(adv_cases), 4)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(results),
        "passed": passed_cnt,
        "failed": len(results) - passed_cnt,
        "fpr": fpr,
        "tpr": tpr,
        "duration_ms": total_ms,
        "outcomes": [asdict(r) for r in results],
    }


def _run_optional_playwright_check(frontend_url: str) -> Optional[CheckOutcome]:
    """可选无头浏览器检测：若已安装 playwright 则访问 /bot-check 验证自动识别为非纯人类。"""
    try:
        from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
    except ImportError:
        print("[Playwright] 当前环境未安装 playwright，已按安全策略跳过无头浏览器实测。")
        return None

    t0 = time.perf_counter()
    target = f"{frontend_url.rstrip('/')}/bot-check"
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(target, wait_until="networkidle")
        page.wait_for_timeout(1800)
        body_text = page.locator("body").inner_text()
        browser.close()

    ms = round((time.perf_counter() - t0) * 1000, 1)
    detected = any(kw in body_text for kw in ("LIKELY_BOT", "高概率机器人", "SUSPICIOUS", "存在可疑"))
    return CheckOutcome(
        id="playwright_headless_live",
        dimension="Playwright",
        name="真实无头 Chromium 访问 /bot-check 实测检出",
        passed=detected,
        latency_ms=ms,
        detail=f"detected={detected} on {target}",
    )


def _print_summary(report: Dict[str, Any], target_label: str) -> None:
    print(f"\n=== AntiCrawl Lab 自动化检测回归报告 ({target_label}) ===")
    dims: Dict[str, List[Dict[str, Any]]] = {}
    for item in report["outcomes"]:
        dims.setdefault(item["dimension"], []).append(item)

    print(f"{'维度':<26} | {'通过/总数':<10} | {'说明'}")
    print("-" * 78)
    for dim, items in dims.items():
        ok_cnt = sum(1 for x in items if x["passed"])
        fails = [x["id"] for x in items if not x["passed"]]
        note = "全部通过" if not fails else f"失败: {', '.join(fails)}"
        print(f"{dim:<26} | {f'{ok_cnt}/{len(items)}':<10} | {note}")

    print("-" * 78)
    print(
        f"总计: {report['passed']}/{report['total']} PASS | "
        f"误报率 FPR={report['fpr'] * 100:.1f}% | "
        f"检出率 TPR={report['tpr'] * 100:.1f}% | "
        f"耗时={report['duration_ms']}ms\n"
    )

    if report["failed"] > 0:
        print("失败详情:")
        for item in report["outcomes"]:
            if not item["passed"]:
                print(f"  [FAIL] {item['id']} ({item['name']}): {item['detail']}")


def _write_markdown_report(path: Path, report: Dict[str, Any], target_label: str) -> None:
    lines = [
        f"# AntiCrawl Lab 自动化检测回归报告（{target_label}）",
        "",
        f"- 生成时间：`{report['generated_at']}`",
        f"- 通过率：**{report['passed']} / {report['total']}**",
        f"- 误报率 (FPR)：**{report['fpr'] * 100:.1f}%**",
        f"- 检出率 (TPR)：**{report['tpr'] * 100:.1f}%**",
        f"- 总耗时：`{report['duration_ms']} ms`",
        "",
        "| ID | 维度 | 用例 | 状态 | 耗时(ms) | 结果摘要 |",
        "| :--- | :--- | :--- | :---: | ---: | :--- |",
    ]
    for item in report["outcomes"]:
        badge = "PASS" if item["passed"] else "FAIL"
        lines.append(
            f"| `{item['id']}` | {item['dimension']} | {item['name']} | {badge} | {item['latency_ms']} | {item['detail']} |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_inprocess(sign_secret: str) -> Dict[str, Any]:
    """在完全隔离的临时 SQLite + fakeredis 进程内环境中运行回归套件。"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "regression.db"
        db_url = f"sqlite:///{db_path.as_posix()}"
        env_backup = {
            k: os.environ.get(k)
            for k in ("LAB_MODE", "ENABLE_LIVE_GEOIP", "REDIS_URL", "DATABASE_URL", "SIGN_SECRET", "POW_DIFFICULTY")
        }
        try:
            os.environ["LAB_MODE"] = "1"
            os.environ["ENABLE_LIVE_GEOIP"] = "0"
            os.environ["REDIS_URL"] = ""
            os.environ["DATABASE_URL"] = db_url
            os.environ["SIGN_SECRET"] = sign_secret
            os.environ["POW_DIFFICULTY"] = "2"

            from fastapi.testclient import TestClient

            from app.cache import reset_cache_for_test
            from app.db import get_engine, init_db, reset_engine_for_test
            from app.main import create_app

            reset_cache_for_test("")
            reset_engine_for_test(db_url)
            init_db(db_url)

            app = create_app()
            with TestClient(app) as tc:
                return _run_suite_with_client(tc, sign_secret=sign_secret, octet=201, run_tag="inproc")
        finally:
            try:
                from app.cache import reset_cache_for_test
                from app.db import get_engine

                reset_cache_for_test("")
                get_engine().dispose()
            except Exception:
                pass
            for k, old_val in env_backup.items():
                if old_val is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = old_val


def main() -> int:
    parser = argparse.ArgumentParser(description="AntiCrawl Lab 合规自动化检测回归运行器")
    parser.add_argument("--mode", choices=["inprocess", "live"], default="inprocess", help="运行模式（默认 inprocess 进程内隔离）")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="live 模式下的靶场 URL（默认 http://127.0.0.1:8000）")
    parser.add_argument("--allow-own-lab", action="store_true", help="显式确认非 localhost 目标为自有 AntiCrawl Lab 靶场")
    parser.add_argument("--sign-secret", default=os.getenv("SIGN_SECRET", "change-me-in-lab"), help="HMAC 签名密钥")
    parser.add_argument("--playwright", action="store_true", help="live 模式下可选运行真实无头 Chromium 检测")
    parser.add_argument("--frontend-url", default="", help="Playwright 访问的前端地址（默认与 --base-url 相同）")
    parser.add_argument("--report-json", default="", help="导出 JSON 格式回归报告的路径")
    parser.add_argument("--report-md", default="", help="导出 Markdown 格式回归报告的路径")
    args = parser.parse_args()

    if args.mode == "inprocess":
        target_label = "inprocess (isolated SQLite + fakeredis)"
        report = run_inprocess(args.sign_secret)
    else:
        target_label = f"live ({args.base_url})"
        live_client = _validate_live_target(args.base_url, args.allow_own_lab)
        try:
            octet = random.randint(20, 235)
            run_tag = uuid.uuid4().hex[:6]
            report = _run_suite_with_client(
                live_client,
                sign_secret=args.sign_secret,
                octet=octet,
                run_tag=run_tag,
            )
            if args.playwright:
                pw_res = _run_optional_playwright_check(args.frontend_url or args.base_url)
                if pw_res is not None:
                    report["outcomes"].append(asdict(pw_res))
                    report["total"] += 1
                    if pw_res.passed:
                        report["passed"] += 1
                    else:
                        report["failed"] += 1
        finally:
            live_client.close()

    _print_summary(report, target_label)

    if args.report_json:
        out_json = Path(args.report_json)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"已导出 JSON 报告: {out_json}")

    if args.report_md:
        out_md = Path(args.report_md)
        _write_markdown_report(out_md, report, target_label)
        print(f"已导出 Markdown 报告: {out_md}")

    return 0 if (report["failed"] == 0 and report["fpr"] == 0.0 and report["tpr"] == 1.0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
