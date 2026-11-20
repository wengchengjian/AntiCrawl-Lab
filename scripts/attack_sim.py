#!/usr/bin/env python3
"""
AntiCrawl Lab 本地攻击者画像演示脚本（scripts/attack_sim.py）。

安全声明（第 17 章）：
- 本脚本仅向本地靶场（默认 http://127.0.0.1:8000）发起教学与自测请求，
  严禁修改为指向任何外部/第三方站点。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import time
import uuid
from typing import Dict

import httpx

DEFAULT_BASE = "http://127.0.0.1:8000"
DEFAULT_SECRET = "change-me-in-lab"


def _assert_local_target(base_url: str) -> None:
    if not (
        base_url.startswith("http://127.0.0.1")
        or base_url.startswith("http://localhost")
    ):
        raise SystemExit("安全边界限制：attack_sim.py 仅允许请求本地靶场（127.0.0.1 / localhost）！")


def _sign(method: str, path: str, secret: str = DEFAULT_SECRET) -> Dict[str, str]:
    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex
    canonical = f"{method.upper()}\n{path}\n{ts}\n{nonce}"
    sig = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "X-Signature": sig,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
    }


def run_http_personas(base_url: str) -> None:
    print(f"=== AntiCrawl Lab 攻击者画像演示（目标: {base_url}） ===")
    with httpx.Client(base_url=base_url, timeout=10.0) as client:
        # 0. 健康检查
        r = client.get("/api/v1/health")
        print(f"[0] Health: {r.status_code} redis_mode={r.json().get('redis_mode')} lab_mode={r.json().get('lab_mode')}")

        # 1. 画像 A：无 UA 裸请求（应触发 HEADER_MISSING 且返回 200 警告）
        r = client.get(
            "/api/v1/font/session",
            headers={"User-Agent": "", "X-Simulated-IP": "116.228.10.50"},
        )
        print(f"[1] 空 UA 裸请求: status={r.status_code} (预期 200 + HEADER_MISSING)")

        # 2. 画像 B：1 秒内高频 11 连打（第 11 次触发 429 RATE_LIMITED）
        burst_ip = "116.228.88.88"
        client.post("/api/v1/admin/reset", json={"ip": burst_ip})
        statuses = [
            client.get("/api/v1/font/session", headers={"X-Simulated-IP": burst_ip}).status_code
            for _ in range(11)
        ]
        print(f"[2] 1 秒 11 连打状态序列: {statuses} (预期第 11 次为 429)")

        # 3. 画像 C：机房 IP + 无签名直打核心接口
        r = client.get("/api/v1/products", headers={"X-Simulated-IP": "52.95.10.20"})
        print(f"[3] 无签名请求列表: status={r.status_code} body={r.json()}")

        # 4. 画像 D：同一签名 + Nonce 重放攻击
        sig_hdrs = _sign("GET", "/api/v1/products")
        hdrs = {
            **sig_hdrs,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
            "Sec-CH-UA": '"Chromium";v="126", "Google Chrome";v="126"',
            "Accept-Language": "zh-CN,zh;q=0.9",
            "X-Simulated-IP": "116.228.10.5",
        }
        r1 = client.get("/api/v1/products", headers=hdrs)
        r2 = client.get("/api/v1/products", headers=hdrs)
        print(f"[4] 签名首次={r1.status_code}, 原样重放={r2.status_code} reason={r2.json().get('risk_reason')}")

        # 5. 画像 E：踩蜜罐封禁 + 解封恢复
        trap_ip = "123.125.66.66"
        r_trap = client.get("/api/v1/trap", headers={"X-Simulated-IP": trap_ip})
        r_blocked = client.get("/api/v1/font/session", headers={"X-Simulated-IP": trap_ip})
        r_unban = client.post("/api/v1/admin/unban", json={"ip": trap_ip, "operator": "attack_sim"})
        r_recovered = client.get("/api/v1/font/session", headers={"X-Simulated-IP": trap_ip})
        print(
            f"[5] 蜜罐演练: trap={r_trap.status_code}, 封禁后={r_blocked.status_code}, "
            f"解封={r_unban.status_code}, 恢复={r_recovered.status_code}"
        )

        # 6. 画像 F：抓取动态字体价格文本（验证 PUA 私用区乱码）
        r_price = client.get("/price")
        has_pua = any(0xE000 <= ord(ch) <= 0xE00A for ch in r_price.text)
        print(f"[6] SSR /price 抓取: status={r_price.status_code}, 包含私用区乱码={has_pua}")


def run_playwright_headless(frontend_url: str) -> None:
    try:
        from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
    except ImportError:
        print("[Playwright] 未安装 playwright 可选依赖，跳过无头浏览器演示。")
        return

    print(f"=== Playwright 无头浏览器画像演示（目标: {frontend_url}） ===")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(f"{frontend_url}/probes", wait_until="networkidle")
        page.wait_for_timeout(1500)
        text = page.locator("body").inner_text()
        print("[Playwright] ProbeTest 渲染完成，是否包含 AUTOMATION / webdriver 提示:", "AUTOMATION" in text or "fp_id" in text)
        browser.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="AntiCrawl Lab 攻击者画像本地演示脚本")
    parser.add_argument("--base-url", default=DEFAULT_BASE, help="后端靶场地址（仅限本地）")
    parser.add_argument("--frontend-url", default="http://127.0.0.1:5173", help="前端靶场地址")
    parser.add_argument("--no-playwright", action="store_true", help="跳过 Playwright 无头浏览器演示")
    args = parser.parse_args()

    _assert_local_target(args.base_url)
    run_http_personas(args.base_url)
    if not args.no_playwright:
        run_playwright_headless(args.frontend_url)


if __name__ == "__main__":
    main()
