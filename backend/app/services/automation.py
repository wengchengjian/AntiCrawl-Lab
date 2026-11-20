"""
自动化工具与 CDP 远程调试特征复核服务（automation.py，模块三）。

检测什么：
1. navigator.webdriver=true 及原型链 getter 篡改（识别初级 stealth 补丁）。
2. ChromeDriver 注入标记 $cdc_*、Selenium 属性（__webdriver_evaluate 等）及历史框架（_phantom/__nightmare）。
3. window.chrome 在 Chrome UA 下缺失、桌面 Chrome 下 plugins 为空。
4. CDP 探针（Runtime.enable 触发 console.debug 空参/getter 序列化）。
5. 增强检测：原生函数（fetch/XHR）toString 完整性、隐藏 iframe 跨 Realm 差异、DevTools 窗口差值与堆栈自动化帧。
为什么可疑：
- 无头浏览器、WebDriver 协议与 Puppeteer/Playwright CDP 控制通道会在 JS 运行时留下结构化副作用或破坏原型链原生描述。
阈值依据：
- webdriver=true 或 getter 篡改 +50（AUTOMATION_MARKER）；cdc_/Selenium +40；CDP +25（CDP_MARKER）；
- window.chrome 缺失 +15；plugins=0 +10；原生函数 Hook / iframe 跨帧矛盾各 +25。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from app.constants import ReasonCode, SCORE_WEIGHTS
from app.services.headercheck import is_chromium_user_agent


@dataclass
class AutomationResult:
    """自动化特征复核输出。"""

    score: int = 0
    reasons: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)


def evaluate_automation(automation: Dict[str, Any], ua: str = "") -> AutomationResult:
    """复核前端采集并上报的 automation 特征字段。"""
    res = AutomationResult()
    if not isinstance(automation, dict):
        return res

    ua_lower = ua.lower()
    is_desktop_chrome = is_chromium_user_agent(ua) and not any(
        tok in ua_lower for tok in ("mobile", "android", "iphone", "ipad")
    )

    # 1. navigator.webdriver 与原型链 getter 篡改检测
    webdriver = bool(automation.get("webdriver", False))
    getter_tampered = bool(automation.get("webdriver_getter_tampered", False))
    if webdriver or getter_tampered:
        res.score += SCORE_WEIGHTS["WEBDRIVER_TRUE"]
        res.reasons.append(ReasonCode.AUTOMATION_MARKER.value)
        detail = "navigator.webdriver === true" if webdriver else "Navigator.prototype.webdriver getter 已被篡改"
        res.findings.append(f"{detail} (+50)")

    # 2. ChromeDriver $cdc_ 与 Selenium / 历史框架注入属性
    cdc_keys = list(automation.get("cdc_keys") or [])
    selenium_keys = list(automation.get("selenium_keys") or [])
    legacy_keys = list(automation.get("legacy_keys") or [])
    if cdc_keys or selenium_keys or legacy_keys:
        res.score += SCORE_WEIGHTS["CDC_OR_SELENIUM"]
        res.reasons.append(ReasonCode.AUTOMATION_MARKER.value)
        joined = ", ".join((cdc_keys + selenium_keys + legacy_keys)[:5])
        res.findings.append(f"检测到驱动注入/自动化全局符号: {joined} (+40)")

    # 3. CDP Runtime.enable 探针
    if bool(automation.get("cdp_console_probe", False)):
        res.score += SCORE_WEIGHTS["CDP_MARKER"]
        res.reasons.append(ReasonCode.CDP_MARKER.value)
        res.findings.append("CDP Runtime.enable 序列化触发 console.debug 探针 (+25)")

    # 4. Chrome UA 缺失 window.chrome 与桌面 Chrome plugins 为空
    if is_desktop_chrome and automation.get("has_window_chrome") is False:
        res.score += SCORE_WEIGHTS["WINDOW_CHROME_MISSING"]
        res.reasons.append(ReasonCode.AUTOMATION_MARKER.value)
        res.findings.append("桌面 Chrome UA 但缺失 window.chrome 对象 (+15)")

    if is_desktop_chrome and automation.get("plugins_length") == 0:
        res.score += SCORE_WEIGHTS["PLUGINS_EMPTY"]
        res.reasons.append(ReasonCode.AUTOMATION_MARKER.value)
        res.findings.append("桌面 Chrome UA 但 navigator.plugins.length === 0 (+10)")

    # 5. 增强检测：原生函数完整性 Hook（11.4）
    if bool(automation.get("hooked_native", False)):
        res.score += SCORE_WEIGHTS["HOOKED_NATIVE"]
        res.reasons.append(ReasonCode.AUTOMATION_MARKER.value)
        res.findings.append("fetch 或 XHR.prototype.open 的 toString() 偏离 [native code] (+25)")

    # 6. 增强检测：Iframe 跨 Realm 一致性矛盾（抓出只改顶层 window 的 stealth 补丁）
    if bool(automation.get("iframe_mismatch", False)):
        res.score += SCORE_WEIGHTS["IFRAME_MISMATCH"]
        res.reasons.append(ReasonCode.AUTOMATION_MARKER.value)
        res.findings.append("新建同源 iframe 与顶层 window 的 webdriver/plugins/toString 不一致 (+25)")

    # 7. 增强诊断信号（不单独重罚，辅助画像判断）
    if bool(automation.get("devtools_open", False)):
        res.findings.append("检测到 DevTools 窗口尺寸差或单步调试时间差异常（诊断告警）")
    if bool(automation.get("stack_automation_frame", False)):
        res.score += 15
        res.reasons.append(ReasonCode.CDP_MARKER.value)
        res.findings.append("Error().stack 包含 playwright/puppeteer/pptr 自动化调用帧 (+15)")

    res.reasons = list(dict.fromkeys(res.reasons))
    return res
