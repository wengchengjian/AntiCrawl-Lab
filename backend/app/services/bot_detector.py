"""
全维度机器人检测与置信分引擎（bot_detector.py）。

参考业内三大基准检测矩阵整合 5 大维度共 30+ 指标：
1. Sannysoft（自动化/无头核验）：webdriver、getter 原型链、chrome 对象子属性、
   Permissions API 矛盾、Plugins/MimeTypes 原型、WebGL 软渲染、破损图片、$cdc_/CDP/Iframe/Hook。
2. BrowserScan（环境真实性与交叉一致）：UA vs Client Hints(HTTP & userAgentData)、
   OS×Platform×WebGL 三角校验、IP 归属地 vs 时区/语言、timezoneOffset 交叉、
   Web Worker 跨线程、JS Math 浮点引擎、outerWidth/outerHeight、硬件参数合理性。
3. BrowserLeaks（图形/隐私/硬件泄露审计）：Canvas 双渲染噪点、WebGL 扩展数与纹理上限、
   OfflineAudioContext、字体 OS 合理性、ClientRects 亚像素噪点、WebRTC ICE、
   MediaDevices 数量、SpeechSynthesis 语音数、CSS 媒体查询一致性。
4. Network（网络协议层）：Header 完整度、Sec-Fetch-*、X-JA4、机房/黑名单 IP。
5. Behavior（行为动力学）：isTrusted 占比、轨迹点数与几何特征、停留时长、击键方差。

输出模型：
- bot_confidence (0.0–100.0)：命中风险加权累计（上限 100.0）
- human_confidence = 100.0 - bot_confidence
- verdict: likely_human (<25) | suspicious (25–54.9) | likely_bot (>=55)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from app.services.automation import evaluate_automation
from app.services.behavior import evaluate_behavior
from app.services.consistency import evaluate_consistency
from app.services.geoip import GeoInfo
from app.services.headercheck import (
    check_headers,
    is_chromium_user_agent,
    is_non_secure_http_context,
)


@dataclass
class CheckMetric:
    """单项检测审计条目（用于 Sannysoft/BrowserScan/BrowserLeaks 逐项展示）。"""

    id: str
    category: str  # sannysoft | browserscan | browserleaks | network | behavior
    source_ref: str
    name: str
    status: str  # pass | warn | fail | info
    observed: str
    expected: str
    risk_delta: float
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "source_ref": self.source_ref,
            "name": self.name,
            "status": self.status,
            "observed": self.observed,
            "expected": self.expected,
            "risk_delta": round(self.risk_delta, 1),
            "reason": self.reason,
        }


@dataclass
class BotAssessment:
    """机器人检测综合置信分输出。"""

    bot_confidence: float
    human_confidence: float
    verdict: str
    verdict_label: str
    confidence_level: str
    summary: str
    category_scores: Dict[str, float]
    reasons: List[Dict[str, Any]]
    checks: List[Dict[str, Any]]
    telemetry_coverage: Dict[str, Any]


def _short(val: Any, limit: int = 80) -> str:
    s = str(val) if val is not None else ""
    return s if len(s) <= limit else f"{s[:limit]}..."


def assess_bot_confidence(
    headers: Mapping[str, str],
    geo: GeoInfo,
    payload: Optional[Dict[str, Any]] = None,
) -> BotAssessment:
    """
    执行全维度机器人置信分评估。
    - payload 为 None（如纯 HTTP GET /api/v1/bot/check）：基于网络/协议/IP 维度评估（confidence_level=low）。
    - payload 存在（POST /api/v1/bot/check）：融合 5 大维度共 30+ 指标进行加权评估。
    """
    norm_headers = {k.lower(): v for k, v in headers.items()}
    checks: List[CheckMetric] = []
    reasons_out: List[Dict[str, Any]] = []
    cat_scores: Dict[str, float] = {
        "sannysoft": 0.0,
        "browserscan": 0.0,
        "browserleaks": 0.0,
        "network": 0.0,
        "behavior": 0.0,
    }

    def add_check(
        cid: str,
        category: str,
        source_ref: str,
        name: str,
        status: str,
        observed: str,
        expected: str,
        risk_delta: float,
        reason: str,
        reason_code: str = "",
    ) -> None:
        checks.append(
            CheckMetric(
                id=cid,
                category=category,
                source_ref=source_ref,
                name=name,
                status=status,
                observed=observed,
                expected=expected,
                risk_delta=risk_delta,
                reason=reason,
            )
        )
        if risk_delta > 0:
            cat_scores[category] = round(cat_scores.get(category, 0.0) + risk_delta, 1)
            reasons_out.append(
                {
                    "id": cid,
                    "code": reason_code or cid.upper(),
                    "category": category,
                    "source_ref": source_ref,
                    "weight": round(risk_delta, 1),
                    "severity": "critical" if risk_delta >= 30 else ("high" if risk_delta >= 15 else "medium"),
                    "message": reason,
                }
            )

    # ── 维度 4：Network（HTTP 协议头、JA4、Sec-Fetch、IP 信誉）────────────────
    non_secure_http = is_non_secure_http_context(norm_headers)
    hdr_res = check_headers(norm_headers)
    ua_hdr = norm_headers.get("user-agent", "").strip()
    sec_fetch_site = norm_headers.get("sec-fetch-site", "").strip()

    if hdr_res.score > 0:
        add_check(
            "http_headers",
            "network",
            "HTTP Protocol",
            "请求头完整性与工具特征",
            "fail" if hdr_res.score >= 30 else "warn",
            f"UA={_short(ua_hdr or '<空>', 50)}; 扣分+{hdr_res.score}",
            "完整现代浏览器请求头与一致的 Sec-CH-UA",
            float(hdr_res.score),
            "；".join(hdr_res.details),
            reason_code=hdr_res.reasons[0] if hdr_res.reasons else "HEADER_INCONSISTENT",
        )
    else:
        add_check(
            "http_headers",
            "network",
            "HTTP Protocol",
            "请求头完整性与工具特征",
            "pass",
            _short(ua_hdr, 56),
            "合法现代浏览器 UA 与客户端提示头",
            0.0,
            "HTTP 请求头基础指纹自然",
        )

    # 现代浏览器同源/跨站导航一般带 Sec-Fetch-Site（仅在 HTTPS 或 localhost 安全上下文发送）
    if ua_hdr and is_chromium_user_agent(ua_hdr) and not sec_fetch_site:
        if non_secure_http:
            add_check(
                "sec_fetch_metadata",
                "network",
                "BrowserScan",
                "Sec-Fetch-Site 获取元数据",
                "info",
                "<非 HTTPS 省略>",
                "HTTPS / localhost 下发送 same-origin",
                0.0,
                "当前为非 HTTPS 公网明文 HTTP（Non-Secure Context），浏览器按 W3C 规范不发送 Sec-Fetch-Site，不扣分；启用 HTTPS 后自动激活校验",
            )
        else:
            add_check(
                "sec_fetch_metadata",
                "network",
                "BrowserScan",
                "Sec-Fetch-Site 获取元数据",
                "warn",
                "<缺失>",
                "same-origin / same-site",
                10.0,
                "Chromium 浏览器声明下缺少 Sec-Fetch-Site 元数据头（常见于伪造请求头的脚本）",
                reason_code="HEADER_MISSING",
            )
    elif sec_fetch_site:
        add_check(
            "sec_fetch_metadata",
            "network",
            "BrowserScan",
            "Sec-Fetch-Site 获取元数据",
            "pass",
            sec_fetch_site,
            "same-origin / same-site / none",
            0.0,
            "携带标准 Fetch Metadata 安全头",
        )

    if geo.score > 0:
        add_check(
            "ip_reputation",
            "network",
            "BrowserScan",
            "IP ASN 与机房/黑名单信誉",
            "fail" if geo.is_blacklist else "warn",
            f"{geo.ip} ({geo.country}/{geo.city}, {geo.asn})",
            "普通住宅或非黑名单网络",
            float(geo.score),
            f"IP 命中 {'黑名单' if geo.is_blacklist else '数据中心/云代理'}网段（{geo.asn}）",
            reason_code=geo.reasons[0] if geo.reasons else "DATACENTER_IP",
        )
    else:
        add_check(
            "ip_reputation",
            "network",
            "BrowserScan",
            "IP ASN 与机房/黑名单信誉",
            "pass",
            f"{geo.ip} ({geo.country}/{geo.city})",
            "住宅宽带或本地可信 IP",
            0.0,
            "未命中机房代理或黑名单网段",
        )

    # 若未上报前端探针（纯 GET /api/v1/bot/check），直接在此汇总返回
    if payload is None:
        total = min(100.0, round(sum(c.risk_delta for c in checks), 1))
        human = round(100.0 - total, 1)
        verdict = "likely_bot" if total >= 55 else ("suspicious" if total >= 25 else "likely_human")
        verdict_label = {"likely_human": "疑似真实浏览器（仅 HTTP 维度）", "suspicious": "存在可疑协议特征", "likely_bot": "高概率自动化脚本"}[verdict]
        reasons_out.sort(key=lambda x: x["weight"], reverse=True)
        return BotAssessment(
            bot_confidence=total,
            human_confidence=human,
            verdict=verdict,
            verdict_label=verdict_label,
            confidence_level="low",
            summary="当前仅基于 HTTP 请求头与 IP 信誉评估；调用 POST /api/v1/bot/check 上报浏览器探针可获得完整置信分。",
            category_scores=cat_scores,
            reasons=reasons_out,
            checks=[c.to_dict() for c in checks],
            telemetry_coverage={"mode": "http_only", "checked_items": len(checks)},
        )

    # ── 维度 1：Sannysoft 自动化与无头核验 ───────────────────────────────────
    ua = str(payload.get("ua") or ua_hdr)
    ua_lower = ua.lower()
    automation = payload.get("automation") or {}
    auto_res = evaluate_automation(automation, ua=ua)
    extra = payload.get("extra_probes") or {}
    sanny = extra.get("sannysoft") or {}
    webgl = payload.get("webgl") or {}
    webgl_renderer = str(webgl.get("renderer") or "")
    webgl_masked = bool(webgl.get("masked", False))
    languages = [str(x) for x in (payload.get("languages") or [])]

    # 1.1 UA 无头关键词
    headless_hit = any(k in ua_lower for k in ("headless", "phantomjs", "playwright", "puppeteer", "selenium"))
    add_check(
        "user_agent_headless",
        "sannysoft",
        "Sannysoft",
        "User-Agent 无头标识",
        "fail" if headless_hit else "pass",
        _short(ua, 60),
        "不含 HeadlessChrome / PhantomJS 等无头特征",
        35.0 if headless_hit else 0.0,
        "User-Agent 直接暴露无头或自动化框架标记" if headless_hit else "User-Agent 未暴露显式无头标识",
        "AUTOMATION_MARKER",
    )

    # 1.2 navigator.webdriver
    wd_flag = bool(automation.get("webdriver", False))
    add_check(
        "webdriver_flag",
        "sannysoft",
        "Sannysoft",
        "navigator.webdriver",
        "fail" if wd_flag else "pass",
        str(wd_flag),
        "false / undefined",
        45.0 if wd_flag else 0.0,
        "navigator.webdriver === true，命中 W3C WebDriver 自动化标准标志" if wd_flag else "navigator.webdriver 为正常非自动化值",
        "AUTOMATION_MARKER",
    )

    # 1.3 webdriver getter 原型链篡改
    wd_tampered = bool(automation.get("webdriver_getter_tampered", False))
    add_check(
        "webdriver_proto_tampered",
        "sannysoft",
        "Sannysoft",
        "WebDriver 原型链描述符",
        "fail" if wd_tampered else "pass",
        "已篡改" if wd_tampered else "[native code]",
        "挂载在 Navigator.prototype 的原生 getter",
        35.0 if wd_tampered else 0.0,
        "检测到对 navigator.webdriver 的实例覆盖或非原生 getter（典型初级 Stealth 补丁痕迹）" if wd_tampered else "webdriver 属性描述符保持原型链原生状态",
        "AUTOMATION_MARKER",
    )

    # 1.4 window.chrome 对象及子属性
    is_chr = is_chromium_user_agent(ua)
    has_chrome = automation.get("has_window_chrome")
    chrome_sub = sanny.get("chrome_subprops") or {}
    chrome_bad = is_chr and (has_chrome is False or (isinstance(chrome_sub, dict) and chrome_sub.get("present") is False))
    add_check(
        "chrome_object_integrity",
        "sannysoft",
        "Sannysoft",
        "window.chrome 对象完整性",
        "fail" if chrome_bad else "pass",
        f"has_chrome={has_chrome}, runtime={chrome_sub.get('runtime') if isinstance(chrome_sub, dict) else 'n/a'}",
        "Chromium 下存在 window.chrome 及其子属性",
        18.0 if chrome_bad else 0.0,
        "声明为 Chrome/Chromium 内核但缺失 window.chrome 运行时对象" if chrome_bad else "window.chrome 运行时结构完整",
        "AUTOMATION_MARKER",
    )

    # 1.5 Permissions API 矛盾（经典 Sannysoft：Notification.permission=denied 但 permissions.query=prompt）
    perm_mismatch = bool(sanny.get("permissions_inconsistent", False))
    add_check(
        "permissions_notification_mismatch",
        "sannysoft",
        "Sannysoft",
        "Permissions 与 Notification 一致性",
        "fail" if perm_mismatch else "pass",
        str(sanny.get("perm_detail", "一致" if not perm_mismatch else "矛盾")),
        "Notification.permission 与 permissions.query 状态同步",
        22.0 if perm_mismatch else 0.0,
        "Notification.permission 与 navigator.permissions.query('notifications') 返回状态矛盾（无头环境典型缺陷）"
        if perm_mismatch
        else "权限查询状态与通知权限状态一致",
        "AUTOMATION_MARKER",
    )

    # 1.6 Plugins 完整性（数量 + PluginArray 原型）
    plugins_len = automation.get("plugins_length")
    plugins_proto_ok = sanny.get("plugins_proto_valid", True)
    is_desktop_chr = is_chr and not any(t in ua_lower for t in ("mobile", "android", "iphone", "ipad"))
    plugins_bad = (is_desktop_chr and plugins_len == 0) or (plugins_proto_ok is False)
    add_check(
        "plugins_integrity",
        "sannysoft",
        "Sannysoft",
        "Plugins 数量与原型链",
        "fail" if plugins_bad else "pass",
        f"length={plugins_len}, proto_valid={plugins_proto_ok}",
        "桌面 Chrome plugins > 0 且原型为 PluginArray",
        15.0 if plugins_bad else 0.0,
        "桌面 Chrome 环境下 plugins 为空或 PluginArray 原型链伪造失败" if plugins_bad else "Plugins 列表与原型链符合标准浏览器特征",
        "AUTOMATION_MARKER",
    )

    # 1.7 MimeTypes 完整性
    mime_len = sanny.get("mime_types_length")
    mime_proto_ok = sanny.get("mime_types_proto_valid", True)
    mime_bad = (is_desktop_chr and mime_len == 0) or (mime_proto_ok is False)
    add_check(
        "mime_types_integrity",
        "sannysoft",
        "Sannysoft",
        "MimeTypes 数组与原型",
        "warn" if mime_bad else "pass",
        f"length={mime_len}, proto_valid={mime_proto_ok}",
        "MimeTypeArray 原型合法且桌面端非空",
        10.0 if mime_bad else 0.0,
        "MimeTypes 数组为空或原型链异常" if mime_bad else "MimeTypes 原型与长度正常",
        "AUTOMATION_MARKER",
    )

    # 1.8 Languages 一致性
    nav_lang = str(sanny.get("language") or (languages[0] if languages else ""))
    lang_bad = (not languages) or (bool(nav_lang) and bool(languages) and nav_lang != languages[0])
    add_check(
        "languages_coherence",
        "sannysoft",
        "Sannysoft",
        "navigator.languages 一致性",
        "warn" if lang_bad else "pass",
        f"language={nav_lang}, languages={languages[:3]}",
        "languages 非空且首项等于 navigator.language",
        12.0 if lang_bad else 0.0,
        "navigator.languages 为空或与 navigator.language 首选语言冲突" if lang_bad else "语言列表与首选语言完全匹配",
        "FINGERPRINT_CONFLICT",
    )

    # 1.9 WebGL 软渲染器与掩码
    rend_low = webgl_renderer.lower()
    soft_gl = webgl_masked or any(k in rend_low for k in ("swiftshader", "llvmpipe", "mesa offscreen", "brian paul", "software"))
    add_check(
        "webgl_software_renderer",
        "sannysoft",
        "Sannysoft",
        "WebGL 渲染器硬件真实性",
        "fail" if soft_gl else "pass",
        _short(webgl_renderer or "<空>", 60),
        "真实独立/集成显卡驱动渲染器",
        20.0 if soft_gl else 0.0,
        "命中 SwiftShader/llvmpipe 无头软件渲染器或调试扩展被掩码" if soft_gl else "WebGL 硬件渲染器特征正常",
        "WEBGL_MASKED",
    )

    # 1.10 破损图片测试（Sannysoft Image naturalWidth）
    broken_img_ok = sanny.get("broken_image_ok", True)
    add_check(
        "broken_image_test",
        "sannysoft",
        "Sannysoft",
        "破损图片尺寸探测",
        "warn" if broken_img_ok is False else "pass",
        "异常" if broken_img_ok is False else "naturalWidth=0 (正常)",
        "未加载图片 naturalWidth/Height === 0",
        10.0 if broken_img_ok is False else 0.0,
        "破损图片回落尺寸异常（常见于被魔改的无头图像渲染管线）" if broken_img_ok is False else "破损图片行为符合浏览器规范",
        "AUTOMATION_MARKER",
    )

    # 1.11 驱动全局符号 ($cdc_ / Selenium / Phantom)
    injected_all = list(automation.get("cdc_keys") or []) + list(automation.get("selenium_keys") or []) + list(automation.get("legacy_keys") or [])
    add_check(
        "driver_globals",
        "sannysoft",
        "Sannysoft",
        "驱动注入全局符号 ($cdc_ / Selenium)",
        "fail" if injected_all else "pass",
        ", ".join(injected_all[:4]) if injected_all else "未检测到",
        "Window/Document 无驱动注入变量",
        40.0 if injected_all else 0.0,
        f"检测到驱动注入变量: {', '.join(injected_all[:4])}" if injected_all else "未发现 ChromeDriver/Selenium 全局注入符",
        "AUTOMATION_MARKER",
    )

    # 1.12 CDP Runtime.enable & 堆栈帧
    cdp_hit = bool(automation.get("cdp_console_probe", False)) or bool(automation.get("stack_automation_frame", False))
    add_check(
        "cdp_runtime_probe",
        "sannysoft",
        "Sannysoft / CDP",
        "CDP Runtime.enable 与调用栈",
        "fail" if cdp_hit else "pass",
        f"console_probe={automation.get('cdp_console_probe')}, stack_frame={automation.get('stack_automation_frame')}",
        "无 CDP 远程调试序列化副作用或自动化栈帧",
        25.0 if cdp_hit else 0.0,
        "命中 CDP Runtime.enable console.debug 序列化陷阱或自动化框架调用栈帧" if cdp_hit else "未触发 CDP 调试协议特征",
        "CDP_MARKER",
    )

    # 1.13 Iframe 跨 Realm 一致性
    iframe_bad = bool(automation.get("iframe_mismatch", False))
    add_check(
        "iframe_cross_realm",
        "sannysoft",
        "Sannysoft / Stealth",
        "Iframe 跨 Realm 原型一致性",
        "fail" if iframe_bad else "pass",
        "存在跨帧差异" if iframe_bad else "完全一致",
        "新建 iframe 与主窗口属性完全一致",
        25.0 if iframe_bad else 0.0,
        "新建同源 iframe 与顶层 window 的 webdriver/plugins/permissions 不一致（单层 Stealth 补丁漏改新帧）" if iframe_bad else "多 Realm 执行上下文一致",
        "AUTOMATION_MARKER",
    )

    # 1.14 原生函数 toString 完整性
    hook_bad = bool(automation.get("hooked_native", False)) or bool(sanny.get("get_image_data_hooked", False))
    add_check(
        "native_to_string_integrity",
        "sannysoft",
        "Sannysoft",
        "原生 API toString() 完整性",
        "fail" if hook_bad else "pass",
        "偏离 [native code]" if hook_bad else "均为 [native code]",
        "fetch / XHR / getImageData 均返回 [native code]",
        25.0 if hook_bad else 0.0,
        "核心原生函数被 JS Hook 劫持且未能伪装 Function.prototype.toString" if hook_bad else "核心浏览器 API 保持原生未篡改",
        "AUTOMATION_MARKER",
    )

    # ── 维度 2：BrowserScan 环境真实性与跨维一致性 ───────────────────────────
    cons_res = evaluate_consistency(payload, norm_headers, geo)
    conflict_by_rule = {c.rule_id: c for c in cons_res.conflicts}

    # 2.1 UA vs Client Hints (HTTP + userAgentData)
    # 注意：缺失 Sec-CH-UA 已在 Network 层 http_headers 单独计分（非 HTTPS 明文环境不计分），
    # 此处仅对「实际携带了矛盾的 Sec-CH-UA 品牌」或「userAgentData.platform 矛盾」扣分，避免重复计分。
    ua_data = extra.get("user_agent_data") or {}
    ch_conflict = conflict_by_rule.get("UA_BRAND_VS_SEC_CH_UA")
    has_sec_ch_ua = bool(norm_headers.get("sec-ch-ua", "").strip())
    uad_platform_bad = False
    if isinstance(ua_data, dict) and ua_data.get("platform"):
        uad_plat = str(ua_data.get("platform")).lower()
        if "windows" in ua_lower and "win" not in uad_plat:
            uad_platform_bad = True
        elif "mac os x" in ua_lower and "mac" not in uad_plat:
            uad_platform_bad = True

    if (ch_conflict and has_sec_ch_ua) or uad_platform_bad:
        add_check(
            "ua_vs_client_hints",
            "browserscan",
            "BrowserScan",
            "UA vs Client Hints (HTTP & JS)",
            "fail",
            f"Sec-CH-UA={_short(norm_headers.get('sec-ch-ua', '<空>'), 35)}, uaData.platform={ua_data.get('platform', 'n/a')}",
            "UA、Sec-CH-UA 与 navigator.userAgentData 品牌及平台一致",
            20.0,
            (ch_conflict.message if (ch_conflict and has_sec_ch_ua) else "navigator.userAgentData.platform 与 UA 操作系统矛盾"),
            "FINGERPRINT_CONFLICT",
        )
    elif non_secure_http and not has_sec_ch_ua:
        add_check(
            "ua_vs_client_hints",
            "browserscan",
            "BrowserScan",
            "UA vs Client Hints (HTTP & JS)",
            "info",
            "Non-Secure HTTP (未发送 Client Hints)",
            "HTTPS / localhost 下自动校验 Sec-CH-UA 与 userAgentData",
            0.0,
            "当前为非 HTTPS 公网明文 HTTP，浏览器按规范不发送 Sec-CH-UA / userAgentData，不扣分",
        )
    elif ch_conflict and not has_sec_ch_ua:
        add_check(
            "ua_vs_client_hints",
            "browserscan",
            "BrowserScan",
            "UA vs Client Hints (HTTP & JS)",
            "warn",
            "Sec-CH-UA=<缺失>",
            "Chromium 安全上下文应携带 Sec-CH-UA",
            0.0,
            "缺失 Sec-CH-UA 已在 Network 层计分，此处不再重复扣分",
        )
    else:
        add_check(
            "ua_vs_client_hints",
            "browserscan",
            "BrowserScan",
            "UA vs Client Hints (HTTP & JS)",
            "pass",
            f"uaData.platform={ua_data.get('platform', 'n/a')}",
            "Client Hints 与 UA 保持一致",
            0.0,
            "HTTP Sec-CH-UA 与 JS userAgentData 与 UA 声明一致",
        )

    # 2.2 OS × Platform × WebGL 三角校验
    tri_rules = [conflict_by_rule[r] for r in ("UA_OS_VS_PLATFORM", "UA_OS_VS_WEBGL") if r in conflict_by_rule]
    add_check(
        "os_platform_webgl_triangulation",
        "browserscan",
        "BrowserScan",
        "OS × Platform × WebGL 三角一致性",
        "fail" if tri_rules else "pass",
        f"platform={payload.get('platform')}, renderer={_short(webgl_renderer, 36)}",
        "UA OS、navigator.platform 与显卡驱动三者同属同一硬件生态",
        float(len(tri_rules) * 20),
        "；".join(r.message for r in tri_rules) if tri_rules else "操作系统、Platform 与 WebGL 驱动生态完全匹配",
        "FINGERPRINT_CONFLICT",
    )

    # 2.3 IP 地理归属 vs 时区 & 2.4 时区名称 vs 分钟偏移
    tz_geo_cf = conflict_by_rule.get("GEO_IP_VS_TIMEZONE")
    add_check(
        "ip_geo_vs_timezone",
        "browserscan",
        "BrowserScan",
        "IP 地理归属 vs 前端时区",
        "fail" if tz_geo_cf else "pass",
        f"{geo.country}/{geo.city} vs {payload.get('timezone')}",
        "出口 IP 所在国家与浏览器时区一致",
        20.0 if tz_geo_cf else 0.0,
        tz_geo_cf.message if tz_geo_cf else "IP 地理归属与 Intl 时区匹配",
        "FINGERPRINT_CONFLICT",
    )

    tz_off_cf = conflict_by_rule.get("ENHANCED_TZ_OFFSET_MISMATCH")
    add_check(
        "timezone_name_vs_offset",
        "browserscan",
        "BrowserScan",
        "Intl 时区名 vs Date.getTimezoneOffset()",
        "fail" if tz_off_cf else "pass",
        f"tz={payload.get('timezone')}, offset={extra.get('timezone_offset')}",
        "时区名称与分钟偏移量严格对应",
        20.0 if tz_off_cf else 0.0,
        tz_off_cf.message if tz_off_cf else "时区名称与系统时间偏移量一致",
        "FINGERPRINT_CONFLICT",
    )

    # 2.5 IP 归属 vs 语言
    lang_geo_cf = conflict_by_rule.get("GEO_IP_VS_LANGUAGE")
    add_check(
        "ip_geo_vs_language",
        "browserscan",
        "BrowserScan",
        "IP 归属地 vs 首选语言",
        "warn" if lang_geo_cf else "pass",
        f"{geo.country} vs {languages[:2]}",
        "归属地与首选语言无长期互斥矛盾",
        15.0 if lang_geo_cf else 0.0,
        lang_geo_cf.message if lang_geo_cf else "语言环境与地域归属相容",
        "FINGERPRINT_CONFLICT",
    )

    # 2.6 Web Worker 跨线程一致性
    worker_cf = conflict_by_rule.get("ENHANCED_WORKER_NAVIGATOR_MISMATCH") or conflict_by_rule.get("ENHANCED_WORKER_CORES_MISMATCH")
    add_check(
        "worker_cross_thread",
        "browserscan",
        "BrowserScan",
        "Web Worker 跨线程一致性",
        "fail" if worker_cf else "pass",
        "存在跨线程矛盾" if worker_cf else "主线程与 Worker 一致",
        "Blob Worker 内 self.navigator 与主线程完全相同",
        25.0 if worker_cf else 0.0,
        worker_cf.message if worker_cf else "Web Worker 线程与主线程指纹参数完全一致",
        "FINGERPRINT_CONFLICT",
    )

    # 2.7 JS Math 浮点内核指纹
    math_cf = conflict_by_rule.get("ENHANCED_MATH_ENGINE_MISMATCH")
    add_check(
        "js_math_engine",
        "browserscan",
        "BrowserScan",
        "JS 引擎 Math 浮点签名",
        "fail" if math_cf else "pass",
        _short((extra.get("math_fp") or {}).get("tan", "n/a"), 26),
        "数学函数尾数特征与 UA 声明引擎（V8/SpiderMonkey）匹配",
        20.0 if math_cf else 0.0,
        math_cf.message if math_cf else "Math 浮点引擎特征与浏览器内核匹配",
        "FINGERPRINT_CONFLICT",
    )

    # 2.8 窗口尺寸与无头 outerWidth=0 检查
    win_dims = extra.get("window_dims") or {}
    scr = payload.get("screen") or {}
    outer_w = int(win_dims.get("outerWidth", 1))
    outer_h = int(win_dims.get("outerHeight", 1))
    scr_w = int(scr.get("width") or 0)
    avail_w = int(scr.get("availWidth") or 0)
    dim_bad = (outer_w == 0 or outer_h == 0) or (scr_w > 0 and avail_w > scr_w)
    add_check(
        "window_outer_dimensions",
        "browserscan",
        "BrowserScan",
        "Window 外框与屏幕尺寸合理性",
        "fail" if dim_bad else "pass",
        f"outer={outer_w}x{outer_h}, screen={scr_w}x{scr.get('height', 0)}",
        "outerWidth/outerHeight > 0 且 availWidth <= screen.width",
        20.0 if dim_bad else 0.0,
        "检测到 outerWidth/outerHeight 为 0 或可用宽大于物理屏宽（典型无头浏览器虚拟屏漏洞）" if dim_bad else "窗口外框与屏幕几何参数正常",
        "AUTOMATION_MARKER",
    )

    # 2.9 硬件并发核数 / 内存 / 触控合理性
    cores = int(payload.get("hardware_concurrency") or 0)
    mem = float(payload.get("device_memory") or 0)
    hw_cf = conflict_by_rule.get("PLATFORM_VS_SCREEN_TOUCH") or conflict_by_rule.get("TOUCH_VS_MOBILE_UA")
    hw_weird = bool(hw_cf) or (cores == 0)
    add_check(
        "hardware_sanity",
        "browserscan",
        "BrowserScan",
        "CPU 核数 / 内存 / 触控一致性",
        "warn" if hw_weird else "pass",
        f"cores={cores}, mem={mem}GB, touch={payload.get('touch_points')}",
        "cores > 0 且设备类型与触控点数匹配",
        15.0 if hw_weird else 0.0,
        (hw_cf.message if hw_cf else "hardwareConcurrency=0，疑似被屏蔽或伪造硬件参数") if hw_weird else "硬件配置档位与触控能力合理",
        "FINGERPRINT_CONFLICT",
    )

    # ── 维度 3：BrowserLeaks 图形、隐私与硬件泄露审计 ───────────────────────
    # 3.1 Canvas 双渲染防噪点
    canvas_noise_cf = conflict_by_rule.get("ENHANCED_CANVAS_NOISE_POISONING")
    canvas_blocked = str(payload.get("canvas_hash") or "") == "canvas_blocked"
    canvas_bad = bool(canvas_noise_cf) or canvas_blocked
    add_check(
        "canvas_noise_poisoning",
        "browserleaks",
        "BrowserLeaks",
        "Canvas 2D 指纹与加噪检测",
        "fail" if canvas_noise_cf else ("warn" if canvas_blocked else "pass"),
        "随机加噪漂移" if canvas_noise_cf else ("被屏蔽" if canvas_blocked else _short(payload.get("canvas_hash"), 16)),
        "同场景双次渲染哈希完全一致",
        25.0 if canvas_noise_cf else (12.0 if canvas_blocked else 0.0),
        "两次同场景 Canvas 渲染哈希不一致，识破防指纹随机加噪插件"
        if canvas_noise_cf
        else ("Canvas 读取被阻止（canvas_blocked）" if canvas_blocked else "Canvas 渲染管线稳定无噪点投毒"),
        "FINGERPRINT_CONFLICT",
    )

    # 3.2 WebGL 扩展数与纹理上限
    bl = extra.get("browserleaks") or {}
    gl_ext_cnt = bl.get("webgl_extensions_count")
    gl_max_tex = bl.get("webgl_max_texture_size")
    gl_weak = (gl_ext_cnt is not None and int(gl_ext_cnt) < 8) or (gl_max_tex is not None and int(gl_max_tex) < 2048)
    add_check(
        "webgl_params_and_extensions",
        "browserleaks",
        "BrowserLeaks",
        "WebGL 扩展数与纹理参数",
        "warn" if gl_weak else "pass",
        f"ext={gl_ext_cnt if gl_ext_cnt is not None else 'n/a'}, maxTex={gl_max_tex if gl_max_tex is not None else 'n/a'}",
        "WebGL 扩展 >= 8 且 MAX_TEXTURE_SIZE >= 2048",
        10.0 if gl_weak else 0.0,
        "WebGL 支持扩展数量或最大纹理尺寸过低，疑似虚拟化容器环境" if gl_weak else "WebGL 扩展矩阵与显卡纹理能力正常",
        "WEBGL_MASKED",
    )

    # 3.3 OfflineAudioContext 音频指纹
    audio_blocked = str(payload.get("audio_hash") or "") == "audio_blocked"
    add_check(
        "audio_context_fingerprint",
        "browserleaks",
        "BrowserLeaks",
        "OfflineAudioContext 音频指纹",
        "warn" if audio_blocked else "pass",
        "audio_blocked" if audio_blocked else _short(payload.get("audio_hash"), 16),
        "正常输出确定性音频混音摘要",
        10.0 if audio_blocked else 0.0,
        "OfflineAudioContext 音频输出被阻断或不可用" if audio_blocked else "音频信号管线可用",
        "FINGERPRINT_CONFLICT",
    )

    # 3.4 字体库与 OS 合理性
    fonts_obj = payload.get("fonts") or {}
    font_list = [str(f) for f in (fonts_obj.get("detected") or [])]
    font_cnt = int(fonts_obj.get("count") or len(font_list))
    font_bad = font_cnt == 0
    if "windows" in ua_lower and font_cnt > 0:
        if not any(f in font_list for f in ("Arial", "Segoe UI", "Microsoft YaHei", "Consolas", "SimSun", "Calibri")):
            font_bad = True
    add_check(
        "fonts_os_plausibility",
        "browserleaks",
        "BrowserLeaks",
        "系统字体枚举与 OS 匹配度",
        "warn" if font_bad else "pass",
        f"命中 {font_cnt} 个字体 ({', '.join(font_list[:4])})",
        "命中常见系统字体且与声明 OS 生态匹配",
        15.0 if font_bad else 0.0,
        "未检出有效系统字体或与声明的操作系统核心字体库不匹配（常见于 Linux 无头容器伪装）"
        if font_bad
        else "已安装字体集合与操作系统生态吻合",
        "FINGERPRINT_CONFLICT",
    )

    # 3.5 ClientRects 双测量亚像素噪点检测
    cr_h1 = str(bl.get("client_rects_hash") or "")
    cr_h2 = str(bl.get("client_rects_hash_2") or "")
    cr_noise = bool(cr_h1 and cr_h2 and cr_h1 != cr_h2)
    add_check(
        "client_rects_subpixel_noise",
        "browserleaks",
        "BrowserLeaks",
        "ClientRects 亚像素噪点检测",
        "fail" if cr_noise else "pass",
        "两次测量漂移" if cr_noise else (cr_h1[:16] if cr_h1 else "未上报"),
        "同 DOM 元素两次 getBoundingClientRect() 精确相等",
        20.0 if cr_noise else 0.0,
        "DOMRect 两次渲染返回不同亚像素坐标，检测到反指纹插件对 ClientRects 注入随机抖动"
        if cr_noise
        else "ClientRects 亚像素几何排版稳定",
        "FINGERPRINT_CONFLICT",
    )

    # 3.6 WebRTC STUN 穿透泄露与国内外分流检测（越过 HTTP 代理 / 规则分流 VPN 的强对抗手段）
    webrtc_obj = extra.get("webrtc") or {}
    cands = list(webrtc_obj.get("candidates") or [])
    public_stun_ips = [str(ip) for ip in (webrtc_obj.get("publicIps") or []) if str(ip).strip()]
    leaked_stun = [ip for ip in public_stun_ips if ip != geo.ip]
    ip_channels = extra.get("ip_channels") or {}
    overseas_ip = str(ip_channels.get("overseas_echo_ip") or "").strip()
    split_tunnel = bool(overseas_ip and geo.ip and overseas_ip != geo.ip and not geo.ip.startswith("127."))

    if leaked_stun:
        add_check(
            "webrtc_ice_leak",
            "browserleaks",
            "BrowserLeaks / STUN",
            "WebRTC UDP STUN 穿透真实 IP 泄露",
            "fail",
            f"HTTP={geo.ip} vs STUN={leaked_stun[0]}",
            "WebRTC 公网候选与 HTTP 出口一致或被 mDNS 掩码",
            35.0,
            f"WebRTC UDP STUN 穿透代理/VPN 捕获到不同的真实公网 IP（{leaked_stun[0]}），表明存在未代理的 UDP 流量泄露",
            "FINGERPRINT_CONFLICT",
        )
    elif split_tunnel:
        add_check(
            "webrtc_ice_leak",
            "browserleaks",
            "BrowserScan / Split-Tunnel",
            "多信道规则分流（VPN 出口不一致）",
            "fail",
            f"Direct={geo.ip} vs Overseas={overseas_ip}",
            "国内外请求出口 IP 应保持一致",
            30.0,
            f"直连出口（{geo.ip}）与海外探测出口（{overseas_ip}）不一致，识破规则分流型代理/VPN",
            "FINGERPRINT_CONFLICT",
        )
    else:
        add_check(
            "webrtc_ice_leak",
            "browserleaks",
            "BrowserLeaks",
            "WebRTC ICE 候选与 mDNS 状态",
            "info",
            f"supported={webrtc_obj.get('supported')}, mdns={webrtc_obj.get('mdnsMasked')}, stun_ips={len(public_stun_ips)}, cands={len(cands)}",
            "现代浏览器采用 mDNS (.local) 掩码且无跨代理泄露",
            0.0,
            "未检测到 WebRTC STUN 跨代理真实 IP 泄露或规则分流差异",
        )

    # 3.7 MediaDevices 硬件设备数量
    media_cnt = bl.get("media_devices_count")
    media_empty = media_cnt is not None and int(media_cnt) == 0
    add_check(
        "media_devices_probe",
        "browserleaks",
        "BrowserLeaks",
        "MediaDevices 音视频设备枚举",
        "warn" if media_empty else "pass",
        f"devices={media_cnt if media_cnt is not None else 'n/a'}",
        "普通终端通常至少存在 1 个默认输入或输出设备",
        8.0 if media_empty else 0.0,
        "navigator.mediaDevices.enumerateDevices() 返回 0 个设备，常见于无硬件容器/Docker 无头浏览器"
        if media_empty
        else "检测到可用的媒体设备枚举信息",
        "AUTOMATION_MARKER",
    )

    # 3.8 SpeechSynthesis 语音引擎数
    voices_cnt = bl.get("speech_voices_count")
    voices_empty = voices_cnt is not None and int(voices_cnt) == 0
    add_check(
        "speech_voices_probe",
        "browserleaks",
        "BrowserLeaks",
        "SpeechSynthesis 系统语音列表",
        "warn" if voices_empty else "pass",
        f"voices={voices_cnt if voices_cnt is not None else 'n/a'}",
        "桌面操作系统通常提供本地 TTS 语音包",
        5.0 if voices_empty else 0.0,
        "speechSynthesis.getVoices() 返回空列表（轻量告警：无头 Linux 容器常见，亦可能因首帧异步加载未就绪）"
        if voices_empty
        else "系统 TTS 语音列表正常加载",
        "AUTOMATION_MARKER",
    )

    # 3.9 CSS 媒体查询 pointer/hover 与设备类型一致
    css_media = extra.get("css_media") or {}
    pointer_fine = css_media.get("pointer_fine")
    is_mobile = any(k in ua_lower for k in ("iphone", "ipad", "android", "mobile"))
    css_bad = (not is_mobile and pointer_fine is False and int(payload.get("touch_points") or 0) == 0)
    add_check(
        "css_media_coherence",
        "browserleaks",
        "BrowserLeaks",
        "CSS pointer/hover 媒体查询匹配",
        "warn" if css_bad else "pass",
        f"pointer_fine={pointer_fine}, hover={css_media.get('hover_hover')}",
        "桌面端应匹配 (pointer: fine)",
        10.0 if css_bad else 0.0,
        "桌面端 UA 下不支持精细指针 (pointer: fine)，与触控设备参数不一致" if css_bad else "CSS 交互媒体查询与终端类型吻合",
        "FINGERPRINT_CONFLICT",
    )

    # ── 维度 5：Behavior（行为动力学，可选随请求附带）────────────────────────
    beh_payload = payload.get("behavior")
    has_behavior = isinstance(beh_payload, dict) and (
        bool(beh_payload.get("points")) or bool(beh_payload.get("keys")) or bool(beh_payload.get("scrolls")) or beh_payload.get("page_seconds") is not None
    )
    if has_behavior:
        beh_res = evaluate_behavior(beh_payload)
        if beh_res.score > 0:
            add_check(
                "behavior_telemetry",
                "behavior",
                "Behavior Engine",
                "交互轨迹、可信事件与停留动力学",
                "fail" if beh_res.score >= 30 else "warn",
                f"pts={beh_res.metrics.get('point_count')}, trusted={beh_res.metrics.get('trusted_ratio')}, dir={beh_res.metrics.get('direction_changes')}",
                "自然轨迹 >=30 点、isTrusted=100%、停留 >=2s",
                float(beh_res.score),
                "；".join(beh_res.details),
                reason_code=beh_res.flags[0] if beh_res.flags else "BOT_TRAJECTORY",
            )
        else:
            add_check(
                "behavior_telemetry",
                "behavior",
                "Behavior Engine",
                "交互轨迹、可信事件与停留动力学",
                "pass",
                f"pts={beh_res.metrics.get('point_count')}, trusted=100%, dir={beh_res.metrics.get('direction_changes')}",
                "人类自然交互动力学基线",
                0.0,
                "交互事件全部为原生可信事件，轨迹曲率与速度波动自然",
            )
    else:
        add_check(
            "behavior_telemetry",
            "behavior",
            "Behavior Engine",
            "交互轨迹、可信事件与停留动力学",
            "info",
            "未附带交互样本",
            "移动鼠标或输入后提交",
            0.0,
            "本次检测未附带交互轨迹数据（仅基于静态与环境探针评分）",
        )

    # ── 汇总计算置信分与结论 ──────────────────────────────────────────────────
    raw_sum = sum(c.risk_delta for c in checks)
    bot_confidence = min(100.0, round(raw_sum, 1))
    human_confidence = round(100.0 - bot_confidence, 1)

    if bot_confidence >= 55.0:
        verdict = "likely_bot"
        verdict_label = "高概率机器人 / 自动化伪装环境"
    elif bot_confidence >= 25.0:
        verdict = "suspicious"
        verdict_label = "存在可疑环境破绽或隐私屏蔽异常"
    else:
        verdict = "likely_human"
        verdict_label = "高概率真实人类浏览器"

    confidence_level = "high" if has_behavior else "medium"
    reasons_out.sort(key=lambda x: x["weight"], reverse=True)

    failed_cnt = sum(1 for c in checks if c.status == "fail")
    warn_cnt = sum(1 for c in checks if c.status == "warn")
    pass_cnt = sum(1 for c in checks if c.status == "pass")

    summary = (
        f"共审计 {len(checks)} 项指标（通过 {pass_cnt} · 警告 {warn_cnt} · 异常 {failed_cnt}），"
        f"机器人置信分 {bot_confidence}%（真实度 {human_confidence}%）。"
    )

    return BotAssessment(
        bot_confidence=bot_confidence,
        human_confidence=human_confidence,
        verdict=verdict,
        verdict_label=verdict_label,
        confidence_level=confidence_level,
        summary=summary,
        category_scores=cat_scores,
        reasons=reasons_out,
        checks=[c.to_dict() for c in checks],
        telemetry_coverage={
            "mode": "full_audit" if has_behavior else "fingerprint_audit",
            "checked_items": len(checks),
            "pass_count": pass_cnt,
            "warn_count": warn_cnt,
            "fail_count": failed_cnt,
        },
    )
