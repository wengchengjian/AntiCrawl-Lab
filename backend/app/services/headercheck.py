"""
HTTP 请求头、JA4 TLS 指纹与请求头顺序校验服务（headercheck.py，模块一）。

检测什么：
1. 缺失 User-Agent / 命中已知自动化 HTTP 库关键词（python-requests、curl、Go-http-client、HeadlessChrome 等）。
2. 条件规则：Chromium 系 UA 缺失 Sec-CH-UA，或 Sec-CH-UA 品牌与 UA 矛盾（非 Chromium 浏览器不误杀）。
3. 缺失 Accept-Language。
4. 增强规则（8.5 可选扩展）：X-JA4 TLS 指纹库交叉验证与 X-Header-Order 浏览器头顺序基线。
为什么可疑：
- 原生 HTTP 客户端默认 User-Agent 会暴露脚本栈，手工伪造 Chrome UA 时常遗漏 Sec-CH-UA 客户端提示或保留 Python/Go 的 TLS JA4 握手特征。
阈值依据：
- 严格对齐 6.2 权重表：UA 缺失 +40、工具特征 +35、Chromium 缺 Sec-CH-UA +20、Sec-CH-UA 矛盾 +25、缺 Accept-Language +15；
- JA4 异常/冲突附加 +20（HEADER_INCONSISTENT），Header 顺序异常附加 +10（HEADER_INCONSISTENT）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Mapping

from app.constants import ReasonCode, SCORE_WEIGHTS

# 已知爬虫/脚本/无头客户端特征（小写子串匹配）
KNOWN_BOT_UA_MARKERS: tuple[str, ...] = (
    "python-requests",
    "python-urllib",
    "curl/",
    "wget/",
    "go-http-client",
    "headlesschrome",
    "scrapy",
    "aiohttp",
    "httpx",
    "apache-httpclient",
    "okhttp",
    "phantomjs",
    "node-fetch",
    "axios/",
    "libwww-perl",
)

# 内置常见 JA4 TLS 指纹特征字典（用于 8.5 可选扩展演练）
KNOWN_BOT_JA4_PREFIXES: dict[str, str] = {
    "t13d1516h2_8daaf6152771_b0da82dd1658": "python-requests / OpenSSL",
    "t13d1715h2_5b57614c22b0_3d5424432f57": "curl / libcurl",
    "t13d1311h2_a09f3c656075_14788d8d241b": "Go net/http",
}

CHROME_LIKE_JA4_PREFIX = "t13d1516h2_"
FIREFOX_LIKE_JA4_PREFIX = "t13d1715h2_"


@dataclass
class HeaderCheckResult:
    """Header 校验结构化输出。"""

    score: int = 0
    reasons: List[str] = field(default_factory=list)
    details: List[str] = field(default_factory=list)
    is_chromium_ua: bool = False
    sec_ch_ua_brands: List[str] = field(default_factory=list)


def is_chromium_user_agent(ua: str) -> bool:
    """
    判断 UA 是否声明为桌面/移动 Chromium 内核浏览器（Chrome/Edg/OPR/Chromium/Brave）。
    注：排除 iOS CriOS 与 Firefox/Safari，以免触发非 Chromium 误判。
    """
    lower = ua.lower()
    if "firefox/" in lower or "crios/" in lower or "fxios/" in lower:
        return False
    if "safari/" in lower and "chrome/" not in lower and "chromium/" not in lower and "edg/" not in lower:
        return False
    return any(token in lower for token in ("chrome/", "chromium/", "edg/", "opr/", "brave/"))


def extract_sec_ch_ua_brands(sec_ch_ua: str) -> List[str]:
    """解析 Sec-CH-UA 头中的品牌名称列表。"""
    return re.findall(r'"([^"]+)"\s*;\s*v="[^"]+"', sec_ch_ua)


def is_non_secure_http_context(headers: Mapping[str, str]) -> bool:
    """
    判断请求是否来自非 HTTPS 的公网/局域网明文 HTTP 环境（Non-Secure Context）。

    检测什么 / 为什么需要：
    - 依据 W3C Secure Contexts 与 Client Hints / Fetch Metadata 规范，Chromium 浏览器仅在
      `https://` 或 `http://localhost` / `http://127.0.0.1` 下才会发送 `Sec-CH-UA` 与 `Sec-Fetch-*`。
    - 当站点通过公网 IP 明文 HTTP（如 `http://119.29.10.20:8090`）部署时，真实人类浏览器必然不发送
      这两个请求头，必须识别此场景避免误杀真实用户；启用 HTTPS 后将自动恢复严格校验。
    """
    norm = {k.lower(): v.strip() for k, v in headers.items()}
    proto = norm.get("x-forwarded-proto", "").lower()
    origin = norm.get("origin", "").lower()
    referer = norm.get("referer", "").lower()
    host_raw = norm.get("host", "").lower()

    if proto == "https" or origin.startswith("https://") or referer.startswith("https://"):
        return False

    def _extract_hostname(val: str) -> str:
        s = val
        if "://" in s:
            s = s.split("://", 1)[1]
        s = s.split("/", 1)[0]
        if s.startswith("["):
            return s.split("]", 1)[0].strip("[]")
        return s.split(":", 1)[0]

    candidate_host = _extract_hostname(origin or referer or host_raw)
    if not candidate_host or candidate_host in {"localhost", "127.0.0.1", "::1", "testserver"}:
        return False

    return proto == "http" or origin.startswith("http://") or referer.startswith("http://")


def check_headers(headers: Mapping[str, str]) -> HeaderCheckResult:
    """执行基础 + 增强 Header 检测并累加风险分（仅计分，不在此处直接拦截）。"""
    # 统一转为小写键读取，兼容 Starlette Headers 与测试字典
    norm = {k.lower(): v for k, v in headers.items()}
    ua = norm.get("user-agent", "").strip()
    sec_ch_ua = norm.get("sec-ch-ua", "").strip()
    accept_lang = norm.get("accept-language", "").strip()
    x_ja4 = norm.get("x-ja4", "").strip()
    x_header_order = norm.get("x-header-order", "").strip()

    result = HeaderCheckResult()

    # 1. 检测 User-Agent 是否缺失或命中脚本特征
    if not ua:
        result.score += SCORE_WEIGHTS["UA_MISSING"]
        result.reasons.append(ReasonCode.HEADER_MISSING.value)
        result.details.append("User-Agent 请求头缺失或为空 (+40)")
    else:
        ua_lower = ua.lower()
        matched_tool = next((m for m in KNOWN_BOT_UA_MARKERS if m in ua_lower), None)
        if matched_tool:
            result.score += SCORE_WEIGHTS["UA_TOOL_SIGNATURE"]
            result.reasons.append(ReasonCode.HEADER_INCONSISTENT.value)
            result.details.append(f"User-Agent 命中已知采集工具/无头特征 '{matched_tool}' (+35)")

    # 2. 条件规则：仅当 UA 声明 Chromium 系时要求 Sec-CH-UA，并校验品牌一致性
    is_chromium = bool(ua) and is_chromium_user_agent(ua)
    result.is_chromium_ua = is_chromium
    if sec_ch_ua:
        result.sec_ch_ua_brands = extract_sec_ch_ua_brands(sec_ch_ua)

    if is_chromium and not sec_ch_ua:
        if not is_non_secure_http_context(norm):
            result.score += SCORE_WEIGHTS["CHROMIUM_MISSING_SEC_CH_UA"]
            result.reasons.append(ReasonCode.HEADER_MISSING.value)
            result.details.append("声明为 Chromium 系 UA 但缺少 Sec-CH-UA 客户端提示头 (+20)")
    elif sec_ch_ua and ua:
        brands_lower = [b.lower() for b in result.sec_ch_ua_brands]
        ua_lower = ua.lower()
        conflict = False
        conflict_msg = ""

        # Edge UA 必须包含 Microsoft Edge 品牌
        if "edg/" in ua_lower and not any("edge" in b for b in brands_lower):
            conflict = True
            conflict_msg = "UA 声明为 Edge，但 Sec-CH-UA 品牌列表中不包含 Microsoft Edge"
        # Firefox / 纯 Safari 不应出现 Chromium/Google Chrome 的 Sec-CH-UA
        elif ("firefox/" in ua_lower or ("safari/" in ua_lower and not is_chromium)) and any(
            "chrom" in b or "edge" in b for b in brands_lower
        ):
            conflict = True
            conflict_msg = "UA 声明为非 Chromium 浏览器，却携带 Chromium 系 Sec-CH-UA 品牌"
        # Chrome UA 但 Sec-CH-UA 完全不包含 Chromium/Google Chrome/Edge/Opera
        elif is_chromium and result.sec_ch_ua_brands and not any(
            any(k in b for k in ("chrom", "edge", "opera", "brave")) for b in brands_lower
        ):
            conflict = True
            conflict_msg = "UA 声明为 Chromium 浏览器，但 Sec-CH-UA 未匹配对应浏览器品牌"

        if conflict:
            result.score += SCORE_WEIGHTS["SEC_CH_UA_MISMATCH"]
            result.reasons.append(ReasonCode.HEADER_INCONSISTENT.value)
            result.details.append(f"{conflict_msg} (+25)")

    # 3. Accept-Language 缺失校验
    if not accept_lang:
        result.score += SCORE_WEIGHTS["ACCEPT_LANGUAGE_MISSING"]
        result.reasons.append(ReasonCode.HEADER_MISSING.value)
        result.details.append("缺少 Accept-Language 首选语言头 (+15)")

    # 4. 可选扩展（8.5）：X-JA4 TLS 指纹与 UA 交叉比对
    if x_ja4:
        bot_label = KNOWN_BOT_JA4_PREFIXES.get(x_ja4)
        if bot_label:
            result.score += SCORE_WEIGHTS["JA4_ANOMALY"]
            result.reasons.append(ReasonCode.HEADER_INCONSISTENT.value)
            result.details.append(f"X-JA4 TLS 指纹命中非浏览器客户端 '{bot_label}' (+20)")
        elif ua and "firefox/" in ua.lower() and x_ja4.startswith(CHROME_LIKE_JA4_PREFIX):
            result.score += SCORE_WEIGHTS["JA4_ANOMALY"]
            result.reasons.append(ReasonCode.HEADER_INCONSISTENT.value)
            result.details.append("X-JA4 显示 Chromium TLS 栈，与 Firefox UA 矛盾 (+20)")
        elif ua and is_chromium and x_ja4.startswith(FIREFOX_LIKE_JA4_PREFIX):
            result.score += SCORE_WEIGHTS["JA4_ANOMALY"]
            result.reasons.append(ReasonCode.HEADER_INCONSISTENT.value)
            result.details.append("X-JA4 与 Chromium UA TLS 握手特征不符 (+20)")

    # 5. 可选扩展（8.5）：X-Header-Order 请求头顺序基线
    if x_header_order:
        order_tokens = [tok.strip().lower() for tok in x_header_order.split(",") if tok.strip()]
        # 脚本库常将 accept-encoding/user-agent 置于 host 之后但缺少 sec-* 现代安全头或倒置顺序
        if is_chromium and "user-agent" in order_tokens and "accept-encoding" in order_tokens:
            if order_tokens.index("accept-encoding") < order_tokens.index("user-agent") and "sec-fetch-site" not in order_tokens:
                result.score += SCORE_WEIGHTS["HEADER_ORDER_ANOMALY"]
                result.reasons.append(ReasonCode.HEADER_INCONSISTENT.value)
                result.details.append("X-Header-Order 请求头顺序偏离 Chromium 浏览器基线 (+10)")

    # 原因码去重且保序
    result.reasons = list(dict.fromkeys(result.reasons))
    return result
