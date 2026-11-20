"""
全局原因码、评分权重、行为阈值与规则元数据定义（前后端单源真相）。
所有原因码与阈值通过 GET /api/v1/health 下发 `rules_meta` 给前端，前端不得硬编码副本。
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict

from app.config import Settings


class ReasonCode(str, Enum):
    """契约 7.3 定义的 23 个标准风控原因码。"""

    RATE_LIMITED = "RATE_LIMITED"
    HEADER_MISSING = "HEADER_MISSING"
    HEADER_INCONSISTENT = "HEADER_INCONSISTENT"
    DATACENTER_IP = "DATACENTER_IP"
    BLACKLIST_IP = "BLACKLIST_IP"
    HONEYPOT_TRIGGERED = "HONEYPOT_TRIGGERED"
    BANNED = "BANNED"
    SIGNATURE_MISSING = "SIGNATURE_MISSING"
    SIGNATURE_EXPIRED = "SIGNATURE_EXPIRED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    NONCE_REUSED = "NONCE_REUSED"
    FINGERPRINT_CONFLICT = "FINGERPRINT_CONFLICT"
    FINGERPRINT_REUSE = "FINGERPRINT_REUSE"
    AUTOMATION_MARKER = "AUTOMATION_MARKER"
    CDP_MARKER = "CDP_MARKER"
    SYNTHETIC_EVENT = "SYNTHETIC_EVENT"
    BOT_TRAJECTORY = "BOT_TRAJECTORY"
    NO_INTERACTION_DEEP_ACCESS = "NO_INTERACTION_DEEP_ACCESS"
    VISIT_ORDER_VIOLATION = "VISIT_ORDER_VIOLATION"
    KEYBOARD_ROBOTIC = "KEYBOARD_ROBOTIC"
    POW_REQUIRED = "POW_REQUIRED"
    DECOY_SERVED = "DECOY_SERVED"
    WEBGL_MASKED = "WEBGL_MASKED"


class RiskAction(str, Enum):
    """风控处置动作枚举。"""

    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"
    CHALLENGE = "challenge"


class RiskModule(str, Enum):
    """四大攻防关卡与业务模块枚举。"""

    NETWORK = "network"
    FINGERPRINT = "fingerprint"
    AUTOMATION = "automation"
    BEHAVIOR = "behavior"
    BUSINESS = "business"


# 契约 6.2 评分权重表（满分 100 截断）
SCORE_WEIGHTS: Dict[str, int] = {
    "UA_MISSING": 40,
    "UA_TOOL_SIGNATURE": 35,
    "CHROMIUM_MISSING_SEC_CH_UA": 20,
    "SEC_CH_UA_MISMATCH": 25,
    "ACCEPT_LANGUAGE_MISSING": 15,
    "JA4_ANOMALY": 20,
    "HEADER_ORDER_ANOMALY": 10,
    "CADENCE_ROBOTIC": 15,
    "DATACENTER_IP": 25,
    "BLACKLIST_IP": 25,
    "FINGERPRINT_CONFLICT_PER_ITEM": 20,
    "FINGERPRINT_REUSE": 30,
    "WEBGL_MASKED": 15,
    "CANVAS_NOISE_POISON": 25,
    "WORKER_MISMATCH": 25,
    "TIMEZONE_OFFSET_MISMATCH": 20,
    "MATH_ENGINE_MISMATCH": 20,
    "WEBDRIVER_TRUE": 50,
    "CDC_OR_SELENIUM": 40,
    "CDP_MARKER": 25,
    "WINDOW_CHROME_MISSING": 15,
    "PLUGINS_EMPTY": 10,
    "HOOKED_NATIVE": 25,
    "IFRAME_MISMATCH": 25,
    "SYNTHETIC_EVENT": 40,
    "TRAJECTORY_FEW_POINTS": 20,
    "TRAJECTORY_LINEAR": 25,
    "NO_INTERACTION_DEEP_ACCESS": 30,
    "PAGE_STAY_TOO_SHORT": 15,
    "KEYBOARD_ROBOTIC": 20,
    "VISIT_ORDER_VIOLATION": 30,
}

# 契约 6.1 与 10.2 量化阈值表
DECISION_THRESHOLDS: Dict[str, int] = {
    "WARN_MIN": 40,
    "BLOCK_MIN": 70,
    "MAX_SCORE": 100,
    "FP_REUSE_IP_COUNT": 3,
}

BEHAVIOR_THRESHOLDS: Dict[str, float] = {
    "MIN_TRAJECTORY_POINTS": 30,
    "MIN_DIRECTION_CHANGES": 8,
    "MIN_VELOCITY_STD_PX_MS": 0.05,
    "MIN_PAGE_SECONDS": 2.0,
    "MIN_KEY_VARIANCE_MS2": 30.0,
    "MAX_CADENCE_CV": 0.08,
}

# 7.3 全部 23 个原因码中文释义对照表
REASON_META: Dict[str, Dict[str, Any]] = {
    ReasonCode.RATE_LIMITED.value: {
        "code": ReasonCode.RATE_LIMITED.value,
        "label": "请求频率超限",
        "description": "单 IP 或单指纹在 1 秒滑动窗口内请求次数超出阈值，触发 429 限流保护。",
        "module": RiskModule.NETWORK.value,
        "severity": "high",
    },
    ReasonCode.HEADER_MISSING.value: {
        "code": ReasonCode.HEADER_MISSING.value,
        "label": "关键请求头缺失",
        "description": "缺少 User-Agent、Accept-Language，或 Chromium 系 UA 缺少 Sec-CH-UA 客户端提示头。",
        "module": RiskModule.NETWORK.value,
        "severity": "medium",
    },
    ReasonCode.HEADER_INCONSISTENT.value: {
        "code": ReasonCode.HEADER_INCONSISTENT.value,
        "label": "请求头特征异常或矛盾",
        "description": "命中脚本客户端特征（requests/curl/HeadlessChrome 等）、Sec-CH-UA 品牌冲突、或 JA4/头顺序矛盾。",
        "module": RiskModule.NETWORK.value,
        "severity": "high",
    },
    ReasonCode.DATACENTER_IP.value: {
        "code": ReasonCode.DATACENTER_IP.value,
        "label": "机房/云代理 IP",
        "description": "effective_ip 命中云服务商或数据中心 ASN 网段（is_datacenter=1），常见于代理池或无头爬虫宿主机。",
        "module": RiskModule.NETWORK.value,
        "severity": "medium",
    },
    ReasonCode.BLACKLIST_IP.value: {
        "code": ReasonCode.BLACKLIST_IP.value,
        "label": "黑名单高危 IP",
        "description": "effective_ip 位于预设黑名单网段内，存在历史恶意采集记录。",
        "module": RiskModule.NETWORK.value,
        "severity": "high",
    },
    ReasonCode.HONEYPOT_TRIGGERED.value: {
        "code": ReasonCode.HONEYPOT_TRIGGERED.value,
        "label": "触发隐藏蜜罐陷阱",
        "description": "客户端访问了隐藏 DOM/视口外/CSS 伪元素诱捕链接或提交了隐藏表单字段，立即执行 IP 封禁。",
        "module": RiskModule.NETWORK.value,
        "severity": "critical",
    },
    ReasonCode.BANNED.value: {
        "code": ReasonCode.BANNED.value,
        "label": "IP 处于封禁期",
        "description": "当前 effective_ip 在 bans 表或缓存黑名单中处于生效封禁状态，请求被流水线首步短路拦截。",
        "module": RiskModule.NETWORK.value,
        "severity": "critical",
    },
    ReasonCode.SIGNATURE_MISSING.value: {
        "code": ReasonCode.SIGNATURE_MISSING.value,
        "label": "接口签名头缺失",
        "description": "核心数据接口缺少 X-Signature、X-Timestamp 或 X-Nonce 请求头。",
        "module": RiskModule.BUSINESS.value,
        "severity": "high",
    },
    ReasonCode.SIGNATURE_EXPIRED.value: {
        "code": ReasonCode.SIGNATURE_EXPIRED.value,
        "label": "接口签名已过期",
        "description": "X-Timestamp 与服务端当前时间差超出 ±120s 允许时间窗。",
        "module": RiskModule.BUSINESS.value,
        "severity": "high",
    },
    ReasonCode.SIGNATURE_INVALID.value: {
        "code": ReasonCode.SIGNATURE_INVALID.value,
        "label": "接口签名校验失败",
        "description": "HMAC-SHA256 摘要与请求方法、路径、时间戳、Nonce 计算结果不一致。",
        "module": RiskModule.BUSINESS.value,
        "severity": "high",
    },
    ReasonCode.NONCE_REUSED.value: {
        "code": ReasonCode.NONCE_REUSED.value,
        "label": "Nonce 重放攻击",
        "description": "相同的 X-Nonce 在去重窗口（300s）内被重复提交，拦截重放抓包请求。",
        "module": RiskModule.BUSINESS.value,
        "severity": "critical",
    },
    ReasonCode.FINGERPRINT_CONFLICT.value: {
        "code": ReasonCode.FINGERPRINT_CONFLICT.value,
        "label": "环境指纹一致性破绽",
        "description": "UA/Platform/WebGL/时区/语言/屏幕/Worker/数学浮点等维度存在自相矛盾的伪装破绽。",
        "module": RiskModule.FINGERPRINT.value,
        "severity": "high",
    },
    ReasonCode.FINGERPRINT_REUSE.value: {
        "code": ReasonCode.FINGERPRINT_REUSE.value,
        "label": "多 IP 复用同一指纹",
        "description": "同一 fp_id（Canvas+Audio 复合哈希）在 ≥3 个不同 effective_ip 下出现，命中指纹浏览器换 IP 特征。",
        "module": RiskModule.FINGERPRINT.value,
        "severity": "high",
    },
    ReasonCode.AUTOMATION_MARKER.value: {
        "code": ReasonCode.AUTOMATION_MARKER.value,
        "label": "自动化框架注入痕迹",
        "description": "命中 navigator.webdriver、getter 篡改、$cdc_ 变量、Selenium 属性、iframe 跨帧不一致或原生函数 Hook。",
        "module": RiskModule.AUTOMATION.value,
        "severity": "critical",
    },
    ReasonCode.CDP_MARKER.value: {
        "code": ReasonCode.CDP_MARKER.value,
        "label": "CDP 调试协议探针命中",
        "description": "Runtime.enable 序列化触发 console.debug 探针或权限/堆栈暴露远程调试特征。",
        "module": RiskModule.AUTOMATION.value,
        "severity": "high",
    },
    ReasonCode.SYNTHETIC_EVENT.value: {
        "code": ReasonCode.SYNTHETIC_EVENT.value,
        "label": "脚本合成假事件",
        "description": "鼠标/键盘/滚动事件中存在 isTrusted=false，判定为页面内 dispatchEvent 等脚本模拟交互。",
        "module": RiskModule.BEHAVIOR.value,
        "severity": "critical",
    },
    ReasonCode.BOT_TRAJECTORY.value: {
        "code": ReasonCode.BOT_TRAJECTORY.value,
        "label": "机械鼠标轨迹或极短停留",
        "description": "轨迹点数 <30、方向变化 <8、速度标准差 <0.05 px/ms 或页面停留 <2s。",
        "module": RiskModule.BEHAVIOR.value,
        "severity": "high",
    },
    ReasonCode.NO_INTERACTION_DEEP_ACCESS.value: {
        "code": ReasonCode.NO_INTERACTION_DEEP_ACCESS.value,
        "label": "零交互直奔深层接口",
        "description": "鼠标/键盘/滚动事件总数为 0 即直接请求敏感数据接口。",
        "module": RiskModule.BEHAVIOR.value,
        "severity": "high",
    },
    ReasonCode.VISIT_ORDER_VIOLATION.value: {
        "code": ReasonCode.VISIT_ORDER_VIOLATION.value,
        "label": "访问路径顺序违规",
        "description": "会话未先经首页 / 与列表页 /api/v1/products 导航而直接拉取单品价格接口。",
        "module": RiskModule.BEHAVIOR.value,
        "severity": "high",
    },
    ReasonCode.KEYBOARD_ROBOTIC.value: {
        "code": ReasonCode.KEYBOARD_ROBOTIC.value,
        "label": "键盘节律机械均匀",
        "description": "表单场景击键间隔方差 <30 ms²，远低于人类打字自然波动范围。",
        "module": RiskModule.BEHAVIOR.value,
        "severity": "medium",
    },
    ReasonCode.POW_REQUIRED.value: {
        "code": ReasonCode.POW_REQUIRED.value,
        "label": "触发 PoW 算力挑战",
        "description": "风险分处于 40–69 灰区且访问敏感价格接口，需完成 SHA-256 前导零工作量证明。",
        "module": RiskModule.BUSINESS.value,
        "severity": "medium",
    },
    ReasonCode.DECOY_SERVED.value: {
        "code": ReasonCode.DECOY_SERVED.value,
        "label": "已投喂掺假诱饵数据",
        "description": "会话风险分 ≥40，服务端返回假价格与假 SKU 诱饵以污染自动化采集结果。",
        "module": RiskModule.BUSINESS.value,
        "severity": "medium",
    },
    ReasonCode.WEBGL_MASKED.value: {
        "code": ReasonCode.WEBGL_MASKED.value,
        "label": "WebGL 掩码或软渲染器",
        "description": "WebGL 调试扩展被禁用掩码或渲染器为 SwiftShader/llvmpipe 等无头软渲染器。",
        "module": RiskModule.FINGERPRINT.value,
        "severity": "medium",
    },
}


def build_rules_meta(settings: Settings) -> Dict[str, Any]:
    """生成前后端共享的规则元数据，经由 /api/v1/health 下发。"""
    return {
        "reasons": REASON_META,
        "weights": SCORE_WEIGHTS,
        "decision_thresholds": DECISION_THRESHOLDS,
        "behavior_thresholds": BEHAVIOR_THRESHOLDS,
        "runtime_limits": {
            "rate_limit_qps": settings.rate_limit_qps,
            "fp_rate_limit_qps": settings.fp_rate_limit_qps,
            "ban_seconds": settings.ban_seconds,
            "sign_window_seconds": settings.sign_window_seconds,
            "nonce_ttl_seconds": settings.nonce_ttl_seconds,
            "pow_difficulty": settings.pow_difficulty,
            "data_retention_days": settings.data_retention_days,
        },
        "rate_limit_tiers": {
            "public": {
                "burst": settings.public_bucket_burst,
                "replenish_rate": settings.public_bucket_rate,
                "desc": "普通业务域（商品列表、字体、探针）",
            },
            "sensitive": {
                "burst": settings.sensitive_bucket_burst,
                "replenish_rate": settings.sensitive_bucket_rate,
                "desc": "高敏业务域（单品底价、PoW 挑战、WAF 保护流）",
            },
        },
        "browse_quota": {
            "max_anon_page": settings.anon_max_page,
            "max_anon_views": settings.anon_max_views,
        },
        "waf_challenge": {
            "param_name": "timestamp__1366",
            "ttl_seconds": 60,
        },
        "bot_check_categories": [
            {"id": "sannysoft", "label": "Sannysoft 自动化与无头核验"},
            {"id": "browserscan", "label": "BrowserScan 环境真实性与一致性"},
            {"id": "browserleaks", "label": "BrowserLeaks 图形与隐私泄露审计"},
            {"id": "network", "label": "网络与协议层信号"},
            {"id": "behavior", "label": "行为与交互动力学"},
        ],
        "pipeline_steps": [
            {"step": 1, "name": "封禁检查", "desc": "bans 表 + 缓存黑名单，命中直接 403 BANNED"},
            {"step": 2, "name": "限流检测", "desc": "IP 滑动窗口 + 指纹维度限流，超限 429 RATE_LIMITED"},
            {"step": 3, "name": "Header 校验", "desc": "UA/Sec-CH-UA/Accept-Language/JA4/头顺序计分"},
            {"step": 4, "name": "IP 信誉", "desc": "mock 库住宅/机房/黑名单段识别与计分"},
            {"step": 5, "name": "蜜罐标记", "desc": "检查是否曾触发隐藏陷阱并累加告警"},
            {"step": 6, "name": "签名校验", "desc": "核心数据接口强制 HMAC-SHA256 + Nonce 去重（失败 401）"},
            {"step": 7, "name": "风险决策", "desc": "<40 放行 / 40–69 警告(诱饵+PoW) / ≥70 拦截"},
            {"step": 8, "name": "落库与广播", "desc": "写入 SQLite risk_logs 并经 SSE 实时推送至仪表盘"},
        ],
    }
