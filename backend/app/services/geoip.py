"""
IP 归属地与信誉检测服务（geoip.py，模块一）。

检测什么：
- 解析有效 IP（LAB_MODE=1 时优先读取 X-Simulated-IP，LAB_MODE=0 时严格忽略模拟头）。
- 查询本地 ip_geo_mock 库识别机房/云厂商代理 IP 与黑名单网段，同时为模块二跨维校验提供国家/城市归属。
为什么可疑：
- 真实个人消费者多处于家庭宽带 ASN 下；高频采集器往往托管在 AWS/GCP/阿里云等数据中心（is_datacenter=1）或已知恶意池。
阈值依据：
- 命中机房网段计 +25 分（DATACENTER_IP），命中黑名单段计 +25 分（BLACKLIST_IP），与提示词第 6.2 节权重表对齐。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Mapping, Optional, Tuple

from sqlalchemy.orm import Session

from app.constants import ReasonCode, SCORE_WEIGHTS
from app.models.tables import IpGeoMock
from app.services.cn_cloud_ranges import match_cn_cloud_by_cidr


@dataclass(frozen=True)
class GeoInfo:
    """IP 地理与信誉查询结果。"""

    ip: str
    country: str
    city: str
    asn: str
    is_datacenter: bool
    is_blacklist: bool
    is_simulated: bool
    score: int
    reasons: List[str]


class GeoIPProvider(ABC):
    """GeoIP 提供者抽象接口（预留公网部署切换 IP2Location / MaxMind 真实库）。"""

    @abstractmethod
    def lookup(self, db: Session, ip: str, is_simulated: bool = False) -> GeoInfo:
        """查询指定 IP 的地理归属与风险分。"""


class MockGeoIPProvider(GeoIPProvider):
    """基于 SQLite ip_geo_mock 表的前缀最长匹配本地演练实现。"""

    def lookup(self, db: Session, ip: str, is_simulated: bool = False) -> GeoInfo:
        records = db.query(IpGeoMock).all()
        matched: Optional[IpGeoMock] = None
        best_len = -1
        for rec in records:
            if ip.startswith(rec.ip_prefix) and len(rec.ip_prefix) > best_len:
                matched = rec
                best_len = len(rec.ip_prefix)

        if matched is None:
            # 二级离线兜底：匹配国内主流云厂商核心公网 CIDR 段（阿里云/腾讯云/华为云/火山引擎/百度云/京东云/UCloud/金山云等）
            cn_hit = match_cn_cloud_by_cidr(ip)
            if cn_hit is not None:
                return GeoInfo(
                    ip=ip,
                    country=cn_hit.country,
                    city=cn_hit.city,
                    asn=f"{cn_hit.asn} [{cn_hit.provider}]",
                    is_datacenter=True,
                    is_blacklist=False,
                    is_simulated=is_simulated,
                    score=SCORE_WEIGHTS["DATACENTER_IP"],
                    reasons=[ReasonCode.DATACENTER_IP.value],
                )
            return GeoInfo(
                ip=ip,
                country="UNKNOWN",
                city="Unknown",
                asn="AS0 Unmapped",
                is_datacenter=False,
                is_blacklist=False,
                is_simulated=is_simulated,
                score=0,
                reasons=[],
            )

        reasons: List[str] = []
        score = 0
        is_bl = bool(matched.is_blacklist)
        is_dc = bool(matched.is_datacenter)

        # 检测：优先判定黑名单网段，其次判定云机房/代理网段
        if is_bl:
            reasons.append(ReasonCode.BLACKLIST_IP.value)
            score += SCORE_WEIGHTS["BLACKLIST_IP"]
        elif is_dc:
            reasons.append(ReasonCode.DATACENTER_IP.value)
            score += SCORE_WEIGHTS["DATACENTER_IP"]

        return GeoInfo(
            ip=ip,
            country=matched.country,
            city=matched.city,
            asn=matched.asn,
            is_datacenter=is_dc,
            is_blacklist=is_bl,
            is_simulated=is_simulated,
            score=score,
            reasons=reasons,
        )


def resolve_effective_ip(
    client_ip: str,
    headers: Mapping[str, str],
    lab_mode: bool,
) -> Tuple[str, bool]:
    """
    解析本次请求的有效 IP（effective_ip）。
    安全边界：仅在 LAB_MODE=1 时允许使用 X-Simulated-IP 进行本地攻防演练；
    LAB_MODE=0 时忽略该请求头，严格按真实连接来源处理。
    """
    if lab_mode:
        sim_ip = headers.get("x-simulated-ip", "").strip()
        if sim_ip:
            # 简单防注入清洗：仅保留合法 IP 字符
            cleaned = "".join(ch for ch in sim_ip if ch.isalnum() or ch in ".:")[:64]
            if cleaned:
                return cleaned, True
    return client_ip or "127.0.0.1", False


_default_provider = MockGeoIPProvider()


def get_geoip_provider() -> GeoIPProvider:
    """获取当前 GeoIP 查询提供者。"""
    return _default_provider
