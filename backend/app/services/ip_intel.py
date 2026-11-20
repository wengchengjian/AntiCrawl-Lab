"""
真实 IP 情报、地域定位、rDNS 反查与 VPN/代理穿透泄露分析服务（ip_intel.py）。

检测什么：
1. 混合 GeoIP 解析：优先匹配本地 ip_geo_mock（保障教学演练与离线单测确定性），
   对真实公网 IP 自动查询实时 GeoIP/ASN/rDNS/代理标记并写入 cache.py（缓存 6 小时）。
2. rDNS 反向解析特征识别：检测云主机/VPN 常见 PTR 命名（ec2/compute.amazonaws/vultr/digitalocean/vpn/proxy 等）。
3. 代理链 HTTP 头泄露检测（Via / X-Forwarded-For 多跳 / Forwarded / Proxy-Connection）。
4. VPN 穿透与真实 IP 对比引擎：交叉比对 HTTP 直连 IP、WebRTC STUN 穿透公网 IP（srflx）、
   海外探测出口 IP、国内探测出口 IP，识破 HTTP/SOCKS5 代理绕过与 Clash/Mihomo 规则分流！
5. 时区/语言/经纬度交叉校验：对比 IP 真实时区与浏览器 Intl 时区、getTimezoneOffset() 及首选语言。
阈值依据：
- WebRTC STUN 泄露不同公网 IP (+35)、分流多出口 IP 不一致 (+30)、云机房/代理 ASN (+25)、
  rDNS 命中云主机/VPN 模式 (+15)、IP 时区与浏览器时区不一致 (+20)、代理链头泄露 (+15)。
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
from typing import Any, Dict, List, Mapping, Optional

import httpx
from sqlalchemy.orm import Session

from app.cache import get_cache
from app.models.tables import IpGeoMock
from app.services.cn_cloud_ranges import match_cn_cloud_by_cidr, match_cn_cloud_by_metadata
from app.services.geoip import GeoInfo, get_geoip_provider

# 常见国内外云服务商/VPN 出口 rDNS 主机名正则特征
CLOUD_RDNS_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"ec2-.*\.amazonaws\.com$", "Amazon AWS EC2"),
    (r"googleusercontent\.com$", "Google Cloud Platform"),
    (r"compute\.internal$|amazonaws\.com$", "Amazon AWS"),
    (r"vultr\.com$|vultrusercontent\.com$", "Vultr Cloud"),
    (r"digitalocean\.com$", "DigitalOcean"),
    (r"linodeusercontent\.com$|members\.linode\.com$", "Akamai/Linode"),
    (r"your-server\.de$|hetzner\.", "Hetzner Datacenter"),
    (r"ovh\.(net|ca|com)$", "OVHcloud"),
    (r"aliyun|alicloud|alibaba", "阿里云 (Alibaba Cloud)"),
    (r"tencent|qcloud|myqcloud", "腾讯云 (Tencent Cloud)"),
    (r"huaweicloud|hwclouds", "华为云 (Huawei Cloud)"),
    (r"volcengine|bytedance|bytefcdn", "火山引擎 / 字节跳动云"),
    (r"baidubce|bcebos|baidu\.com$", "百度智能云 (Baidu Cloud)"),
    (r"jdcloud|jcloud", "京东云 (JD Cloud)"),
    (r"ucloud", "UCloud 优刻得"),
    (r"ksyun|kingsoft", "金山云 (Kingsoft Cloud)"),
    (r"qingcloud", "青云 (QingCloud)"),
    (r"qiniu", "七牛云 (Qiniu Cloud)"),
    (r"ctyun", "天翼云 (China Telecom Cloud)"),
    (r"netease|163\.com$", "网易云 (NetEase Cloud)"),
    (r"wangsu|lxdns", "网宿科技 (Wangsu)"),
    (r"(^|[.-])(vpn|proxy|exit|tor|relay|socks|node)([.-]|$)", "VPN/Proxy Exit PTR"),
)

# 常见云/代理组织关键词（ISP/Org/ASN 名称匹配）
HOSTING_ORG_KEYWORDS: tuple[str, ...] = (
    "amazon",
    "aws",
    "google cloud",
    "microsoft azure",
    "alibaba",
    "aliyun",
    "tencent",
    "digitalocean",
    "vultr",
    "linode",
    "hetzner",
    "ovh",
    "oracle cloud",
    "cloudflare",
    "datacamp",
    "m247",
    "leaseweb",
    "choopa",
    "packethub",
    "akamai",
    "fastly",
    "cdn77",
)

# 预置本地 Mock 坐标与时区补充（供 14 条演练段也能展示真实地图）
MOCK_COORDS: Dict[str, Dict[str, Any]] = {
    "Shanghai": {"lat": 31.2304, "lon": 121.4737, "tz": "Asia/Shanghai", "region": "Shanghai"},
    "Beijing": {"lat": 39.9042, "lon": 116.4074, "tz": "Asia/Shanghai", "region": "Beijing"},
    "Guangzhou": {"lat": 23.1291, "lon": 113.2644, "tz": "Asia/Shanghai", "region": "Guangdong"},
    "Hangzhou": {"lat": 30.2741, "lon": 120.1551, "tz": "Asia/Shanghai", "region": "Zhejiang"},
    "Shenzhen": {"lat": 22.5431, "lon": 114.0579, "tz": "Asia/Shanghai", "region": "Guangdong"},
    "Chengdu": {"lat": 30.5728, "lon": 104.0668, "tz": "Asia/Shanghai", "region": "Sichuan"},
    "Ashburn": {"lat": 39.0438, "lon": -77.4874, "tz": "America/New_York", "region": "Virginia"},
    "Mountain View": {"lat": 37.3861, "lon": -122.0839, "tz": "America/Los_Angeles", "region": "California"},
    "Boardman": {"lat": 45.8399, "lon": -119.7006, "tz": "America/Los_Angeles", "region": "Oregon"},
    "Hong Kong": {"lat": 22.3193, "lon": 114.1694, "tz": "Asia/Hong_Kong", "region": "Hong Kong"},
    "Singapore": {"lat": 1.3521, "lon": 103.8198, "tz": "Asia/Singapore", "region": "Singapore"},
    "Localhost Lab": {"lat": 31.2304, "lon": 121.4737, "tz": "Asia/Shanghai", "region": "Loopback"},
}


def is_public_ip(ip_str: str) -> bool:
    """判断字符串是否为可路由公网 IPv4/IPv6（排除内网、回环、链路本地、mDNS）。"""
    if not ip_str or ".local" in ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        return False


def analyze_rdns(hostname: str) -> Optional[str]:
    """分析 PTR 反向解析域名是否命中云主机或 VPN/Proxy 出口模式。"""
    if not hostname:
        return None
    low = hostname.strip().lower().rstrip(".")
    for pattern, label in CLOUD_RDNS_PATTERNS:
        if re.search(pattern, low):
            return label
    return None


def _lookup_live_ip_intel(ip: str) -> Optional[Dict[str, Any]]:
    """
    查询实时公网 IP 情报（ip-api.com 主源 + ipwho.is 备源），结果写入 cache.py 缓存 6 小时。
    单测可通过环境变量 `ENABLE_LIVE_GEOIP=0` 关闭外网查询。
    """
    if os.getenv("ENABLE_LIVE_GEOIP", "1").strip().lower() in {"0", "false", "off"}:
        return None
    if not is_public_ip(ip):
        return None

    cache = get_cache()
    cache_key = f"ip_intel_v2:{ip}"
    cached = cache.get(cache_key)
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            pass

    intel: Optional[Dict[str, Any]] = None

    # 主源：ip-api.com（含 country/city/lat/lon/timezone/isp/org/as/reverse/mobile/proxy/hosting）
    try:
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"
            "&lang=zh-CN"
        )
        resp = httpx.get(url, timeout=2.5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                intel = {
                    "ip": ip,
                    "source": "ip-api.com",
                    "country": str(data.get("country") or "Unknown"),
                    "country_code": str(data.get("countryCode") or "UNKNOWN"),
                    "region": str(data.get("regionName") or ""),
                    "city": str(data.get("city") or "Unknown"),
                    "lat": float(data.get("lat") or 0.0),
                    "lon": float(data.get("lon") or 0.0),
                    "timezone": str(data.get("timezone") or ""),
                    "isp": str(data.get("isp") or ""),
                    "org": str(data.get("org") or ""),
                    "asn": str(data.get("as") or ""),
                    "asname": str(data.get("asname") or ""),
                    "rdns": str(data.get("reverse") or ""),
                    "is_mobile": bool(data.get("mobile", False)),
                    "is_proxy": bool(data.get("proxy", False)),
                    "is_hosting": bool(data.get("hosting", False)),
                    "is_blacklist": False,
                }
    except Exception:
        intel = None

    # 备源：ipwho.is
    if intel is None:
        try:
            resp = httpx.get(f"https://ipwho.is/{ip}", timeout=2.5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    conn = data.get("connection") or {}
                    tz_obj = data.get("timezone") or {}
                    intel = {
                        "ip": ip,
                        "source": "ipwho.is",
                        "country": str(data.get("country") or "Unknown"),
                        "country_code": str(data.get("country_code") or "UNKNOWN"),
                        "region": str(data.get("region") or ""),
                        "city": str(data.get("city") or "Unknown"),
                        "lat": float(data.get("latitude") or 0.0),
                        "lon": float(data.get("longitude") or 0.0),
                        "timezone": str(tz_obj.get("id") or ""),
                        "isp": str(conn.get("isp") or ""),
                        "org": str(conn.get("org") or ""),
                        "asn": f"AS{conn.get('asn', '')} {conn.get('org', '')}".strip(),
                        "asname": str(conn.get("domain") or ""),
                        "rdns": "",
                        "is_mobile": False,
                        "is_proxy": False,
                        "is_hosting": False,
                        "is_blacklist": False,
                    }
        except Exception:
            intel = None

    if intel is not None:
        # 若上游未返回 rDNS，尝试快速 PTR 反查
        if not intel.get("rdns"):
            try:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(0.8)
                try:
                    intel["rdns"] = socket.gethostbyaddr(ip)[0]
                finally:
                    socket.setdefaulttimeout(old_timeout)
            except Exception:
                pass

        # 结合国内云厂商 CIDR / ASN / ISP 组织与海外机房关键词 + rDNS 四维强化识别
        cloud_provider: Optional[str] = None
        cloud_match_by: Optional[str] = None

        cn_meta_hit = match_cn_cloud_by_metadata(
            asn=str(intel.get("asn") or ""),
            isp=str(intel.get("isp") or ""),
            org=str(intel.get("org") or ""),
            asname=str(intel.get("asname") or ""),
        )
        cn_cidr_hit = match_cn_cloud_by_cidr(ip)
        cn_hit = cn_meta_hit or cn_cidr_hit
        if cn_hit is not None:
            intel["is_hosting"] = True
            cloud_provider = cn_hit.provider
            cloud_match_by = f"{cn_hit.match_by}:{cn_hit.matched_rule}"

        org_blob = f"{intel.get('isp', '')} {intel.get('org', '')} {intel.get('asn', '')}".lower()
        if any(kw in org_blob for kw in HOSTING_ORG_KEYWORDS):
            intel["is_hosting"] = True

        rdns_hit = analyze_rdns(str(intel.get("rdns") or ""))
        intel["rdns_cloud_tag"] = rdns_hit
        if rdns_hit:
            intel["is_hosting"] = True
            if cloud_provider is None:
                cloud_provider = rdns_hit
                cloud_match_by = "rdns"
            if "VPN" in rdns_hit or "Proxy" in rdns_hit:
                intel["is_proxy"] = True

        intel["cloud_provider"] = cloud_provider
        intel["cloud_match_by"] = cloud_match_by

        cache.set(cache_key, json.dumps(intel, ensure_ascii=False), ex=21600)
    return intel


def _match_mock_table_only(db: Session, ip: str) -> Optional[IpGeoMock]:
    """仅查询本地 ip_geo_mock 表（用于区分教学演练 Mock 段与真实公网国内云 CIDR）。"""
    records = db.query(IpGeoMock).all()
    matched: Optional[IpGeoMock] = None
    best_len = -1
    for rec in records:
        if ip.startswith(rec.ip_prefix) and len(rec.ip_prefix) > best_len:
            matched = rec
            best_len = len(rec.ip_prefix)
    return matched


def get_rich_ip_profile(db: Session, ip: str, is_simulated: bool = False) -> Dict[str, Any]:
    """
    获取综合 IP 情报画像：
    1. 优先匹配本地 ip_geo_mock 教学演练库；
    2. 真实公网 IP 优先走实时 GeoIP + 国内云厂商四维识别（CIDR/ASN/Org/rDNS）；
    3. 离线/无外网环境自动回退至国内云厂商离线 CIDR 精准库。
    """
    mock_rec = _match_mock_table_only(db, ip)
    if mock_rec is not None:
        coords = MOCK_COORDS.get(mock_rec.city, {"lat": 31.2304, "lon": 121.4737, "tz": "Asia/Shanghai", "region": mock_rec.city})
        cn_meta = match_cn_cloud_by_metadata(asn=mock_rec.asn, org=mock_rec.asn)
        return {
            "ip": ip,
            "source": "ip_geo_mock",
            "is_simulated": is_simulated,
            "country": mock_rec.country,
            "country_code": mock_rec.country,
            "region": coords["region"],
            "city": mock_rec.city,
            "lat": coords["lat"],
            "lon": coords["lon"],
            "timezone": coords["tz"],
            "isp": mock_rec.asn,
            "org": mock_rec.asn,
            "asn": mock_rec.asn,
            "rdns": f"mock-{ip.replace('.', '-')}.anticrawl.lab",
            "rdns_cloud_tag": "Mock Datacenter" if mock_rec.is_datacenter else None,
            "cloud_provider": cn_meta.provider if cn_meta else (mock_rec.asn if mock_rec.is_datacenter else None),
            "cloud_match_by": f"mock:{mock_rec.ip_prefix}" if mock_rec.is_datacenter else None,
            "is_mobile": False,
            "is_proxy": bool(mock_rec.is_blacklist),
            "is_hosting": bool(mock_rec.is_datacenter),
            "is_blacklist": bool(mock_rec.is_blacklist),
        }

    live = _lookup_live_ip_intel(ip)
    if live is not None:
        live["is_simulated"] = is_simulated
        return live

    # 离线兜底：命中国内主流云厂商核心 CIDR 段
    cn_cidr = match_cn_cloud_by_cidr(ip)
    if cn_cidr is not None:
        coords = MOCK_COORDS.get(cn_cidr.city, {"lat": 31.2304, "lon": 121.4737, "tz": "Asia/Shanghai", "region": cn_cidr.city})
        return {
            "ip": ip,
            "source": "cn_cloud_cidr",
            "is_simulated": is_simulated,
            "country": "中国" if cn_cidr.country == "CN" else cn_cidr.country,
            "country_code": cn_cidr.country,
            "region": coords["region"],
            "city": cn_cidr.city,
            "lat": coords["lat"],
            "lon": coords["lon"],
            "timezone": coords["tz"],
            "isp": cn_cidr.provider,
            "org": cn_cidr.provider,
            "asn": cn_cidr.asn,
            "rdns": "",
            "rdns_cloud_tag": None,
            "cloud_provider": cn_cidr.provider,
            "cloud_match_by": f"cidr:{cn_cidr.matched_rule}",
            "is_mobile": False,
            "is_proxy": False,
            "is_hosting": True,
            "is_blacklist": False,
        }

    return {
        "ip": ip,
        "source": "fallback",
        "is_simulated": is_simulated,
        "country": "Unknown",
        "country_code": "UNKNOWN",
        "region": "",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "timezone": "",
        "isp": "Unmapped",
        "org": "",
        "asn": "AS0 Unmapped",
        "rdns": "",
        "rdns_cloud_tag": None,
        "cloud_provider": None,
        "cloud_match_by": None,
        "is_mobile": False,
        "is_proxy": False,
        "is_hosting": False,
        "is_blacklist": False,
    }


def detect_proxy_headers(headers: Mapping[str, str]) -> List[str]:
    """检测 HTTP 代理链泄露头（Via / Forwarded / Proxy-Connection / 多跳 X-Forwarded-For）。"""
    norm = {k.lower(): v.strip() for k, v in headers.items()}
    leaks: List[str] = []
    for h in ("via", "forwarded", "proxy-connection", "x-proxy-id", "client-ip", "x-cluster-client-ip"):
        if norm.get(h):
            leaks.append(f"{h}: {norm[h][:60]}")
    xff = norm.get("x-forwarded-for", "")
    if xff and len([p for p in xff.split(",") if p.strip()]) > 1:
        leaks.append(f"x-forwarded-for 多跳代理链: {xff[:80]}")
    return leaks


def evaluate_vpn_and_geo_leaks(
    db: Session,
    *,
    effective_ip: str,
    is_simulated: bool,
    headers: Mapping[str, str],
    webrtc_public_ips: List[str],
    webrtc_local_candidates: List[str],
    overseas_echo_ip: str = "",
    domestic_echo_ip: str = "",
    browser_timezone: str = "",
    browser_tz_offset: Optional[int] = None,
    browser_languages: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    综合 VPN/代理穿透与地域一致性对抗引擎：
    - 对比 4 条独立 IP 信道（本服直连 IP / WebRTC STUN 穿透 IP / 海外探测 IP / 国内探测 IP）；
    - 判定是否越过 VPN 捕获真实 IP、是否命中规则分流、是否暴露云机房/代理特征与时区矛盾；
    - 输出隐匿度评分（concealment_score 0–100）、暴露风险分（risk_score 0–100）与攻防对抗建议。
    """
    primary_profile = get_rich_ip_profile(db, effective_ip, is_simulated=is_simulated)
    findings: List[Dict[str, Any]] = []
    risk_score = 0

    def add_finding(fid: str, title: str, severity: str, weight: int, detail: str, evasion_tip: str, defense_tip: str) -> None:
        nonlocal risk_score
        risk_score = min(100, risk_score + weight)
        findings.append(
            {
                "id": fid,
                "title": title,
                "severity": severity,
                "weight": weight,
                "detail": detail,
                "evasion_tip": evasion_tip,
                "defense_tip": defense_tip,
            }
        )

    # 1. 云机房 / 商业代理 / 黑名单标记
    if primary_profile.get("is_blacklist"):
        add_finding(
            "IP_BLACKLIST",
            "命中高危黑名单网段",
            "critical",
            35,
            f"当前 IP {effective_ip} 位于高危黑名单池（{primary_profile.get('asn')}）。",
            "更换干净的独享住宅出口 IP，避免使用公共免费代理或滥用池。",
            "接入实时威胁情报库（AbuseIPDB / Spamhaus）在网关层直接拦截或强制 PoW。",
        )
    elif primary_profile.get("is_proxy") or primary_profile.get("is_hosting"):
        cloud_vendor = primary_profile.get("cloud_provider")
        match_by = primary_profile.get("cloud_match_by")
        tag = "VPN/Proxy 代理出口" if primary_profile.get("is_proxy") else (f"国内/云数据中心机房（{cloud_vendor}）" if cloud_vendor else "云数据中心 / 托管机房")
        match_note = f"，命中规则={match_by}" if match_by else ""
        add_finding(
            "IP_HOSTING_OR_PROXY",
            f"出口 IP 属于 {tag}",
            "high",
            25,
            f"{effective_ip} 归属 {cloud_vendor or primary_profile.get('isp') or primary_profile.get('asn')}（hosting={primary_profile.get('is_hosting')}, proxy={primary_profile.get('is_proxy')}{match_note}）。",
            "商业代理通常需切换到 ISP 静态住宅 IP 或 4G/5G 移动出口才可降低 ASN 评分。",
            "结合国内云厂商 CIDR/ASN 精确库与同网段高频指纹复用追踪，对机房段默认施加诱饵或挑战降级。",
        )

    # 2. rDNS 反向解析特征
    rdns_tag = primary_profile.get("rdns_cloud_tag")
    if rdns_tag:
        add_finding(
            "RDNS_CLOUD_PATTERN",
            "rDNS 主机名暴露云主机/代理特征",
            "medium",
            15,
            f"PTR 反向解析 `{primary_profile.get('rdns')}` 命中特征：{rdns_tag}。",
            "定制合法住宅风格 PTR 记录（普通云主机通常无权修改运营商 PTR）。",
            "异步缓存 PTR 反查结果，将 ec2/vultr/vpn/exit 等关键词纳入综合风控特征。",
        )

    # 3. WebRTC UDP STUN 穿透泄露真实 IP（核心越过 VPN/HTTP 代理能力！）
    clean_stun_ips = list(dict.fromkeys(ip.strip() for ip in webrtc_public_ips if is_public_ip(ip)))
    leaked_real_ips: List[str] = [ip for ip in clean_stun_ips if ip != effective_ip]
    leaked_profiles: List[Dict[str, Any]] = []

    if leaked_real_ips:
        for lip in leaked_real_ips[:3]:
            leaked_profiles.append(get_rich_ip_profile(db, lip, is_simulated=False))
        lp0 = leaked_profiles[0]
        add_finding(
            "WEBRTC_STUN_REAL_IP_LEAK",
            "WebRTC UDP STUN 穿透代理捕获真实公网 IP",
            "critical",
            35,
            f"HTTP 出口为 {effective_ip}，但 UDP STUN 穿透返回真实公网 IP {lip}（{lp0.get('country')}/{lp0.get('city')} · {lp0.get('isp')}）！",
            "开启完整 TUN 全局 UDP 代理，或在浏览器策略中强制 WebRTC 仅使用代理接口（disable_non_proxied_udp）。",
            "并行探针多组 STUN 服务器提取 srflx 候选，与 HTTP 源 IP 比对是穿透 HTTP/SOCKS5 代理最直接的防线。",
        )

    # 4. 国内外规则分流探测（专克 Clash / Mihomo / V2Ray Rule 模式！）
    split_ips: Dict[str, str] = {"direct_origin": effective_ip}
    if overseas_echo_ip and is_public_ip(overseas_echo_ip):
        split_ips["overseas_echo"] = overseas_echo_ip.strip()
    if domestic_echo_ip and is_public_ip(domestic_echo_ip):
        split_ips["domestic_echo"] = domestic_echo_ip.strip()

    distinct_public_ips = list(dict.fromkeys(ip for ip in split_ips.values() if is_public_ip(ip)))
    extra_channel_profiles: Dict[str, Dict[str, Any]] = {}
    for ch_name, ch_ip in split_ips.items():
        if ch_ip == effective_ip:
            extra_channel_profiles[ch_name] = primary_profile
        else:
            extra_channel_profiles[ch_name] = get_rich_ip_profile(db, ch_ip, is_simulated=False)

    if len(distinct_public_ips) >= 2:
        desc_parts = [
            f"{k}={v}({extra_channel_profiles[k].get('country_code')}/{extra_channel_profiles[k].get('city')})"
            for k, v in split_ips.items()
        ]
        add_finding(
            "SPLIT_TUNNEL_VPN_DETECTED",
            "多信道分流暴露代理/VPN 真实出口差异",
            "critical",
            30,
            "检测到规则分流多出口不一致：" + " vs ".join(desc_parts) + "（典型 Clash/Mihomo 规则模式特征）。",
            "使用全局代理（Global Mode）并统一所有国内外域名的出口路由。",
            "通过同时部署国内直连探针域与海外探针域（CORS/Img/Fetch），可无感识破几乎所有规则分流型 VPN。",
        )

    # 5. IP 真实时区 vs 浏览器时区
    ip_tz = str(primary_profile.get("timezone") or "")
    if ip_tz and browser_timezone and ip_tz != browser_timezone:
        # 容忍同属中国标准时间的等价别名
        cn_equiv = {"Asia/Shanghai", "Asia/Chongqing", "Asia/Harbin", "Asia/Urumqi", "Asia/Hong_Kong", "Asia/Macau"}
        if not (ip_tz in cn_equiv and browser_timezone in cn_equiv):
            add_finding(
                "IP_TZ_VS_BROWSER_TZ",
                "IP 地理时区与浏览器时区冲突",
                "high",
                20,
                f"出口 IP 对应时区为 {ip_tz}，但浏览器上报时区为 {browser_timezone}（offset={browser_tz_offset}）。",
                "同步伪装浏览器 Intl.DateTimeFormat 与 Date.getTimezoneOffset() 为出口 IP 所在时区。",
                "将 IP 真实时区、Intl 时区名、getTimezoneOffset() 三方交叉校验，单改一项即暴露破绽。",
            )

    # 6. IP 国家 vs 浏览器语言
    cc = str(primary_profile.get("country_code") or "UNKNOWN")
    langs = [str(x).lower() for x in (browser_languages or [])]
    if cc not in {"CN", "HK", "TW", "MO", "SG", "UNKNOWN"} and langs and langs[0].startswith("zh"):
        add_finding(
            "IP_COUNTRY_VS_LANGUAGE",
            "海外出口 IP 与中文浏览器语言生态偏差",
            "medium",
            12,
            f"出口 IP 位于 {primary_profile.get('country')}（{cc}），但浏览器首选语言为 {langs[0]}。",
            "使 Accept-Language、navigator.languages 与出口国家官方语言保持一致。",
            "结合字体库（SimSun/Microsoft YaHei）与首选语言综合判断海外代理伪装。",
        )

    # 7. HTTP 代理链头泄露
    proxy_hdr_leaks = detect_proxy_headers(headers)
    if proxy_hdr_leaks:
        add_finding(
            "PROXY_HEADER_LEAK",
            "HTTP 请求头泄露中间代理链路",
            "medium",
            15,
            "检测到代理转发头：" + "；".join(proxy_hdr_leaks),
            "使用高匿（Elite）代理，剥离 Via / Proxy-Connection / X-Forwarded-For 头。",
            "检查 Via / Forwarded / 多跳 X-Forwarded-For 快速识别透明与普通匿名代理。",
        )

    # 推断最可能的「真实本地 IP」与「代理出口 IP」
    suspected_real_ip = None
    suspected_proxy_ip = None
    if leaked_real_ips:
        suspected_real_ip = leaked_real_ips[0]
        suspected_proxy_ip = effective_ip
    elif len(distinct_public_ips) >= 2:
        # 优先将住宅/非机房 IP 推断为真实直连 IP，机房/海外 IP 推断为代理出口
        for ip_cand in distinct_public_ips:
            prof = next((p for p in extra_channel_profiles.values() if p["ip"] == ip_cand), None)
            if prof and not prof.get("is_hosting") and not prof.get("is_proxy"):
                suspected_real_ip = ip_cand
            elif prof and (prof.get("is_hosting") or prof.get("is_proxy")):
                suspected_proxy_ip = ip_cand
        if not suspected_real_ip:
            suspected_real_ip = split_ips.get("domestic_echo") or effective_ip
        if not suspected_proxy_ip:
            suspected_proxy_ip = split_ips.get("overseas_echo") or effective_ip

    concealment_score = max(0, 100 - risk_score)
    findings.sort(key=lambda x: x["weight"], reverse=True)

    return {
        "effective_ip": effective_ip,
        "primary_profile": primary_profile,
        "channels": {
            "direct_origin": extra_channel_profiles.get("direct_origin"),
            "overseas_echo": extra_channel_profiles.get("overseas_echo"),
            "domestic_echo": extra_channel_profiles.get("domestic_echo"),
            "webrtc_public_ips": clean_stun_ips,
            "webrtc_local_candidates": webrtc_local_candidates[:6],
            "webrtc_leaked_profiles": leaked_profiles,
        },
        "vpn_pierced": bool(leaked_real_ips or len(distinct_public_ips) >= 2),
        "suspected_real_ip": suspected_real_ip,
        "suspected_proxy_ip": suspected_proxy_ip,
        "proxy_headers": proxy_hdr_leaks,
        "risk_score": risk_score,
        "concealment_score": concealment_score,
        "findings": findings,
    }
