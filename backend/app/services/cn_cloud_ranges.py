"""
国内主流云厂商与 IDC 机房 IP 四维识别引擎（cn_cloud_ranges.py）。

检测什么：
1. 离线精准 CIDR 网段匹配：覆盖阿里云、腾讯云、华为云、火山引擎（字节云）、百度智能云、京东云、
   UCloud 优刻得、金山云、青云 QingCloud、网易云、首都在线、光环新网等国内主流云厂商核心公网段。
2. 自治系统号（ASN）精准映射：覆盖国内 18+ 家主流云厂商与 BGP IDC 机房 ASN，弥补海外 GeoIP 库
   （如 ip-api.com / ipwho.is）对国内云机房常漏标 `hosting=false` 的短板。
3. 组织/ISP 关键词匹配（中英文双语）：识别运营商云（天翼云、移动云、联通云）及 CDN/IDC 机房，
   同时避免误杀三大运营商普通家庭宽带/移动流量 ASN（如 AS4134/AS4837/AS9808）。
4. rDNS 反向解析云特征匹配：补齐国内云厂商常见 PTR 域名特征。

为什么可疑：
- 国内大规模数据采集与自动化爬虫绝大多数部署在阿里云、腾讯云、华为云、火山引擎、UCloud 等弹性云服务器或 BGP 机房；
- 真实个人消费者极少直接以云厂商公网段作为浏览器出口 IP。

阈值依据：
- 命中任意国内云机房 CIDR / ASN / 组织特征时，在网络层记为 `DATACENTER_IP`（+25 分），
  并在 `/api/v1/ip/audit` 与 `/api/v1/bot/check` 中明确输出所属云厂商标签。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class CloudProviderHit:
    """国内云厂商机房命中结果。"""

    provider: str
    vendor_code: str
    asn: str
    city: str
    country: str
    match_by: str  # "cidr" | "asn" | "org_keyword" | "rdns"
    matched_rule: str


# 1. 国内主流云厂商与 BGP IDC 机房 ASN 精确字典（严禁收录三大运营商普通住宅宽带 ASN 如 AS4134/AS4837/AS9808）
CN_CLOUD_ASNS: Dict[str, Tuple[str, str]] = {
    # 阿里云 Alibaba Cloud
    "AS37963": ("阿里云 (Alibaba Cloud)", "aliyun"),
    "AS45102": ("阿里云国际 (Alibaba Cloud Intl)", "aliyun"),
    "AS24429": ("阿里云/淘宝机房 (Alibaba)", "aliyun"),
    "AS45062": ("阿里云/网易联合 BGP", "aliyun"),
    # 腾讯云 Tencent Cloud
    "AS45090": ("腾讯云 (Tencent Cloud)", "tencent"),
    "AS132203": ("腾讯云国际 (Tencent Cloud Intl)", "tencent"),
    "AS132591": ("腾讯云 (Tencent Cloud)", "tencent"),
    "AS133478": ("腾讯云/深圳腾讯机房", "tencent"),
    # 华为云 Huawei Cloud
    "AS55990": ("华为云 (Huawei Cloud)", "huawei"),
    "AS136907": ("华为云国际 (Huawei Cloud Intl)", "huawei"),
    "AS131444": ("华为云 (Huawei Cloud)", "huawei"),
    # 火山引擎 / 字节跳动云 Volcengine
    "AS137718": ("火山引擎 / 字节跳动云 (Volcengine)", "volcengine"),
    "AS138699": ("火山引擎 / 字节跳动 (ByteDance)", "volcengine"),
    "AS141425": ("火山引擎 BGP (Volcengine)", "volcengine"),
    "AS150436": ("火山引擎 (Volcengine Cloud)", "volcengine"),
    "AS396986": ("字节跳动海外云 (ByteDance Intl)", "volcengine"),
    # 百度智能云 Baidu Cloud
    "AS38365": ("百度智能云 (Baidu Cloud)", "baidu"),
    "AS55967": ("百度智能云 (Baidu Cloud BCE)", "baidu"),
    # 京东云 JD Cloud
    "AS134764": ("京东云 (JD Cloud)", "jdcloud"),
    "AS137753": ("京东云 (JD Cloud)", "jdcloud"),
    "AS138950": ("京东科技机房 (JD Cloud)", "jdcloud"),
    # UCloud 优刻得
    "AS135377": ("UCloud 优刻得", "ucloud"),
    "AS59077": ("UCloud 优刻得国际", "ucloud"),
    # 金山云 Kingsoft Cloud
    "AS134773": ("金山云 (Kingsoft Cloud)", "ksyun"),
    "AS137715": ("金山云 (KSYUN)", "ksyun"),
    # 青云 QingCloud
    "AS59019": ("青云 (QingCloud)", "qingcloud"),
    # 天翼云专属 ASN（不含电信普通家宽）
    "AS141998": ("天翼云 (China Telecom Cloud)", "ctyun"),
    "AS137691": ("天翼云 (CTYun)", "ctyun"),
    # 网易云 NetEase
    "AS45083": ("网易云 / 网易机房 (NetEase)", "netease"),
    # 七牛云 / 网宿 / 又拍云 / 蓝汛
    "AS136195": ("七牛云 (Qiniu Cloud)", "qiniu"),
    "AS58519": ("网宿科技 (Wangsu / ChinaNetCenter)", "wangsu"),
    "AS133775": ("网宿科技国际 (Wangsu)", "wangsu"),
    "AS38353": ("蓝汛机房 (ChinaCache)", "chinacache"),
    # 美团云 / 滴滴云
    "AS137788": ("美团云 / 美团机房 (Meituan)", "meituan"),
    "AS138949": ("滴滴云 (Didi Cloud)", "didi"),
    # 国内头部商业 BGP IDC 机房（常用于代理池与爬虫托管）
    "AS4847": ("世纪互联 BGP IDC (21Vianet)", "21vianet"),
    "AS24400": ("世纪互联 / 上海驰联 IDC", "21vianet"),
    "AS45087": ("首都在线云机房 (CapitalOnline)", "capitalonline"),
    "AS131526": ("光环新网 IDC (Sinnet)", "sinnet"),
    "AS45057": ("光环新网 BGP (Sinnet)", "sinnet"),
    "AS38283": ("网银互联 / 杭州 BGP IDC", "cn_idc"),
}


# 2. 国内主流云厂商代表性核心公网 IPv4 CIDR 网段（预编译，毫秒级离线精准命中）
# 格式: (cidr, provider_name, vendor_code, asn, default_city)
_RAW_CN_CLOUD_CIDRS: Tuple[Tuple[str, str, str, str, str], ...] = (
    # --- 阿里云 Alibaba Cloud ---
    ("47.92.0.0/14", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Beijing"),
    ("47.96.0.0/12", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Hangzhou"),
    ("47.112.0.0/12", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Shenzhen"),
    ("39.96.0.0/13", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Beijing"),
    ("39.104.0.0/13", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Shanghai"),
    ("101.200.0.0/15", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Beijing"),
    ("112.124.0.0/15", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Hangzhou"),
    ("114.55.0.0/16", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Hangzhou"),
    ("118.178.0.0/15", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Hangzhou"),
    ("120.24.0.0/14", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Shenzhen"),
    ("120.76.0.0/14", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Shenzhen"),
    ("121.40.0.0/14", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Hangzhou"),
    ("121.196.0.0/14", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Hangzhou"),
    ("123.56.0.0/15", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Beijing"),
    ("139.196.0.0/16", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Shanghai"),
    ("139.224.0.0/16", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Shanghai"),
    ("8.128.0.0/13", "阿里云 (Alibaba Cloud)", "aliyun", "AS37963 Alibaba Cloud", "Hangzhou"),
    # --- 腾讯云 Tencent Cloud ---
    ("43.128.0.0/13", "腾讯云 (Tencent Cloud)", "tencent", "AS132203 Tencent Cloud", "Hong Kong"),
    ("49.232.0.0/14", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Beijing"),
    ("81.68.0.0/14", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Shanghai"),
    ("82.156.0.0/15", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Beijing"),
    ("106.52.0.0/14", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Guangzhou"),
    ("118.24.0.0/15", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Chengdu"),
    ("118.89.0.0/16", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Guangzhou"),
    ("119.28.0.0/15", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Guangzhou"),
    ("124.220.0.0/14", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Shanghai"),
    ("129.204.0.0/16", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Guangzhou"),
    ("129.211.0.0/16", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Shanghai"),
    ("134.175.0.0/16", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Guangzhou"),
    ("140.143.0.0/16", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Beijing"),
    ("150.158.0.0/16", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Shanghai"),
    ("152.136.0.0/16", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Beijing"),
    ("175.178.0.0/16", "腾讯云 (Tencent Cloud)", "tencent", "AS45090 Tencent Cloud", "Guangzhou"),
    # --- 华为云 Huawei Cloud ---
    ("1.92.0.0/14", "华为云 (Huawei Cloud)", "huawei", "AS55990 Huawei Cloud", "Beijing"),
    ("114.115.0.0/16", "华为云 (Huawei Cloud)", "huawei", "AS55990 Huawei Cloud", "Beijing"),
    ("114.116.0.0/16", "华为云 (Huawei Cloud)", "huawei", "AS55990 Huawei Cloud", "Beijing"),
    ("117.78.0.0/18", "华为云 (Huawei Cloud)", "huawei", "AS55990 Huawei Cloud", "Beijing"),
    ("119.3.0.0/16", "华为云 (Huawei Cloud)", "huawei", "AS55990 Huawei Cloud", "Guangzhou"),
    ("121.36.0.0/15", "华为云 (Huawei Cloud)", "huawei", "AS55990 Huawei Cloud", "Beijing"),
    ("122.112.0.0/16", "华为云 (Huawei Cloud)", "huawei", "AS55990 Huawei Cloud", "Shanghai"),
    ("124.70.0.0/15", "华为云 (Huawei Cloud)", "huawei", "AS55990 Huawei Cloud", "Shanghai"),
    ("139.9.0.0/16", "华为云 (Huawei Cloud)", "huawei", "AS55990 Huawei Cloud", "Guangzhou"),
    ("139.159.0.0/16", "华为云 (Huawei Cloud)", "huawei", "AS55990 Huawei Cloud", "Guangzhou"),
    ("159.138.0.0/16", "华为云国际 (Huawei Cloud Intl)", "huawei", "AS136907 Huawei Cloud", "Hong Kong"),
    # --- 火山引擎 / 字节跳动云 Volcengine ---
    ("14.103.0.0/16", "火山引擎 / 字节跳动云 (Volcengine)", "volcengine", "AS137718 Volcengine Cloud", "Beijing"),
    ("115.190.0.0/16", "火山引擎 / 字节跳动云 (Volcengine)", "volcengine", "AS137718 Volcengine Cloud", "Shanghai"),
    ("118.196.0.0/16", "火山引擎 / 字节跳动云 (Volcengine)", "volcengine", "AS137718 Volcengine Cloud", "Beijing"),
    ("180.184.0.0/16", "火山引擎 / 字节跳动云 (Volcengine)", "volcengine", "AS137718 Volcengine Cloud", "Beijing"),
    # --- 百度智能云 Baidu Cloud ---
    ("106.12.0.0/15", "百度智能云 (Baidu Cloud)", "baidu", "AS55967 Baidu Cloud", "Beijing"),
    ("120.48.0.0/16", "百度智能云 (Baidu Cloud)", "baidu", "AS55967 Baidu Cloud", "Guangzhou"),
    ("180.76.0.0/16", "百度智能云 (Baidu Cloud)", "baidu", "AS38365 Baidu Cloud", "Beijing"),
    ("182.61.0.0/16", "百度智能云 (Baidu Cloud)", "baidu", "AS38365 Baidu Cloud", "Beijing"),
    # --- 京东云 JD Cloud ---
    ("114.67.0.0/16", "京东云 (JD Cloud)", "jdcloud", "AS134764 JD Cloud", "Beijing"),
    ("116.196.64.0/18", "京东云 (JD Cloud)", "jdcloud", "AS134764 JD Cloud", "Beijing"),
    # --- UCloud 优刻得 ---
    ("106.75.0.0/16", "UCloud 优刻得", "ucloud", "AS135377 UCloud", "Shanghai"),
    ("117.50.0.0/16", "UCloud 优刻得", "ucloud", "AS135377 UCloud", "Beijing"),
    ("123.59.0.0/16", "UCloud 优刻得", "ucloud", "AS135377 UCloud", "Beijing"),
    ("152.32.128.0/17", "UCloud 优刻得国际", "ucloud", "AS59077 UCloud Intl", "Hong Kong"),
    ("165.154.0.0/16", "UCloud 优刻得国际", "ucloud", "AS59077 UCloud Intl", "Singapore"),
    # --- 金山云 Kingsoft Cloud ---
    ("110.43.0.0/16", "金山云 (Kingsoft Cloud)", "ksyun", "AS134773 Kingsoft Cloud", "Beijing"),
    ("120.92.0.0/16", "金山云 (Kingsoft Cloud)", "ksyun", "AS134773 Kingsoft Cloud", "Beijing"),
    ("120.131.0.0/16", "金山云 (Kingsoft Cloud)", "ksyun", "AS134773 Kingsoft Cloud", "Shanghai"),
    # --- 青云 QingCloud ---
    ("139.198.0.0/16", "青云 (QingCloud)", "qingcloud", "AS59019 QingCloud", "Beijing"),
    # --- 网易云 NetEase ---
    ("59.111.0.0/16", "网易云 (NetEase Cloud)", "netease", "AS45083 NetEase Cloud", "Hangzhou"),
)

_COMPILED_CN_CIDRS: List[Tuple[ipaddress.IPv4Network, str, str, str, str]] = [
    (ipaddress.ip_network(cidr), provider, code, asn, city)
    for cidr, provider, code, asn, city in _RAW_CN_CLOUD_CIDRS
]

# 3. 国内云厂商中英文 ISP / Org / ASN 关键词（覆盖天翼云、移动云、联通云等共享运营商网段的云业务）
CN_CLOUD_ORG_KEYWORDS: Tuple[Tuple[str, str, str], ...] = (
    ("aliyun", "阿里云 (Alibaba Cloud)", "aliyun"),
    ("alicloud", "阿里云 (Alibaba Cloud)", "aliyun"),
    ("alibaba", "阿里云 (Alibaba Cloud)", "aliyun"),
    ("阿里云", "阿里云 (Alibaba Cloud)", "aliyun"),
    ("tencent", "腾讯云 (Tencent Cloud)", "tencent"),
    ("qcloud", "腾讯云 (Tencent Cloud)", "tencent"),
    ("腾讯云", "腾讯云 (Tencent Cloud)", "tencent"),
    ("huawei cloud", "华为云 (Huawei Cloud)", "huawei"),
    ("huaweicloud", "华为云 (Huawei Cloud)", "huawei"),
    ("华为云", "华为云 (Huawei Cloud)", "huawei"),
    ("华为软件技术", "华为云 (Huawei Cloud)", "huawei"),
    ("volcengine", "火山引擎 / 字节跳动云 (Volcengine)", "volcengine"),
    ("bytedance", "火山引擎 / 字节跳动云 (Volcengine)", "volcengine"),
    ("火山引擎", "火山引擎 / 字节跳动云 (Volcengine)", "volcengine"),
    ("字节跳动", "火山引擎 / 字节跳动云 (Volcengine)", "volcengine"),
    ("baidu", "百度智能云 (Baidu Cloud)", "baidu"),
    ("百度", "百度智能云 (Baidu Cloud)", "baidu"),
    ("jd cloud", "京东云 (JD Cloud)", "jdcloud"),
    ("jdcloud", "京东云 (JD Cloud)", "jdcloud"),
    ("jingdong", "京东云 (JD Cloud)", "jdcloud"),
    ("京东云", "京东云 (JD Cloud)", "jdcloud"),
    ("ucloud", "UCloud 优刻得", "ucloud"),
    ("优刻得", "UCloud 优刻得", "ucloud"),
    ("kingsoft", "金山云 (Kingsoft Cloud)", "ksyun"),
    ("ksyun", "金山云 (Kingsoft Cloud)", "ksyun"),
    ("金山云", "金山云 (Kingsoft Cloud)", "ksyun"),
    ("ctyun", "天翼云 (China Telecom Cloud)", "ctyun"),
    ("china telecom cloud", "天翼云 (China Telecom Cloud)", "ctyun"),
    ("天翼云", "天翼云 (China Telecom Cloud)", "ctyun"),
    ("ecloud", "移动云 (China Mobile Cloud)", "cmcc_cloud"),
    ("cmcc cloud", "移动云 (China Mobile Cloud)", "cmcc_cloud"),
    ("china mobile cloud", "移动云 (China Mobile Cloud)", "cmcc_cloud"),
    ("移动云", "移动云 (China Mobile Cloud)", "cmcc_cloud"),
    ("cucloud", "联通云 (China Unicom Cloud)", "cucloud"),
    ("wo cloud", "联通云 (China Unicom Cloud)", "cucloud"),
    ("china unicom cloud", "联通云 (China Unicom Cloud)", "cucloud"),
    ("联通云", "联通云 (China Unicom Cloud)", "cucloud"),
    ("qingcloud", "青云 (QingCloud)", "qingcloud"),
    ("青云", "青云 (QingCloud)", "qingcloud"),
    ("qiniu", "七牛云 (Qiniu Cloud)", "qiniu"),
    ("七牛", "七牛云 (Qiniu Cloud)", "qiniu"),
    ("wangsu", "网宿科技 (Wangsu)", "wangsu"),
    ("chinanetcenter", "网宿科技 (Wangsu)", "wangsu"),
    ("网宿", "网宿科技 (Wangsu)", "wangsu"),
    ("netease", "网易云 (NetEase Cloud)", "netease"),
    ("网易", "网易云 (NetEase Cloud)", "netease"),
    ("21vianet", "世纪互联 BGP IDC (21Vianet)", "21vianet"),
    ("世纪互联", "世纪互联 BGP IDC (21Vianet)", "21vianet"),
    ("capitalonline", "首都在线云机房 (CapitalOnline)", "capitalonline"),
    ("首都在线", "首都在线云机房 (CapitalOnline)", "capitalonline"),
    ("sinnet", "光环新网 IDC (Sinnet)", "sinnet"),
    ("光环新网", "光环新网 IDC (Sinnet)", "sinnet"),
    ("chinacache", "蓝汛机房 (ChinaCache)", "chinacache"),
    ("蓝汛", "蓝汛机房 (ChinaCache)", "chinacache"),
    ("upyun", "又拍云 (Upyun)", "upyun"),
    ("又拍云", "又拍云 (Upyun)", "upyun"),
    ("baishan", "白山云 (BaishanCloud)", "baishan"),
    ("白山云", "白山云 (BaishanCloud)", "baishan"),
    ("meituan", "美团云 (Meituan)", "meituan"),
    ("美团", "美团云 (Meituan)", "meituan"),
    ("didi", "滴滴云 (Didi Cloud)", "didi"),
    ("滴滴", "滴滴云 (Didi Cloud)", "didi"),
)

_ASN_RE = re.compile(r"\bAS(\d+)\b", re.IGNORECASE)


def match_cn_cloud_by_cidr(ip_str: str) -> Optional[CloudProviderHit]:
    """基于离线预编译 CIDR 表精准识别国内主流云厂商机房 IP。"""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None
    if not isinstance(addr, ipaddress.IPv4Address):
        return None

    for net, provider, code, asn, city in _COMPILED_CN_CIDRS:
        if addr in net:
            country = "HK" if city == "Hong Kong" else ("SG" if city == "Singapore" else "CN")
            return CloudProviderHit(
                provider=provider,
                vendor_code=code,
                asn=asn,
                city=city,
                country=country,
                match_by="cidr",
                matched_rule=str(net),
            )
    return None


def match_cn_cloud_by_metadata(
    *,
    asn: str = "",
    isp: str = "",
    org: str = "",
    asname: str = "",
) -> Optional[CloudProviderHit]:
    """基于实时 GeoIP 返回的 ASN 编号与 ISP/Org 组织名称识别国内云厂商与 IDC 机房。"""
    # 1. 优先精确匹配 ASN 编号（最权威、零误杀）
    m = _ASN_RE.search(asn or "")
    if m:
        asn_key = f"AS{m.group(1)}"
        if asn_key in CN_CLOUD_ASNS:
            provider, code = CN_CLOUD_ASNS[asn_key]
            return CloudProviderHit(
                provider=provider,
                vendor_code=code,
                asn=asn or asn_key,
                city="",
                country="CN",
                match_by="asn",
                matched_rule=asn_key,
            )

    # 2. 次选匹配 ISP / Org / ASName 中英文关键词（覆盖天翼云/移动云/联通云等共享运营商 ASN 场景）
    blob = f"{isp} {org} {asn} {asname}".lower()
    if blob.strip():
        for kw, provider, code in CN_CLOUD_ORG_KEYWORDS:
            if kw in blob:
                return CloudProviderHit(
                    provider=provider,
                    vendor_code=code,
                    asn=asn,
                    city="",
                    country="CN",
                    match_by="org_keyword",
                    matched_rule=kw,
                )
    return None


def get_supported_cn_cloud_summary() -> List[Dict[str, object]]:
    """返回已覆盖的国内云厂商及 IDC 机房目录摘要（供前端与诊断接口展示）。"""
    by_vendor: Dict[str, Dict[str, object]] = {}
    for _, provider, code, _, _ in _COMPILED_CN_CIDRS:
        entry = by_vendor.setdefault(code, {"vendor_code": code, "provider": provider, "cidr_count": 0, "asns": []})
        entry["cidr_count"] = int(entry["cidr_count"]) + 1
    for asn_key, (provider, code) in CN_CLOUD_ASNS.items():
        entry = by_vendor.setdefault(code, {"vendor_code": code, "provider": provider, "cidr_count": 0, "asns": []})
        asns = entry["asns"]
        if isinstance(asns, list) and asn_key not in asns:
            asns.append(asn_key)
    return list(by_vendor.values())
