"""
商品目录真值与诱饵（Decoy）投毒服务（decoy.py，模块四）。

防御什么：
- 当会话风险分 >=40 但未达到 70 拦截线时，避免直接硬拒绝打草惊蛇，
  向采集器投喂掺假价格与伪造 SKU 标记（DECOY_SERVED），污染其离线数据资产。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from app.services.fonts import FontVariantInfo, encode_price_pua


@dataclass(frozen=True)
class ProductItem:
    """靶场商品真值与诱饵对照定义。"""

    id: int
    sku: str
    name: str
    category: str
    real_price: str
    decoy_price: str
    decoy_sku: str
    spec: str


PRODUCTS_CATALOG: List[ProductItem] = [
    ProductItem(
        id=1,
        sku="ACL-HW-01",
        name="PhantomShield 硬件指纹审计卡 Pro",
        category="Hardware Security",
        real_price="¥3999",
        decoy_price="¥2999",
        decoy_sku="ACL-DECOY-991",
        spec="PCIe TLS/JA4 硬件加速分析 · 25Gbps 线速镜像",
    ),
    ProductItem(
        id=2,
        sku="ACL-SW-02",
        name="ZeroTrace 边缘动态混淆网关",
        category="WAF & Edge",
        real_price="¥6480",
        decoy_price="¥4280",
        decoy_sku="ACL-DECOY-992",
        spec="毫秒级动态字体切片 · PoW 弹性降级防护",
    ),
    ProductItem(
        id=3,
        sku="ACL-AI-03",
        name="SentinelEye 轨迹动力学风控引擎",
        category="Behavior Analytics",
        real_price="¥8800",
        decoy_price="¥5199",
        decoy_sku="ACL-DECOY-993",
        spec="生物力学微颤特征建模 · 跨线程 Worker 校验",
    ),
    ProductItem(
        id=4,
        sku="ACL-FP-04",
        name="DeepPrint Canvas/WebGL 探针套件",
        category="Browser Telemetry",
        real_price="¥2560",
        decoy_price="¥1680",
        decoy_sku="ACL-DECOY-994",
        spec="对抗 Canvas 随机加噪 · 跨 Realm Iframe 探测",
    ),
    ProductItem(
        id=5,
        sku="ACL-HP-05",
        name="HoneyMesh 多形态主动诱捕矩阵",
        category="Deception Tech",
        real_price="¥1990",
        decoy_price="¥1290",
        decoy_sku="ACL-DECOY-995",
        spec="CSS 伪元素诱饵 · Shadow DOM 隔离渲染",
    ),
    ProductItem(
        id=6,
        sku="ACL-LAB-06",
        name="AntiCrawl RedTeam 全栈攻防靶机镜像",
        category="Training Lab",
        real_price="¥1299",
        decoy_price="¥899",
        decoy_sku="ACL-DECOY-996",
        spec="含 16 项现代对抗实验与实时 SSE SOC 仪表盘",
    ),
]


def get_product_by_id(product_id: int) -> Optional[ProductItem]:
    """按商品 ID 查找目录条目。"""
    return next((item for item in PRODUCTS_CATALOG if item.id == product_id), None)


def serialize_product_list(
    variant: FontVariantInfo,
    serve_decoy: bool,
    page: int = 1,
    size: int = 6,
) -> List[Dict[str, object]]:
    """
    序列化商品列表；支持分页演示（第 1 页返回 6 款核心商品，第 2–5 页生成分页扩展资产）；
    serve_decoy=True 时返回掺假价格与假 SKU。
    """
    result: List[Dict[str, object]] = []
    start_idx = (page - 1) * size
    for offset in range(size):
        global_idx = start_idx + offset
        base = PRODUCTS_CATALOG[global_idx % len(PRODUCTS_CATALOG)]
        tier_suffix = "" if page == 1 else f" · Page{page} 批次#{global_idx + 1}"
        # 第 2 页起按页码偏移构造真实与诱饵价格，保持清晰可辨
        base_num = int("".join(ch for ch in base.real_price if ch.isdigit()) or "1000")
        decoy_num = int("".join(ch for ch in base.decoy_price if ch.isdigit()) or "700")
        page_delta = (page - 1) * 120
        price_raw = f"¥{decoy_num + page_delta}" if serve_decoy else f"¥{base_num + page_delta}"
        sku_val = (
            (base.decoy_sku if page == 1 else f"{base.decoy_sku}-P{page}")
            if serve_decoy
            else (base.sku if page == 1 else f"{base.sku}-P{page}")
        )
        result.append(
            {
                "id": base.id if page == 1 else (global_idx + 1),
                "sku": sku_val,
                "name": f"{base.name}{tier_suffix}",
                "category": base.category,
                "spec": base.spec,
                "price_pua": encode_price_pua(price_raw, variant),
                "decoy": serve_decoy,
            }
        )
    return result
