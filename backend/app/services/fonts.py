"""
动态会话字体服务（fonts.py，模块四）。

检测什么 / 防御什么：
- 按会话标识（session_id / X-Session-Id / effective_ip）通过 hash(session_id) % 8 选定字体变体，
  将真值价格或诱饵价格中的 0-9 与 ¥ 编码为私用区字符 U+E000–U+E00A。
- 仅在 HTTP 响应中下发字体二进制文件与 Seed，绝不把映射字典下发给前端或公开接口。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

FONTS_DIR = Path(__file__).resolve().parent.parent.parent / "static" / "fonts"


@dataclass(frozen=True)
class FontVariantInfo:
    """单个字体变体元信息。"""

    variant_id: int
    filename: str
    seed: str
    fmt: str
    char_to_pua: Dict[str, str]
    file_path: Path


@lru_cache(maxsize=1)
def load_variants() -> List[FontVariantInfo]:
    """加载构建期 scripts/make_font.py 生成的 variants.json 索引。"""
    index_path = FONTS_DIR / "variants.json"
    if not index_path.exists():
        raise FileNotFoundError(
            f"字体索引文件不存在：{index_path}，请先运行 python scripts/make_font.py"
        )
    raw = json.loads(index_path.read_text(encoding="utf-8"))
    fmt = str(raw.get("format", "woff2"))
    variants: List[FontVariantInfo] = []
    for item in raw.get("variants", []):
        vid = int(item["id"])
        filename = str(item["filename"])
        variants.append(
            FontVariantInfo(
                variant_id=vid,
                filename=filename,
                seed=str(item["seed"]),
                fmt=str(item.get("format", fmt)),
                char_to_pua=dict(item["char_to_pua"]),
                file_path=FONTS_DIR / filename,
            )
        )
    return variants


def select_variant_for_session(session_id: str) -> FontVariantInfo:
    """按 sha256(session_id) % len(variants) 确定性选择本会话字体变体。"""
    variants = load_variants()
    digest = hashlib.sha256(session_id.encode("utf-8")).digest()
    idx = int.from_bytes(digest[:4], "big") % len(variants)
    return variants[idx]


def encode_price_pua(plain_price: str, variant: FontVariantInfo) -> str:
    """将明文价格（如 '¥3999' 或 '¥3999.00'）映射为当前会话字体的私用区乱码字符串。"""
    return "".join(variant.char_to_pua.get(ch, ch) for ch in plain_price)
