#!/usr/bin/env python3
"""
构建期动态反爬字体生成器（Module 4 核心组件）

检测什么 / 防御什么：
- 针对「直接请求 HTTP 文本 / 正则提取价格 / 离线维护固定 PUA 映射表 / 字形轮廓哈希比对」的采集器。
为什么需要：
- 将真实数字 0-9 与货币符号 ¥ 映射到 Unicode 私用区 U+E000–U+E00A，使原始 HTML/JSON 文本变成乱码；
- 生成 8 个变体，每个变体不仅码点排列不同，还对字形控制点施加 ±2 单位微扰并随机化字形名，
  抬高攻击者通过字形 MD5 离线建表的成本，迫使其按会话解析字体或走 OCR。
阈值/参数依据：
- 8 个变体（`variant_0` ~ `variant_7`）与 ±2 UPM 微扰（在 1000 UPM 下视觉无感但足使二进制与轮廓哈希完全不同）。
"""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

# 目标字符集：11 个核心字符映射到 U+E000 ~ U+E00A
TARGET_CHARS: List[str] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¥"]
PUA_START = 0xE000
VARIANT_COUNT = 8

ROOT_DIR = Path(__file__).resolve().parent.parent
FONT_OUTPUT_DIR = ROOT_DIR / "backend" / "static" / "fonts"

Point = Tuple[int, int]
Polygon = List[Point]


def _has_brotli() -> bool:
    """检测当前环境是否支持 Brotli（用于输出 woff2；缺失时降级输出 woff）。"""
    try:
        import brotli  # noqa: F401
        return True
    except ImportError:
        return False


def _rect_poly(x0: int, y0: int, x1: int, y1: int) -> Polygon:
    """生成顺时针矩形轮廓（TrueType 外轮廓标准绕向）。"""
    return [(x0, y0), (x0, y1), (x1, y1), (x1, y0)]


def _quad_poly(p0: Point, p1: Point, p2: Point, p3: Point) -> Polygon:
    """生成顺时针四边形轮廓。"""
    return [p0, p1, p2, p3]


def _seven_segment_glyphs() -> Dict[str, List[Polygon]]:
    """
    构造极客等宽风格的 0-9、¥、. 纯矢量多边形集合（1000 UPM，advanceWidth=620）。
    所有笔画彼此不重叠，避免自相交导致跨平台光栅化差异。
    """
    # 7 段坐标基准：左右 x=[90, 530]，上中下 y=[680, 365, 40]，笔宽 t=76
    lx, rx = 95, 525
    ty, my, by = 700, 370, 40
    t = 74
    gap = 10

    seg_a = _rect_poly(lx + t + gap, ty - t, rx - t - gap, ty)          # 上横
    seg_g = _rect_poly(lx + t + gap, my - t // 2, rx - t - gap, my + t // 2)  # 中横
    seg_d = _rect_poly(lx + t + gap, by, rx - t - gap, by + t)          # 下横
    seg_f = _rect_poly(lx, my + gap, lx + t, ty)                        # 左上竖
    seg_e = _rect_poly(lx, by, lx + t, my - gap)                        # 左下竖
    seg_b = _rect_poly(rx - t, my + gap, rx, ty)                        # 右上竖
    seg_c = _rect_poly(rx - t, by, rx, my - gap)                        # 右下竖

    digits_map: Dict[str, List[str]] = {
        "0": ["a", "b", "c", "d", "e", "f"],
        "1": ["b", "c"],
        "2": ["a", "b", "g", "e", "d"],
        "3": ["a", "b", "g", "c", "d"],
        "4": ["f", "g", "b", "c"],
        "5": ["a", "f", "g", "c", "d"],
        "6": ["a", "f", "g", "e", "c", "d"],
        "7": ["a", "b", "c"],
        "8": ["a", "b", "c", "d", "e", "f", "g"],
        "9": ["a", "b", "c", "d", "f", "g"],
    }
    segs = {"a": seg_a, "b": seg_b, "c": seg_c, "d": seg_d, "e": seg_e, "f": seg_f, "g": seg_g}

    glyphs: Dict[str, List[Polygon]] = {
        ch: [segs[s] for s in names] for ch, names in digits_map.items()
    }

    # 小数点 '.'
    glyphs["."] = [_rect_poly(260, 40, 360, 140)]

    # 人民币符号 '¥'：两道斜臂 + 竖干 + 两道横杠（互不重叠）
    cx = 310
    stem_half = 36
    glyphs["¥"] = [
        # 左上斜臂
        _quad_poly((90, 700), (176, 700), (cx - 10, 430), (cx - 70, 430)),
        # 右上斜臂
        _quad_poly((cx + 10, 430), (cx + 70, 430), (530, 700), (444, 700)),
        # 中央竖干（从交叉点到底部）
        _rect_poly(cx - stem_half, 40, cx + stem_half, 420),
        # 上横杠（左右两段，避免与竖干重叠）
        _rect_poly(120, 305, cx - stem_half - 8, 365),
        _rect_poly(cx + stem_half + 8, 305, 500, 365),
        # 下横杠
        _rect_poly(120, 175, cx - stem_half - 8, 235),
        _rect_poly(cx + stem_half + 8, 175, 500, 235),
    ]
    return glyphs


def _draw_polygons(polygons: Sequence[Polygon], rng: random.Random, jitter: int = 2) -> object:
    """绘制多边形集合并施加 ±jitter 单位微扰，防止字形轮廓静态 MD5 识别。"""
    pen = TTGlyphPen(None)
    for poly in polygons:
        pts = [
            (x + rng.randint(-jitter, jitter), y + rng.randint(-jitter, jitter))
            for x, y in poly
        ]
        pen.moveTo(pts[0])
        for pt in pts[1:]:
            pen.lineTo(pt)
        pen.closePath()
    return pen.glyph()


def build_variant(variant_id: int, out_dir: Path, use_woff2: bool) -> Dict[str, object]:
    """构建单个动态字体变体并返回其索引元信息。"""
    seed_hex = hashlib.sha256(f"anticrawl-lab-font-v2-{variant_id}".encode("utf-8")).hexdigest()[:16]
    rng = random.Random(int(seed_hex, 16))

    shuffled_chars = TARGET_CHARS.copy()
    rng.shuffle(shuffled_chars)

    char_to_pua: Dict[str, str] = {}
    pua_to_char: Dict[str, str] = {}
    for idx, ch in enumerate(shuffled_chars):
        pua_code = PUA_START + idx
        pua_char = chr(pua_code)
        char_to_pua[ch] = pua_char
        pua_to_char[f"U+{pua_code:04X}"] = ch

    base_polygons = _seven_segment_glyphs()

    # 随机构造字形名，防止攻击者按 glyphName 反推真实数字
    glyph_order = [".notdef", "space", "period"]
    pua_glyph_names: Dict[int, str] = {}
    for idx in range(len(shuffled_chars)):
        code = PUA_START + idx
        gname = f"ac_{variant_id}_{rng.randint(10000, 99999)}_{idx}"
        pua_glyph_names[code] = gname
        glyph_order.append(gname)

    fb = FontBuilder(1000, isTTF=True)
    fb.setupGlyphOrder(glyph_order)

    cmap: Dict[int, str] = {
        0x0020: "space",
        0x002E: "period",
    }
    for idx, ch in enumerate(shuffled_chars):
        code = PUA_START + idx
        cmap[code] = pua_glyph_names[code]
    fb.setupCharacterMap(cmap)

    empty_pen = TTGlyphPen(None)
    notdef_pen = TTGlyphPen(None)
    # .notdef 简单空框
    for pt in _rect_poly(80, 40, 540, 700):
        if pt == (80, 40):
            notdef_pen.moveTo(pt)
        else:
            notdef_pen.lineTo(pt)
    notdef_pen.closePath()

    glyf_map = {
        ".notdef": notdef_pen.glyph(),
        "space": empty_pen.glyph(),
        "period": _draw_polygons(base_polygons["."], rng, jitter=1),
    }
    metrics = {
        ".notdef": (620, 80),
        "space": (360, 0),
        "period": (340, 260),
    }

    for idx, ch in enumerate(shuffled_chars):
        code = PUA_START + idx
        gname = pua_glyph_names[code]
        glyf_map[gname] = _draw_polygons(base_polygons[ch], rng, jitter=2)
        metrics[gname] = (620, 90)

    fb.setupGlyf(glyf_map)
    fb.setupHorizontalMetrics(metrics)
    fb.setupHorizontalHeader(ascent=820, descent=-180)
    fb.setupNameTable(
        {
            "familyName": "AnticrawlDigits",
            "styleName": "Regular",
        }
    )
    fb.setupOS2(sTypoAscender=820, sTypoDescender=-180, usWinAscent=820, usWinDescent=180)
    fb.setupPost()

    ext = "woff2" if use_woff2 else "woff"
    filename = f"variant_{variant_id}.{ext}"
    out_path = out_dir / filename
    fb.font.flavor = ext
    fb.save(str(out_path))

    return {
        "id": variant_id,
        "filename": filename,
        "seed": seed_hex,
        "format": ext,
        "char_to_pua": char_to_pua,
        "pua_to_char": pua_to_char,
    }


def main() -> None:
    FONT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    use_woff2 = _has_brotli()
    fmt = "woff2" if use_woff2 else "woff"
    variants: List[Dict[str, object]] = []

    for vid in range(VARIANT_COUNT):
        variants.append(build_variant(vid, FONT_OUTPUT_DIR, use_woff2=use_woff2))

    index_payload = {
        "version": 2,
        "format": fmt,
        "pua_range": f"U+{PUA_START:04X}-U+{PUA_START + len(TARGET_CHARS) - 1:04X}",
        "variants": variants,
    }
    index_path = FONT_OUTPUT_DIR / "variants.json"
    index_path.write_text(json.dumps(index_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[make_font] Generated {VARIANT_COUNT} {fmt} font variants in {FONT_OUTPUT_DIR}")


if __name__ == "__main__":
    main()
