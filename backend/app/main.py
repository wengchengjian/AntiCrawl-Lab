"""
AntiCrawl Lab FastAPI 入口文件（main.py）。
默认绑定 127.0.0.1（见第 2 章与第 17 章安全边界，不做公网监听）。
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.v1 import (
    admin,
    behavior,
    bot_check,
    browse,
    challenge,
    events,
    fingerprint,
    fonts,
    health,
    ip_intel,
    products,
    server_time,
    trap,
    waf,
)
from app.config import get_settings
from app.db import init_db
from app.middleware.risk import RiskMiddleware
from app.services.decoy import PRODUCTS_CATALOG
from app.services.fonts import encode_price_pua, load_variants, select_variant_for_session
from app.services.retention import retention_worker

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """应用启停生命周期：建表、预置 GeoIP 种子、预加载字体索引、启动每日留存清理后台任务。"""
    init_db()
    load_variants()
    stop_event = asyncio.Event()
    cleanup_task = asyncio.create_task(retention_worker(stop_event))
    try:
        yield
    finally:
        stop_event.set()
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass


def create_app() -> FastAPI:
    """构建并返回配置完整的 FastAPI 应用实例。"""
    settings = get_settings()
    app = FastAPI(
        title="AntiCrawl Lab API",
        version="2.0.0",
        description="防爬虫安全教学与对抗演练靶场（仅限本地隔离安全研究使用）",
        lifespan=lifespan,
    )

    # 先挂载风控流水线，再挂载 CORS（确保异常响应仍带 CORS 头）
    app.add_middleware(RiskMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "X-Font-Seed",
            "X-Font-Variant",
            "X-RateLimit-Tier",
            "X-RateLimit-Burst-Capacity",
            "X-RateLimit-Replenish-Rate",
            "X-RateLimit-Remaining",
            "X-RateLimit-Requested-Tokens",
            "X-Request-Id",
            "X-WAF-Challenge",
        ],
    )

    app.include_router(health.router)
    app.include_router(server_time.router)
    app.include_router(fingerprint.router)
    app.include_router(behavior.router)
    app.include_router(bot_check.router)
    app.include_router(ip_intel.router)
    app.include_router(waf.router)
    app.include_router(browse.router)
    app.include_router(products.router)
    app.include_router(fonts.router)
    app.include_router(challenge.router)
    app.include_router(trap.router)
    app.include_router(events.router)
    app.include_router(admin.router)

    @app.exception_handler(HTTPException)
    async def unified_http_exception_handler(_request: Request, exc: HTTPException) -> JSONResponse:
        """统一 HTTPException JSON 响应格式（对齐第 6.3 节契约）。"""
        if isinstance(exc.detail, dict) and "code" in exc.detail and "risk_reason" in exc.detail:
            return JSONResponse(status_code=exc.status_code, content=exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "code": exc.status_code,
                "message": str(exc.detail),
                "risk_reason": "NOT_FOUND" if exc.status_code == 404 else "ERROR",
            },
        )

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", tags=["demo"])
    def index_root(request: Request) -> HTMLResponse:
        """
        靶场后端首页导航点（同时向 10.3 访问顺序图登记 `/`）。
        正常浏览器 SPA 入口运行在前端端口（默认 5173），此处亦供单测与纯后端访序演练。
        """
        from app.services.behavior import record_visit
        from app.services.geoip import resolve_effective_ip

        client_ip = request.client.host if request.client else "127.0.0.1"
        effective_ip, _ = resolve_effective_ip(client_ip, request.headers, settings.lab_mode)
        sid = request.headers.get("x-session-id", "").strip() or effective_ip
        record_visit(sid, "/")
        if sid != effective_ip:
            record_visit(effective_ip, "/")

        return HTMLResponse(
            content=(
                "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'/>"
                "<title>AntiCrawl Lab Backend</title></head>"
                "<body style='background:#060a12;color:#e2e8f0;font-family:monospace;padding:2rem'>"
                "<h1>AntiCrawl Lab API v2.0</h1>"
                "<p>状态：<a href='/api/v1/health' style='color:#00f5a0'>/api/v1/health</a> | "
                "动态字体演示：<a href='/price' style='color:#00d9f5'>/price</a> | "
                "OpenAPI 文档：<a href='/docs' style='color:#00d9f5'>/docs</a></p>"
                "<a href='/api/v1/trap' style='display:none'>Hidden Trap</a>"
                "</body></html>"
            )
        )

    @app.get("/price", response_class=HTMLResponse, tags=["demo"])
    @app.get("/ssr/price", response_class=HTMLResponse, tags=["demo"])
    def ssr_price_demo(request: Request) -> HTMLResponse:
        """
        轻量 SSR 动态字体演示页（验收用例 10 辅助验证）：
        - HTTP 源码仅包含私用区 PUA 乱码（U+E000–U+E00A），无明文阿拉伯数字价格；
        - 浏览器加载 /api/v1/font/session 后通过 @font-face 正确渲染为可读数字。
        """
        sid = request.query_params.get("sid") or (request.client.host if request.client else "demo-sid")
        variant = select_variant_for_session(sid)
        fmt = "woff2" if variant.fmt == "woff2" else "woff"
        cards_html = "\n".join(
            f'<div class="card"><h3>{item.name}</h3>'
            f'<p class="sku">{item.sku}</p>'
            f'<p class="price">{encode_price_pua(item.real_price, variant)}</p></div>'
            for item in PRODUCTS_CATALOG
        )
        html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>AntiCrawl Lab · 动态字体 SSR 价格演示</title>
  <style>
    @font-face {{
      font-family: 'AnticrawlDigits';
      src: url('/api/v1/font/session?sid={sid}') format('{fmt}');
      font-display: swap;
    }}
    body {{ background:#060a12; color:#e2e8f0; font-family: system-ui, sans-serif; padding:2rem; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:1rem; }}
    .card {{ background:#111a2e; border:1px solid #1e2c48; border-radius:12px; padding:1rem; }}
    .price {{ font-family:'AnticrawlDigits', monospace; font-size:2rem; color:#00f5a0; margin:0.5rem 0 0; }}
    .sku {{ color:#94a3b8; font-size:0.85rem; }}
    .trap {{ display:none; }}
  </style>
</head>
<body>
  <h1>动态会话字体价格演示（Variant #{variant.variant_id} · Seed {variant.seed}）</h1>
  <p>提示：直接用 requests.get(...).text 查看 HTML 源码，价格文本均为 Unicode 私用区乱码。</p>
  <div class="grid">{cards_html}</div>
  <a class="trap" href="/api/v1/trap">Internal Admin Pricing Export</a>
</body>
</html>"""
        return HTMLResponse(content=html)

    return app


app = create_app()
