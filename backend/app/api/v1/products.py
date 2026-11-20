"""
核心数据与价格接口（端点 4：GET /api/v1/products；端点 5：GET /api/v1/products/{id}/price）。
受 Step ⑥ HMAC-SHA256 强制签名保护，并与诱饵投毒、PoW 挑战、动态字体与访问顺序图联动。
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from app.cache import get_cache
from app.config import get_settings
from app.constants import DECISION_THRESHOLDS, ReasonCode, RiskAction
from app.middleware.risk import RiskContext
from app.services.behavior import check_price_visit_order, record_visit
from app.services.browse_quota import check_and_record_page_browse
from app.services.decoy import get_product_by_id, serialize_product_list
from app.services.fonts import encode_price_pua, select_variant_for_session
from app.services.pow import is_pow_token_valid, issue_pow_challenge

router = APIRouter(tags=["products"])


@router.get("/api/v1/products")
def list_products(
    request: Request,
    page: int = Query(default=1, ge=1, le=20),
    size: int = Query(default=6, ge=1, le=20),
) -> Any:
    """
    端点 4：商品列表（签名接口；风险分 ≥40 时投喂掺假诱饵数据；支持匿名浏览深度配额校验）。
    同时向会话访问顺序图登记 `/api/v1/products`。
    """
    settings = get_settings()
    ctx: RiskContext | None = getattr(request.state, "risk_ctx", None)
    session_id = ctx.session_id if ctx else (request.client.host if request.client else "default")
    effective_ip = ctx.effective_ip if ctx else session_id

    # 若前端从首页导航过来（或携带 X-Visit-Origin: /），补记起点 '/'
    if request.headers.get("x-visit-origin", "").strip() == "/":
        record_visit(session_id, "/")
        if session_id != effective_ip:
            record_visit(effective_ip, "/")

    record_visit(session_id, "/api/v1/products")
    if session_id != effective_ip:
        record_visit(effective_ip, "/api/v1/products")

    # 匿名浏览深度配额校验（复刻 pxb7 queryBrowseLimit：免费前 2 页，深翻页需模拟登录或 PoW）
    auth_token = request.headers.get("x-lab-auth", "").strip()
    pow_ok = is_pow_token_valid(request.headers.get("x-pow-token", "").strip())
    quota_res = check_and_record_page_browse(
        effective_ip,
        page=page,
        auth_token=auth_token,
        pow_ok=pow_ok,
        settings=settings,
    )
    if not quota_res.allowed:
        challenge = issue_pow_challenge(settings.pow_difficulty, effective_ip)
        get_cache().set(f"pow_last:{effective_ip}", challenge["data"], ex=60)
        if ctx is not None:
            ctx.action = RiskAction.CHALLENGE.value
            ctx.add_signal(0, ReasonCode.POW_REQUIRED.value, quota_res.reason)
            ctx.extra["detail_code"] = "BROWSE_LIMIT_EXCEEDED"
        return JSONResponse(
            status_code=403,
            content={
                "code": 403,
                "message": quota_res.reason,
                "risk_reason": ReasonCode.POW_REQUIRED.value,
                "detail_code": "BROWSE_LIMIT_EXCEEDED",
                "max_anon_page": settings.anon_max_page,
                "requested_page": page,
                "browse_quota": quota_res.quota,
                "challenge": challenge,
            },
        )

    risk_score = ctx.score if ctx else 0
    serve_decoy = risk_score >= DECISION_THRESHOLDS["WARN_MIN"]

    variant = select_variant_for_session(session_id)
    items = serialize_product_list(variant, serve_decoy=serve_decoy, page=page, size=size)

    resp: Dict[str, Any] = {
        "items": items,
        "font_seed": variant.seed,
        "variant": variant.variant_id,
        "page": page,
        "size": size,
        "total_pages": 5,
        "browse_quota": quota_res.quota,
    }
    if serve_decoy and ctx is not None:
        ctx.decoy_served = True
        ctx.add_signal(0, ReasonCode.DECOY_SERVED.value, f"风险分 {risk_score} ≥ 40，已向列表注入掺假诱饵价格")
        resp["decoy_hint"] = "检测到中高风险会话特征，已激活数据投毒诱饵价格"

    return resp


@router.get("/api/v1/products/{product_id}/price")
def get_product_price(product_id: int, request: Request) -> Any:
    """
    端点 5：单品价格（签名 + 访问顺序图 + 会话字体 + 灰区触发 PoW 挑战）。
    """
    item = get_product_by_id(product_id)
    if item is None:
        raise HTTPException(status_code=404, detail="商品不存在")

    settings = get_settings()
    ctx: RiskContext | None = getattr(request.state, "risk_ctx", None)
    session_id = ctx.session_id if ctx else (request.client.host if request.client else "default")
    effective_ip = ctx.effective_ip if ctx else session_id

    # 1. 10.3 访问顺序图校验：先 '/' 后 '/api/v1/products'
    order_ok = check_price_visit_order(session_id) or (
        session_id != effective_ip and check_price_visit_order(effective_ip)
    )
    if not order_ok and ctx is not None:
        ctx.add_signal(30, ReasonCode.VISIT_ORDER_VIOLATION.value, "未经首页与列表页导航直访价格接口 (+30)")
        # 若既跳过导航顺序又未上报任何交互行为，判定为无交互直奔深层（10.2）
        cache = get_cache()
        beh_cnt = cache.get(f"beh_events_count:{session_id}") or cache.get(f"beh_events_count:{effective_ip}")
        if beh_cnt is None:
            ctx.add_signal(
                30,
                ReasonCode.NO_INTERACTION_DEEP_ACCESS.value,
                "会话无任何前端交互轨迹记录即直奔单品价格接口 (+30)",
            )

    risk_score = ctx.score if ctx else 0
    pow_token = request.headers.get("x-pow-token", "").strip()
    pow_ok = is_pow_token_valid(pow_token)

    # 2. 高危 ≥70 拦截
    if risk_score >= DECISION_THRESHOLDS["BLOCK_MIN"]:
        if ctx is not None:
            ctx.action = RiskAction.BLOCK.value
        primary = (ctx.reasons[0] if (ctx and ctx.reasons) else ReasonCode.VISIT_ORDER_VIOLATION.value)
        return JSONResponse(
            status_code=403,
            content={
                "code": 403,
                "message": f"累计风险分 {risk_score} 达到拦截阈值（≥70），拒绝下发单品价格",
                "risk_reason": primary,
                "risk_score": risk_score,
                "reasons": ctx.reasons if ctx else [],
            },
        )

    # 3. 灰区 40–69 且无有效 X-PoW-Token → 返回 PoW 挑战
    if risk_score >= DECISION_THRESHOLDS["WARN_MIN"] and not pow_ok:
        challenge = issue_pow_challenge(settings.pow_difficulty, effective_ip)
        get_cache().set(f"pow_last:{effective_ip}", challenge["data"], ex=60)
        if ctx is not None:
            ctx.action = RiskAction.CHALLENGE.value
            ctx.add_signal(0, ReasonCode.POW_REQUIRED.value, "风险分处于 40–69 灰区，转交 PoW 算力挑战")
        return JSONResponse(
            status_code=403,
            content={
                "code": 403,
                "message": "会话处于中高风险灰区，请先完成 PoW 工作量证明挑战",
                "risk_reason": ReasonCode.POW_REQUIRED.value,
                "challenge": challenge,
                "risk_score": risk_score,
            },
        )

    # 4. 放行并返回动态会话字体编码后的 PUA 价格
    variant = select_variant_for_session(session_id)
    serve_decoy = False
    if risk_score >= DECISION_THRESHOLDS["WARN_MIN"] and not pow_ok:
        serve_decoy = True

    plain_price = item.decoy_price if serve_decoy else item.real_price
    if serve_decoy and ctx is not None:
        ctx.decoy_served = True
        ctx.add_signal(0, ReasonCode.DECOY_SERVED.value, "已下发单品诱饵价格")

    return {
        "id": item.id,
        "sku": item.decoy_sku if serve_decoy else item.sku,
        "name": item.name,
        "price_pua": encode_price_pua(plain_price, variant),
        "font_seed": variant.seed,
        "variant": variant.variant_id,
        "pow_verified": pow_ok,
        "decoy_served": serve_decoy,
    }
