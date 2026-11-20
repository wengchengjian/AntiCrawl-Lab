# 关卡四：前端防逆向与业务数据混淆（Module 4）

## 教学目标
理解接口签名防重放、动态会话字体映射、Shadow DOM 隔离、工作量证明（PoW）与掺假诱饵数据等纵深业务保护机制。

## 核心检测与混淆机制
1. **接口 HMAC-SHA256 签名与 Nonce 去重（`signature.ts` + `signature.py`）**：
   - 签名原文：`METHOD + "\n" + PATH + "\n" + X-Timestamp + "\n" + X-Nonce`。
   - 时间窗 `±120s`（`SIGNATURE_EXPIRED`），Nonce 通过 Redis/fakeredis `SETNX` 在 `300s` 内去重（`NONCE_REUSED`）。
   - 前端密钥由 12 段字符串常量 + 异或盐拼装（明确声明为刻意逆向教学靶点，而非安全边界）。
2. **动态字体反爬与轮廓微扰（`make_font.py` + `fonts.py`）**：
   - 构建期生成 8 个变体 `.woff2`（无 Brotli 自动退 `.woff`），将 `0-9` 与 `¥` 映射至 `U+E000–U+E00A` 并对控制点施加 ±2 单位微扰与随机字形名。
   - 会话期按 `sha256(session_id) % 8` 下发字体二进制与 `X-Font-Seed`，浏览器正常显示，HTTP 抓取仅为乱码。
3. **多模态价格渲染（`PriceTagElement.ts`）**：
   - Shadow DOM（支持 `open` / `closed`）、Canvas 位图防 OCR 噪线渲染（`?render=canvas`）、CSS Flexbox `order` 乱序 + 零宽诱饵（`?render=css-order`）。
4. **PoW 挑战与诱饵投毒**：
   - 风险分 `40–69` 访问 `/api/v1/products` 返回掺假价格与假 SKU（`DECOY_SERVED`）；访问单品价格接口触发 `403 POW_REQUIRED`，需寻找使 `SHA-256(data + ":" + nonce)` 满足前导零的解答换取 `X-PoW-Token`。
5. **反调试、匿名浏览配额与服务端授时校准**：
   - 闭包内 `debugger` 时间差监测、`fetch`/`XHR.open` 的 `[native code]` 校验、窗口内外尺寸差监测。
   - **匿名浏览深度配额**：`/api/v1/products` 默认允许匿名浏览第 1–2 页，第 3 页起触发 `403 BROWSE_LIMIT_EXCEEDED` 并要求模拟登录（`X-Lab-Auth`）或 PoW 挑战。
   - **服务端授时校准**：前端通过 `GET /api/v1/time` 校准本地与服务端时钟偏差后再生成 `X-Signature`，防止端侧时间漂移导致签名误拦截。

## 预期破绽与演练要点
- 使用 `requests.get('http://127.0.0.1:8000/price').text` 可直接观察源码中价格均为私用区乱码字符。
- 抓包复制合法请求头重放，第二次立即命中 `401 NONCE_REUSED`。
