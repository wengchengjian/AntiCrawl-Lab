# 关卡一：网络与协议层检测（Module 1）

## 教学目标
理解服务端在不依赖前端 JS 探针时，如何在中间件最前线拦截高并发扫段、脚本 HTTP 库与恶意解析器。

## 核心检测机制
1. **滑动窗口限流 + 分级网关令牌桶（Redis / fakeredis）**：
   - 按 `rl:{effective_ip}`（默认 10 QPS）与 `rl:fp:{fp_id}`（默认 30 QPS）统计 1 秒内请求数，超限即在 Step ② 返回 `429 RATE_LIMITED`。
   - **分级令牌桶扩展**：普通域 `public`（60 burst / 30/s）与高敏域 `sensitive`（8 burst / 4/s，覆盖底价/PoW/WAF）独立限流，并输出标准 `X-RateLimit-*` 与 `X-Request-Id` 响应头。
   - 增强：计算同一 IP 请求间隔的变异系数（CV < 0.08 判为定频睡眠脚本）。
2. **边缘 WAF 200 HTML 透明 JS 动态挑战（`timestamp__1366`）**：
   - `/api/v1/waf/protected-feed` 对未携带有效一次性令牌的请求返回 `200 text/html` 混淆脚本，强制客户端计算 SHA-256 签名参数后再自动放行 JSON。
2. **条件式 Header 规则**：
   - UA 缺失（+40）、已知采集库特征（`python-requests` / `curl` / `HeadlessChrome` 等 +35）、Chromium UA 却缺少 `Sec-CH-UA`（+20，非 Chromium 不误判）、`Sec-CH-UA` 品牌矛盾（+25）、缺少 `Accept-Language`（+15）。
   - 可选扩展：`X-JA4` TLS 指纹交叉校验与 `X-Header-Order` 顺序基线。
3. **Mock GeoIP 与代理识别**：
   - 在 `LAB_MODE=1` 时通过 `X-Simulated-IP` 演练上海/北京住宅段 vs 美国 AWS/香港阿里云机房段（`DATACENTER_IP` +25）与黑名单段（`BLACKLIST_IP` +25）。
4. **4 形态蜜罐矩阵**：
   - `display:none` 链接、`opacity:0` 视口外链接、隐藏表单诱饵域（`POST /api/v1/trap/form`）、CSS `::before` 伪元素链接。触发即写 `bans` 表与缓存黑名单，后续全部返回 `403 BANNED`。

## 预期破绽与演练要点
- 直接用 `requests.get` 不带浏览器头即可在仪表盘看到 `HEADER_INCONSISTENT` 与 `HEADER_MISSING`。
- 1 秒内连打 11 次即可观察第 11 次准确短路为 `429`。
- 触发 `/api/v1/trap` 后，即使换回正常浏览器头也会在流水线 Step ① 被拦截，需经仪表盘点击「一键解封」恢复。
