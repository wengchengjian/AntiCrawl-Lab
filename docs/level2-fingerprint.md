# 关卡二：浏览器指纹与环境一致性检测（Module 2）

## 教学目标
掌握浏览器多维硬件/图形/声学指纹采集原理，并学会通过「跨维一致性矩阵」与「反噪点/跨线程探针」识别指纹浏览器与伪装插件。

## 核心检测机制
1. **基础与高级独立探针**：
   - Canvas 渐变+文字+投影 SHA-256、WebGL 调试渲染器与参数哈希、`OfflineAudioContext` 音频指纹、50 种字体宽度枚举、可选 WebRTC ICE 探针。
   - 单项被屏蔽时优雅降级（`canvas_blocked` / `audio_blocked` / `webgl_masked=1`），其中 WebGL 掩码或 `SwiftShader` 软渲染器本身记 `WEBGL_MASKED` (+15)。
2. **7 维一致性校验矩阵（`consistency.py`，每条 +20）**：
   - UA OS vs `navigator.platform`
   - UA 品牌 vs `Sec-CH-UA` 品牌
   - UA OS vs WebGL renderer（例如 macOS UA 配 Windows Direct3D 渲染器）
   - `effective_ip` 国家 vs `timezone`（如美国 IP 配 `Asia/Shanghai`）
   - `effective_ip` 国家 vs `languages` 首选语言
   - `platform` vs 屏幕宽高及触控参数
   - 移动设备 UA vs `maxTouchPoints=0`
3. **跨 IP 指纹复用追踪**：
   - 复合 `fp_id` 出现在 `>=3` 个不同 IP 下触发 `FINGERPRINT_REUSE` (+30)，直击代理池一机多号场景。
4. **增强反伪装探针 & 机器人检测置信引擎（`/bot-check` & `/api/v1/bot/check`）**：
   - 双 Canvas 渲染与 ClientRects 亚像素双次测量识破随机加噪插件；Web Worker 跨线程比对 `navigator`；`Date.getTimezoneOffset()` 与 `Intl` 时区交叉验证；JS 引擎 Math 浮点指纹。
   - 融合 **Sannysoft**（Permissions 矛盾、Plugin/MimeType 原型、破损图片、`$cdc_`/CDP/Iframe）、**BrowserScan**（Client Hints、OS×Platform×WebGL、outerWidth=0）与 **BrowserLeaks**（MediaDevices、SpeechSynthesis、WebGL 扩展）30+ 指标输出 `bot_confidence` 置信分与可解释原因。

## 预期破绽与演练要点
- 在 `ProbeTest` 页将模拟 IP 切换到美国机房（`52.95.10.20`）并上报本机上海时区，立即触发 `FINGERPRINT_CONFLICT`。
- 在仪表盘画像抽屉的「环境伪装破绽」分组中可逐条查看左右矛盾证据。
