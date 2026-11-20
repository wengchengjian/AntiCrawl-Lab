# 关卡三：自动化特征与行为动力学检测（Module 3）

## 教学目标
识别 Playwright/Puppeteer/Selenium 自动化特征及初级 Stealth 补丁漏洞，并理解基于轨迹几何学、原生可信度与访问状态图的风控建模。

## 核心检测机制
1. **自动化环境探针（`automation.ts` + `automation.py`）**：
   - `navigator.webdriver` 与 `Navigator.prototype.webdriver` getter 原型链篡改检测 (+50 `AUTOMATION_MARKER`)；
   - `$cdc_` ChromeDriver 注入痕、Selenium 全局属性与历史框架属性 (+40)；
   - CDP `Runtime.enable` 触发 `console.debug` getter 序列化 (+25 `CDP_MARKER`)；
   - 桌面 Chrome UA 缺少 `window.chrome` (+15) 或 `plugins.length === 0` (+10)；
   - 增强：隐藏同源 Iframe 跨 Realm 比对、原生 `fetch`/`XHR` `toString()` 完整性校验与调用栈帧检查。
2. **行为量化阈值（`behavior.py`）**：
   - 轨迹点数 `< 30` (+20 `BOT_TRAJECTORY`)；
   - 方向转折 `< 8` 或相邻点速度标准差 `< 0.05 px/ms` (+25 `BOT_TRAJECTORY`)；
   - 任一事件 `isTrusted === false` (+40 `SYNTHETIC_EVENT`)；
   - 鼠标/键盘/滚动事件总数为 `0` (+30 `NO_INTERACTION_DEEP_ACCESS`)；
   - 页面停留 `< 2s` (+15)；击键间隔方差 `< 30 ms²` (+20 `KEYBOARD_ROBOTIC`)。
3. **会话访问顺序图**：
   - 请求单品价格 `/api/v1/products/{id}/price` 前必须依次出现 `/` 与 `/api/v1/products`，否则记 `VISIT_ORDER_VIOLATION` (+30)。

## 预期破绽与演练要点
- 使用未做隐藏的 Playwright 无头模式访问 `/probes` 即命中 `AUTOMATION_MARKER` 与 `webdriver=true`。
- 在 `/probes` 页点击「注入 30 点合成事件」或「注入 30 点直线轨迹」，实时画布变红并立即在仪表盘看到对应告警。
