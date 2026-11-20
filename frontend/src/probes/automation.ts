/**
 * 自动化工具、CDP 协议、原生函数完整性与反调试自检探针（模块三 & 模块四 11.4）。
 *
 * 检测什么：
 * 1. navigator.webdriver 直读与 Navigator.prototype.webdriver 属性描述符篡改（识破初级 stealth 插件）。
 * 2. ChromeDriver 注入痕（window/document 键名含 $cdc_ 前缀）与 Selenium/历史框架全局属性。
 * 3. window.chrome 缺失、plugins 为空。
 * 4. CDP Runtime.enable 序列化触发的 console.debug getter 探针与 Error().stack 自动化帧。
 * 5. 原生函数完整性（fetch / XMLHttpRequest.prototype.open 是否偏离 [native code]）。
 * 6. 增强实验：隐藏同源 Iframe 跨 Realm 比对（识破仅 patch 顶层 window 的伪装脚本）。
 * 7. 11.4 反调试：DevTools 尺寸差值与闭包内 debugger 时间差自检。
 * 为什么可疑：
 * - 无头浏览器与自动化驱动框架会在原型链、Window 全局符号与多 Realm 之间留下极难完全消除的痕迹。
 * 阈值依据：
 * - webdriver/getter 篡改 +50，cdc/Selenium +40，CDP +25，原生函数 Hook / Iframe 跨帧矛盾 +25。
 */

import type { AutomationSignals } from '@/types/lab'

const SELENIUM_PROPS: readonly string[] = [
  '__webdriver_evaluate',
  '__selenium_unwrapped',
  '__driver_evaluate',
  '__webdriver_script_fn',
  '__fxdriver_unwrapped',
  '__webdriver_unwrapped',
]

const LEGACY_PROPS: readonly string[] = ['_phantom', '__nightmare', 'callSelenium', 'domAutomation']

function checkWebdriverAndGetter(): { webdriver: boolean; getterTampered: boolean } {
  const webdriver = navigator.webdriver === true
  let getterTampered = false
  try {
    // 1. 正常浏览器中 webdriver 定义在 Navigator.prototype 上，而非 navigator 实例自身属性
    const ownDesc = Object.getOwnPropertyDescriptor(navigator, 'webdriver')
    if (ownDesc) {
      getterTampered = true
    }
    // 2. 校验原型链上 getter 的 toString() 是否仍为 [native code]
    const protoDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver')
    if (protoDesc?.get) {
      const src = Function.prototype.toString.call(protoDesc.get)
      if (!src.includes('[native code]')) {
        getterTampered = true
      }
    }
  } catch {
    getterTampered = true
  }
  return { webdriver, getterTampered }
}

function scanInjectedKeys(): { cdc: string[]; selenium: string[]; legacy: string[] } {
  const cdc = new Set<string>()
  const selenium = new Set<string>()
  const legacy = new Set<string>()

  const scanObj = (target: object) => {
    try {
      for (const k of Object.getOwnPropertyNames(target)) {
        if (k.startsWith('$cdc_') || k.includes('cdc_')) cdc.add(k)
      }
    } catch {
      // 忽略访问受限属性
    }
  }
  scanObj(window)
  scanObj(document)

  const winRec = window as unknown as Record<string, unknown>
  const docRec = document as unknown as Record<string, unknown>

  for (const prop of SELENIUM_PROPS) {
    if (prop in window || prop in document || winRec[prop] !== undefined || docRec[prop] !== undefined) {
      selenium.add(prop)
    }
  }
  for (const prop of LEGACY_PROPS) {
    if (prop in window || winRec[prop] !== undefined) {
      legacy.add(prop)
    }
  }

  return {
    cdc: Array.from(cdc),
    selenium: Array.from(selenium),
    legacy: Array.from(legacy),
  }
}

function probeCdpConsoleGetter(): boolean {
  let cdpTriggered = false
  try {
    // 利用 CDP Runtime.enable 启用时对 console 参数执行属性预览序列化的副作用
    const trapObj: Record<string, unknown> = {}
    Object.defineProperty(trapObj, 'acl_cdp_probe', {
      enumerable: true,
      get() {
        cdpTriggered = true
        return 'probe'
      },
    })
    console.debug(trapObj)
  } catch {
    // 忽略异常
  }
  return cdpTriggered
}

function checkNativeIntegrity(): boolean {
  try {
    const fetchStr = Function.prototype.toString.call(window.fetch)
    const xhrStr = Function.prototype.toString.call(XMLHttpRequest.prototype.open)
    const fetchHooked = !fetchStr.includes('[native code]')
    const xhrHooked = !xhrStr.includes('[native code]')
    return fetchHooked || xhrHooked
  } catch {
    return true
  }
}

function checkIframeCrossRealm(): boolean {
  try {
    const iframe = document.createElement('iframe')
    iframe.style.cssText = 'display:none;width:0;height:0;border:0;'
    document.body.appendChild(iframe)
    let mismatch = false
    const iWin = iframe.contentWindow
    if (iWin) {
      const mainWebdriver = navigator.webdriver === true
      const iframeWebdriver = iWin.navigator.webdriver === true
      if (mainWebdriver !== iframeWebdriver) {
        mismatch = true
      }
      if (navigator.plugins.length !== iWin.navigator.plugins.length) {
        mismatch = true
      }
      const mainToStr = Function.prototype.toString.call(navigator.permissions.query)
      const iframeToStr = (iWin as unknown as { Function: typeof Function }).Function.prototype.toString.call(
        iWin.navigator.permissions.query
      )
      if (mainToStr.includes('[native code]') !== iframeToStr.includes('[native code]')) {
        mismatch = true
      }
    }
    document.body.removeChild(iframe)
    return mismatch
  } catch {
    return false
  }
}

function checkStackAutomationFrame(): boolean {
  try {
    const err = new Error('acl_stack_probe')
    const stack = (err.stack || '').toLowerCase()
    return ['puppeteer', 'playwright', '__playwright', 'pptr:', 'selenium'].some((k) =>
      stack.includes(k)
    )
  } catch {
    return false
  }
}

export function detectDevtoolsSizeDiff(): boolean {
  const widthDiff = Math.abs((window.outerWidth || 0) - (window.innerWidth || 0))
  const heightDiff = Math.abs((window.outerHeight || 0) - (window.innerHeight || 0))
  return widthDiff > 160 || heightDiff > 180
}

/**
 * 11.4 反调试时间差自检（在闭包内执行 debugger，以 Date.now 差值识别开发者工具单步暂停）。
 */
export function runAntiDebugSelfCheck(cycles = 1): { triggered: boolean; deltaMs: number } {
  let maxDelta = 0
  let triggered = false
  for (let i = 0; i < cycles; i++) {
    const delta = (function () {
      const t0 = Date.now()
      // eslint-disable-next-line no-debugger
      debugger
      return Date.now() - t0
    })()
    if (delta > maxDelta) maxDelta = delta
    if (delta > 120) {
      triggered = true
      break
    }
  }
  return { triggered: triggered || detectDevtoolsSizeDiff(), deltaMs: maxDelta }
}

export function probeAutomation(runDebuggerProbe = false): AutomationSignals {
  const { webdriver, getterTampered } = checkWebdriverAndGetter()
  const injected = scanInjectedKeys()
  const cdpConsole = probeCdpConsoleGetter()
  const hookedNative = checkNativeIntegrity()
  const iframeMismatch = checkIframeCrossRealm()
  const stackAutomation = checkStackAutomationFrame()
  const devtoolsOpen = runDebuggerProbe
    ? runAntiDebugSelfCheck(1).triggered
    : detectDevtoolsSizeDiff()

  const hasWindowChrome =
    'chrome' in window && typeof (window as unknown as { chrome?: unknown }).chrome === 'object'

  return {
    webdriver,
    webdriver_getter_tampered: getterTampered,
    cdc_keys: injected.cdc,
    selenium_keys: injected.selenium,
    legacy_keys: injected.legacy,
    cdp_console_probe: cdpConsole,
    has_window_chrome: hasWindowChrome,
    plugins_length: navigator.plugins ? navigator.plugins.length : 0,
    hooked_native: hookedNative,
    iframe_mismatch: iframeMismatch,
    devtools_open: devtoolsOpen,
    stack_automation_frame: stackAutomation,
  }
}
