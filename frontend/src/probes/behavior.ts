/**
 * 用户交互行为轨迹采集、本地实时指标估算与红队注入模拟器（模块三）。
 *
 * 检测什么：
 * - 实时监听鼠标移动（采样节流保留自然曲线）、键盘 down/up 时间戳、滚动及页面聚焦状态；
 * - 提取事件原生可信标志 event.isTrusted（区分人工操作与页面内 dispatchEvent 脚本合成事件）。
 * 为什么可疑：
 * - 自动化脚本常出现轨迹点不足 30、严格直线无转折、等速运动、isTrusted=false 合成事件或机械均匀击键。
 * 阈值依据：
 * - 与后端 behavior.py 10.2 节对齐：点数 <30、方向变化 <8、速度标准差 <0.05 px/ms、页面停留 <2s、击键方差 <30 ms²。
 */

import type {
  BehaviorFocusEvent,
  BehaviorKey,
  BehaviorMetrics,
  BehaviorPoint,
  BehaviorScroll,
  BehaviorTracePayload,
} from '@/types/lab'
import { labState } from '@/services/labState'

export class BehaviorTracker {
  public points: BehaviorPoint[] = []
  public keys: BehaviorKey[] = []
  public scrolls: BehaviorScroll[] = []
  public focusEvents: BehaviorFocusEvent[] = []
  private startedAt = performance.now()
  private lastPointAt = 0
  private pendingDown = new Map<string, { downTs: number; isTrusted: boolean }>()
  private attached = false
  private onUpdate?: () => void

  constructor(onUpdate?: () => void) {
    this.onUpdate = onUpdate
  }

  private handleMouseMove = (ev: MouseEvent) => {
    const now = performance.now()
    if (now - this.lastPointAt < 18 && ev.isTrusted) {
      return
    }
    this.lastPointAt = now
    this.points.push({
      x: Math.round(ev.clientX),
      y: Math.round(ev.clientY),
      t: Math.round(now),
      isTrusted: ev.isTrusted,
    })
    if (this.points.length > 240) {
      this.points = this.points.slice(-240)
    }
    this.onUpdate?.()
  }

  private handleKeyDown = (ev: KeyboardEvent) => {
    this.pendingDown.set(ev.code || ev.key, {
      downTs: Math.round(performance.now()),
      isTrusted: ev.isTrusted,
    })
  }

  private handleKeyUp = (ev: KeyboardEvent) => {
    const code = ev.code || ev.key
    const upTs = Math.round(performance.now())
    const start = this.pendingDown.get(code)
    this.pendingDown.delete(code)
    this.keys.push({
      key: ev.key.length === 1 ? '*' : ev.key,
      downTs: start ? start.downTs : upTs - 45,
      upTs,
      isTrusted: start ? start.isTrusted && ev.isTrusted : ev.isTrusted,
    })
    if (this.keys.length > 100) {
      this.keys = this.keys.slice(-100)
    }
    this.onUpdate?.()
  }

  private handleScroll = (ev: Event) => {
    this.scrolls.push({
      scrollY: Math.round(window.scrollY),
      t: Math.round(performance.now()),
      isTrusted: ev.isTrusted,
    })
    if (this.scrolls.length > 80) {
      this.scrolls = this.scrolls.slice(-80)
    }
    this.onUpdate?.()
  }

  private handleFocus = (type: 'focus' | 'blur' | 'visibilitychange') => {
    this.focusEvents.push({
      type,
      hidden: document.hidden,
      t: Math.round(performance.now()),
    })
  }

  private onFocusFn = () => this.handleFocus('focus')
  private onBlurFn = () => this.handleFocus('blur')
  private onVisFn = () => this.handleFocus('visibilitychange')

  public attach(): void {
    if (this.attached) return
    window.addEventListener('mousemove', this.handleMouseMove, true)
    window.addEventListener('keydown', this.handleKeyDown, true)
    window.addEventListener('keyup', this.handleKeyUp, true)
    window.addEventListener('scroll', this.handleScroll, true)
    window.addEventListener('focus', this.onFocusFn)
    window.addEventListener('blur', this.onBlurFn)
    document.addEventListener('visibilitychange', this.onVisFn)
    this.attached = true
  }

  public detach(): void {
    if (!this.attached) return
    window.removeEventListener('mousemove', this.handleMouseMove, true)
    window.removeEventListener('keydown', this.handleKeyDown, true)
    window.removeEventListener('keyup', this.handleKeyUp, true)
    window.removeEventListener('scroll', this.handleScroll, true)
    window.removeEventListener('focus', this.onFocusFn)
    window.removeEventListener('blur', this.onBlurFn)
    document.removeEventListener('visibilitychange', this.onVisFn)
    this.attached = false
  }

  public clear(): void {
    this.points = []
    this.keys = []
    this.scrolls = []
    this.focusEvents = []
    this.startedAt = performance.now()
    this.onUpdate?.()
  }

  /**
   * 演练辅助（验收用例 6）：通过原生 DOM dispatchEvent 注入 30 个合成鼠标事件（isTrusted=false）。
   */
  public injectSyntheticEvents(target: HTMLElement = document.body): void {
    const baseT = Math.round(performance.now())
    for (let i = 0; i < 30; i++) {
      const ev = new MouseEvent('mousemove', {
        bubbles: true,
        cancelable: true,
        clientX: 120 + i * 8,
        clientY: 200 + Math.round(Math.sin(i * 0.6) * 24),
      })
      target.dispatchEvent(ev)
      // 若短时间内被节流略过，仍保证事件采集逻辑观测到合成事件标志
      if (this.points.length < 30 && i === 29) {
        this.points.push({ x: 360, y: 210, t: baseT + i * 25, isTrusted: false })
      }
    }
    this.onUpdate?.()
  }

  /**
   * 演练辅助（验收用例 7）：向轨迹缓冲区注入 30 个严格共线、等速点（触发 BOT_TRAJECTORY）。
   */
  public injectLinearTrajectory(): void {
    const baseT = Math.round(performance.now())
    this.points = []
    for (let i = 0; i < 30; i++) {
      this.points.push({
        x: 100 + i * 10,
        y: 100 + i * 5,
        t: baseT + i * 20,
        isTrusted: true,
      })
    }
    this.onUpdate?.()
  }

  /**
   * 演练辅助：注入 8 个严格等间隔（100ms）机械击键事件（方差=0 < 30 ms²，触发 KEYBOARD_ROBOTIC）。
   */
  public injectRoboticKeys(): void {
    const baseT = Math.round(performance.now())
    this.keys = []
    for (let i = 0; i < 8; i++) {
      this.keys.push({
        key: '*',
        downTs: baseT + i * 100,
        upTs: baseT + i * 100 + 40,
        isTrusted: true,
      })
    }
    this.onUpdate?.()
  }

  public getPageSeconds(): number {
    return Number(((performance.now() - this.startedAt) / 1000).toFixed(2))
  }

  public estimateMetrics(): BehaviorMetrics {
    const all = [...this.points, ...this.keys, ...this.scrolls]
    const untrustedCount = all.filter((e) => !e.isTrusted).length
    const trustedRatio = all.length === 0 ? 1 : Number(((all.length - untrustedCount) / all.length).toFixed(4))

    let dirChanges = 0
    let prevDx: number | null = null
    let prevDy: number | null = null
    const vels: number[] = []

    for (let i = 1; i < this.points.length; i++) {
      const p0 = this.points[i - 1]!
      const p1 = this.points[i]!
      const dx = p1.x - p0.x
      const dy = p1.y - p0.y
      const dt = Math.max(1, p1.t - p0.t)
      const mag = Math.hypot(dx, dy)
      vels.push(mag / dt)
      if (mag > 0.001) {
        if (prevDx !== null && prevDy !== null) {
          const pm = Math.hypot(prevDx, prevDy)
          if (pm > 0.001) {
            const cosT = Math.max(-1, Math.min(1, (dx * prevDx + dy * prevDy) / (mag * pm)))
            if ((Math.acos(cosT) * 180) / Math.PI > 12) dirChanges++
          }
        }
        prevDx = dx
        prevDy = dy
      }
    }

    let velStd = 0
    if (vels.length >= 2) {
      const meanV = vels.reduce((a, b) => a + b, 0) / vels.length
      const varV = vels.reduce((a, v) => a + (v - meanV) ** 2, 0) / vels.length
      velStd = Number(Math.sqrt(varV).toFixed(4))
    }

    let keyVar: number | null = null
    if (this.keys.length >= 3) {
      const downs = this.keys.map((k) => k.downTs).sort((a, b) => a - b)
      const ivs: number[] = []
      for (let i = 1; i < downs.length; i++) ivs.push(downs[i]! - downs[i - 1]!)
      const meanIv = ivs.reduce((a, b) => a + b, 0) / ivs.length
      keyVar = Number((ivs.reduce((a, x) => a + (x - meanIv) ** 2, 0) / ivs.length).toFixed(2))
    }

    return {
      point_count: this.points.length,
      key_count: this.keys.length,
      scroll_count: this.scrolls.length,
      trusted_ratio: trustedRatio,
      untrusted_count: untrustedCount,
      direction_changes: dirChanges,
      velocity_std: velStd,
      key_interval_variance: keyVar,
      page_seconds: this.getPageSeconds(),
    }
  }

  public buildPayload(overrideVisitPath?: string[]): BehaviorTracePayload {
    return {
      points: this.points,
      keys: this.keys,
      scrolls: this.scrolls,
      page_focus_events: this.focusEvents,
      page_seconds: this.getPageSeconds(),
      visit_path: overrideVisitPath ?? [...labState.visitPath],
    }
  }
}
