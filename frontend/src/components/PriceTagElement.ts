/**
 * <price-tag> Shadow DOM 自定义价格组件（模块四 11.2 & 11.6）。
 *
 * 防御目标：
 * 1. 将价格文本节点封装在 Shadow Root 内（支持 open / closed 两种隔离模式），普通 document.querySelectorAll('span') 无法穿透提取；
 * 2. 配合动态会话字体 AnticrawlDigits 渲染私用区 PUA 字符串，HTTP/DOM 源码抓取仅为乱码；
 * 3. 支持 render="canvas" 位图渲染（附加防 OCR 干扰噪线与旋转）及 render="css-order" Flexbox 乱序 + 零宽诱饵数字干扰。
 */

export type PriceRenderMode = 'font' | 'closed-shadow' | 'canvas' | 'css-order'

let fontLoadedSeed = ''

export async function ensureSessionFontLoaded(sessionId: string, simulatedIp = ''): Promise<{
  seed: string
  variant: string
  ok: boolean
}> {
  const headers: Record<string, string> = { 'X-Session-Id': sessionId }
  if (simulatedIp) {
    headers['X-Simulated-IP'] = simulatedIp
  }
  const resp = await fetch(`/api/v1/font/session?sid=${encodeURIComponent(sessionId)}`, {
    headers,
    cache: 'no-store',
  })
  if (!resp.ok) {
    return { seed: 'error', variant: '-', ok: false }
  }
  const seed = resp.headers.get('X-Font-Seed') || 'unknown'
  const variant = resp.headers.get('X-Font-Variant') || '0'

  if (fontLoadedSeed !== `${seed}:${variant}`) {
    const buf = await resp.arrayBuffer()
    const face = new FontFace('AnticrawlDigits', buf)
    await face.load()
    // 移除旧变体避免浏览器缓存命中旧码表
    for (const existing of Array.from(document.fonts)) {
      if (existing.family === 'AnticrawlDigits') {
        document.fonts.delete(existing)
      }
    }
    document.fonts.add(face)
    fontLoadedSeed = `${seed}:${variant}`
  }

  return { seed, variant, ok: true }
}

class PriceTagElement extends HTMLElement {
  private root: ShadowRoot | null = null

  static get observedAttributes(): string[] {
    return ['price-pua', 'render-mode', 'decoy', 'seed']
  }

  connectedCallback(): void {
    this.render()
  }

  attributeChangedCallback(): void {
    this.render()
  }

  private render(): void {
    const pricePua = this.getAttribute('price-pua') || '—'
    const mode = (this.getAttribute('render-mode') || 'font') as PriceRenderMode
    const isDecoy = this.getAttribute('decoy') === 'true'
    const targetMode: ShadowRootMode = mode === 'closed-shadow' ? 'closed' : 'open'

    // 如果需要切换 open/closed 模式且尚未 attachShadow，直接创建对应 ShadowRoot
    if (!this.root) {
      try {
        this.root = this.attachShadow({ mode: targetMode })
      } catch {
        // 已挂载 ShadowRoot 时复用
      }
    }
    const shadow = this.root || this.shadowRoot
    if (!shadow) return

    const accent = isDecoy ? '#f59e0b' : '#00f5a0'

    if (mode === 'canvas') {
      shadow.innerHTML = `
        <style>
          :host { display: inline-block; }
          .wrap { display: inline-flex; align-items: center; gap: 6px; padding: 4px 8px; border-radius: 6px; background: rgba(15,23,42,0.75); border: 1px solid rgba(30,44,72,0.9); }
          canvas { display: block; height: 34px; }
        </style>
        <div class="wrap"><canvas width="150" height="34"></canvas></div>
      `
      const canvas = shadow.querySelector('canvas')
      const ctx = canvas?.getContext('2d')
      if (canvas && ctx) {
        ctx.clearRect(0, 0, canvas.width, canvas.height)
        // 添加浅色防 OCR 干扰曲线与噪点
        ctx.strokeStyle = 'rgba(0, 217, 245, 0.25)'
        ctx.lineWidth = 1
        for (let i = 0; i < 4; i++) {
          ctx.beginPath()
          ctx.moveTo(0, 6 + i * 7)
          ctx.bezierCurveTo(50, 2 + i * 4, 100, 30 - i * 4, 150, 10 + i * 5)
          ctx.stroke()
        }
        ctx.fillStyle = accent
        ctx.font = 'bold 24px AnticrawlDigits, monospace'
        ctx.textBaseline = 'middle'
        ctx.fillText(pricePua, 8, 18)
      }
      return
    }

    if (mode === 'css-order') {
      // 将字符拆分后通过 CSS order 打乱 DOM 顺序，同时混入 aria-hidden 零宽/零字号诱饵节点
      const chars = Array.from(pricePua)
      const indexed = chars.map((ch, idx) => ({ ch, idx }))
      const reversed = [...indexed].reverse()
      const decoyChar = chars[1] ?? chars[0] ?? ''

      const spansHtml = reversed
        .map(
          (item) =>
            `<span class="glyph" style="order:${item.idx * 2}">${item.ch}</span>` +
            (item.idx % 2 === 1
              ? `<span class="decoy-noise" style="order:${item.idx * 2 - 1}">${decoyChar}</span>`
              : '')
        )
        .join('')

      shadow.innerHTML = `
        <style>
          :host { display: inline-block; }
          .flex-price {
            display: inline-flex;
            align-items: baseline;
            font-family: 'AnticrawlDigits', monospace;
            font-size: 1.65rem;
            font-weight: 700;
            color: ${accent};
            letter-spacing: 0.04em;
            user-select: none;
          }
          .decoy-noise {
            width: 0;
            height: 0;
            overflow: hidden;
            opacity: 0;
            font-size: 0;
            pointer-events: none;
          }
        </style>
        <div class="flex-price">${spansHtml}</div>
      `
      return
    }

    // 默认 Shadow DOM + 动态字体渲染
    shadow.innerHTML = `
      <style>
        :host { display: inline-block; }
        .tag {
          font-family: 'AnticrawlDigits', monospace;
          font-size: 1.75rem;
          font-weight: 700;
          color: ${accent};
          letter-spacing: 0.05em;
          text-shadow: 0 0 12px ${isDecoy ? 'rgba(245,158,11,0.35)' : 'rgba(0,245,160,0.3)'};
        }
      </style>
      <span class="tag">${pricePua}</span>
    `
  }
}

export function registerPriceTagElement(): void {
  if (typeof customElements !== 'undefined' && !customElements.get('price-tag')) {
    customElements.define('price-tag', PriceTagElement)
  }
}
