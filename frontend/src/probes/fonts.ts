/**
 * 50 种常用系统字体宽度枚举探针（模块二）。
 *
 * 检测什么：
 * - 将 50 个常见桌面/中文字体逐一叠加于基础字体族（monospace/serif/sans-serif）之上，测量文本渲染宽度偏移以判断本机已安装字体。
 * 为什么可疑：
 * - 无头容器或跨 OS 伪装环境（如 Linux 容器伪装 macOS/Windows）安装的字体库与声明操作系统严重不符。
 * 阈值依据：
 * - 输出命中字体列表与 count；异常时仅降级返回 count=0。
 */

const CANDIDATE_FONTS: readonly string[] = [
  'Arial', 'Arial Black', 'Calibri', 'Cambria', 'Comic Sans MS', 'Consolas',
  'Courier New', 'Georgia', 'Impact', 'Lucida Console', 'Lucida Sans Unicode',
  'Microsoft YaHei', 'SimSun', 'SimHei', 'NSimSun', 'FangSong', 'KaiTi',
  'PingFang SC', 'Hiragino Sans GB', 'Heiti SC', 'STSong', 'STHeiti',
  'Helvetica', 'Helvetica Neue', 'Menlo', 'Monaco', 'San Francisco', 'SF Pro Display',
  'Palatino Linotype', 'Segoe UI', 'Tahoma', 'Times New Roman', 'Trebuchet MS',
  'Verdana', 'DejaVu Sans', 'DejaVu Serif', 'DejaVu Sans Mono', 'Liberation Sans',
  'Liberation Serif', 'Liberation Mono', 'Ubuntu', 'Cantarell', 'Noto Sans CJK SC',
  'Source Han Sans CN', 'JetBrains Mono', 'Fira Code', 'Roboto', 'Inter',
  'Meiryo', 'Yu Gothic',
]

export function probeFonts(): { detected: string[]; count: number } {
  try {
    const baseFonts = ['monospace', 'sans-serif', 'serif'] as const
    const testString = 'mmmmmmmmmmlli123456中文测试'
    const testSize = '72px'

    const container = document.createElement('div')
    container.style.cssText =
      'position:absolute;left:-9999px;top:-9999px;visibility:hidden;pointer-events:none;'
    document.body.appendChild(container)

    const span = document.createElement('span')
    span.style.fontSize = testSize
    span.style.whiteSpace = 'nowrap'
    span.textContent = testString
    container.appendChild(span)

    const baseline: Record<string, { w: number; h: number }> = {}
    for (const bf of baseFonts) {
      span.style.fontFamily = bf
      baseline[bf] = { w: span.offsetWidth, h: span.offsetHeight }
    }

    const detected: string[] = []
    for (const fontName of CANDIDATE_FONTS) {
      let matched = false
      for (const bf of baseFonts) {
        span.style.fontFamily = `'${fontName}',${bf}`
        const base = baseline[bf]!
        if (span.offsetWidth !== base.w || span.offsetHeight !== base.h) {
          matched = true
          break
        }
      }
      if (matched) detected.push(fontName)
    }

    document.body.removeChild(container)
    return { detected, count: detected.length }
  } catch {
    return { detected: [], count: 0 }
  }
}
