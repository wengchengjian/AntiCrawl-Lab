/**
 * Canvas 指纹与随机噪点投毒探测模块（模块二）。
 *
 * 检测什么：
 * 1. 绘制「渐变矩形 + 指定中英文文本 + 投影」标准组合图并计算 toDataURL 的 SHA-256。
 * 2. 增强实验：在同一页面连续渲染两次完全相同的离屏 Canvas 场景，比对两次哈希是否一致。
 * 为什么可疑：
 * - 真实浏览器在同一 GPU/字体光栅化管线下，相同 Canvas 指令输出确定性的像素摘要；
 * - 防指纹浏览器或 CanvasBlocker 插件常向像素注入随机微噪点，导致同场景二次渲染哈希漂移。
 * 阈值依据：
 * - hash1 !== hash2 即判定存在随机噪点投毒（后端对应 +25 分）；toDataURL 抛出异常时安全降级记 canvas_blocked。
 */

import { sha256Hex } from '@/crypto/signature'

export interface CanvasProbeResult {
  canvasHash: string
  canvasHash2: string
  noiseDetected: boolean
  blocked: boolean
}

function renderStandardScene(canvas: HTMLCanvasElement): string {
  canvas.width = 280
  canvas.height = 68
  const ctx = canvas.getContext('2d')
  if (!ctx) {
    throw new Error('2D context unavailable')
  }

  // 渐变矩形底图
  const grad = ctx.createLinearGradient(0, 0, 280, 68)
  grad.addColorStop(0, '#0f172a')
  grad.addColorStop(0.5, '#065f46')
  grad.addColorStop(1, '#1e3a8a')
  ctx.fillStyle = grad
  ctx.fillRect(0, 0, 280, 68)

  // 几何图形与混合投影
  ctx.shadowColor = 'rgba(0, 245, 160, 0.65)'
  ctx.shadowBlur = 4
  ctx.shadowOffsetX = 2
  ctx.shadowOffsetY = 2

  ctx.fillStyle = '#f8fafc'
  ctx.font = '15px "JetBrains Mono", "Microsoft YaHei", sans-serif'
  ctx.fillText('AntiCrawl Lab · 指纹探针 9876', 12, 28)

  ctx.shadowBlur = 0
  ctx.fillStyle = 'rgba(0, 217, 245, 0.85)'
  ctx.font = '12px monospace'
  ctx.fillText('Cwm fjordbank glyphs vext quiz', 12, 50)

  ctx.beginPath()
  ctx.arc(248, 34, 16, 0, Math.PI * 1.6)
  ctx.strokeStyle = '#f59e0b'
  ctx.lineWidth = 2.5
  ctx.stroke()

  return canvas.toDataURL('image/png')
}

export async function probeCanvas(): Promise<CanvasProbeResult> {
  try {
    const c1 = document.createElement('canvas')
    const c2 = document.createElement('canvas')
    const url1 = renderStandardScene(c1)
    const url2 = renderStandardScene(c2)

    if (!url1 || !url1.startsWith('data:image/')) {
      return {
        canvasHash: 'canvas_blocked',
        canvasHash2: 'canvas_blocked',
        noiseDetected: false,
        blocked: true,
      }
    }

    const [h1, h2] = await Promise.all([sha256Hex(url1), sha256Hex(url2)])
    return {
      canvasHash: h1,
      canvasHash2: h2,
      noiseDetected: h1 !== h2,
      blocked: false,
    }
  } catch {
    return {
      canvasHash: 'canvas_blocked',
      canvasHash2: 'canvas_blocked',
      noiseDetected: false,
      blocked: true,
    }
  }
}
