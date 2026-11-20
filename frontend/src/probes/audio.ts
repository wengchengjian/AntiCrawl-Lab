/**
 * OfflineAudioContext 音频渲染指纹探针（模块二）。
 *
 * 检测什么：
 * - 使用 OfflineAudioContext（而非在线 AudioContext）以固定频率振荡器 + 动态压缩器渲染离散音频采样并取 SHA-256。
 * 为什么可疑：
 * - 规避浏览器自动播放限制，稳定提取底层音频混音器浮点差异；结合 Canvas 哈希生成复合 fp_id，用于识别跨 IP 复用。
 * 阈值依据：
 * - 若接口被禁用/拦截自动降级返回 `audio_blocked`，不阻塞指纹整体上报。
 */

import { sha256Hex } from '@/crypto/signature'

export async function probeAudio(): Promise<{ audioHash: string; blocked: boolean }> {
  try {
    const OfflineCtx =
      window.OfflineAudioContext ||
      (window as unknown as { webkitOfflineAudioContext?: typeof OfflineAudioContext })
        .webkitOfflineAudioContext

    if (!OfflineCtx) {
      return { audioHash: 'audio_blocked', blocked: true }
    }

    const ctx = new OfflineCtx(1, 5000, 44100)
    const osc = ctx.createOscillator()
    osc.type = 'triangle'
    osc.frequency.setValueAtTime(10000, ctx.currentTime)

    const comp = ctx.createDynamicsCompressor()
    comp.threshold.setValueAtTime(-50, ctx.currentTime)
    comp.knee.setValueAtTime(40, ctx.currentTime)
    comp.ratio.setValueAtTime(12, ctx.currentTime)
    comp.attack.setValueAtTime(0, ctx.currentTime)
    comp.release.setValueAtTime(0.25, ctx.currentTime)

    osc.connect(comp)
    comp.connect(ctx.destination)
    osc.start(0)

    const rendered = await ctx.startRendering()
    const channel = rendered.getChannelData(0)
    let acc = ''
    for (let i = 4500; i < Math.min(4600, channel.length); i++) {
      acc += (channel[i] ?? 0).toFixed(7)
    }
    const audioHash = await sha256Hex(acc)
    return { audioHash, blocked: false }
  } catch {
    return { audioHash: 'audio_blocked', blocked: true }
  }
}
