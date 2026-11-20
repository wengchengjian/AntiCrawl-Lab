/**
 * 浏览器全维度指纹聚合与增强反伪装探针编排器（模块二 9.1–9.2）。
 *
 * 采集内容：
 * - 基础字段：UA、platform、languages、timezone、screen 硬件参数、deviceMemory、hardwareConcurrency、maxTouchPoints；
 * - 高级独立探针：Canvas（含双渲染噪点比对）、WebGL、OfflineAudioContext、Fonts、Automation、WebRTC；
 * - 增强反伪装探针：Web Worker 跨线程一致性、Math 浮点引擎指纹、Date.getTimezoneOffset()、CSS 媒体查询。
 * 容错原则：
 * - 任意单项探针独立捕获异常并降级，绝不阻塞整体指纹上报。
 */

import { probeAudio } from './audio'
import { probeAutomation } from './automation'
import { probeCanvas } from './canvas'
import { probeFonts } from './fonts'
import { probeWebGL } from './webgl'
import { probeWebRTC } from './webrtc'
import type { FingerprintReportPayload } from '@/types/lab'

async function probeWorkerNavigator(): Promise<Record<string, unknown>> {
  if (typeof Worker === 'undefined' || typeof Blob === 'undefined') {
    return { supported: false }
  }
  return new Promise((resolve) => {
    let settled = false
    let worker: Worker | null = null
    const finish = (res: Record<string, unknown>) => {
      if (settled) return
      settled = true
      try {
        worker?.terminate()
      } catch {
        // 忽略清理异常
      }
      resolve(res)
    }

    try {
      const script = `
        self.postMessage({
          supported: true,
          ua: self.navigator.userAgent || '',
          platform: self.navigator.platform || '',
          languages: Array.from(self.navigator.languages || []),
          hardware_concurrency: self.navigator.hardwareConcurrency || 0
        });
      `
      const blob = new Blob([script], { type: 'application/javascript' })
      const url = URL.createObjectURL(blob)
      worker = new Worker(url)
      worker.onmessage = (ev) => {
        URL.revokeObjectURL(url)
        finish(ev.data as Record<string, unknown>)
      }
      worker.onerror = () => {
        URL.revokeObjectURL(url)
        finish({ supported: false })
      }
      window.setTimeout(() => {
        URL.revokeObjectURL(url)
        finish({ supported: false })
      }, 400)
    } catch {
      finish({ supported: false })
    }
  })
}

function probeMathEngine(): Record<string, string> {
  try {
    return {
      tan: String(Math.tan(-1e300)),
      acos: String(Math.acos(0.123456789)),
      sinh: String(Math.sinh(1)),
      expm1: String(Math.expm1(1)),
    }
  } catch {
    return {}
  }
}

export async function collectFullFingerprint(options?: {
  runDebuggerProbe?: boolean
}): Promise<FingerprintReportPayload> {
  const [canvasRes, webglRes, audioRes, workerRes, webrtcRes] = await Promise.all([
    probeCanvas(),
    probeWebGL(),
    probeAudio(),
    probeWorkerNavigator(),
    probeWebRTC(),
  ])

  const fontsRes = probeFonts()
  const automationRes = probeAutomation(Boolean(options?.runDebuggerProbe))
  const mathFp = probeMathEngine()

  const nav = navigator as Navigator & { deviceMemory?: number }
  let timezone = 'UTC'
  try {
    timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    timezone = 'UTC'
  }

  return {
    ua: navigator.userAgent || '',
    platform: navigator.platform || '',
    languages: Array.from(navigator.languages || [navigator.language || 'en-US']),
    timezone,
    screen: {
      width: window.screen.width || 0,
      height: window.screen.height || 0,
      availWidth: window.screen.availWidth || 0,
      availHeight: window.screen.availHeight || 0,
      colorDepth: window.screen.colorDepth || 24,
      devicePixelRatio: window.devicePixelRatio || 1,
    },
    device_memory: Number(nav.deviceMemory || 0),
    hardware_concurrency: Number(navigator.hardwareConcurrency || 0),
    touch_points: Number(navigator.maxTouchPoints || 0),
    canvas_hash: canvasRes.canvasHash,
    audio_hash: audioRes.audioHash,
    webgl: webglRes,
    fonts: fontsRes,
    automation: automationRes,
    extra_probes: {
      canvas_hash_2: canvasRes.canvasHash2,
      canvas_noise_detected: canvasRes.noiseDetected,
      timezone_offset: new Date().getTimezoneOffset(),
      worker: workerRes,
      math_fp: mathFp,
      webrtc: webrtcRes,
      css_media: {
        pointer_fine: window.matchMedia?.('(pointer: fine)').matches ?? null,
        hover_hover: window.matchMedia?.('(hover: hover)').matches ?? null,
      },
    },
  }
}
