/**
 * 全维度机器人检测审计探针（botAudit.ts）。
 * 参考 Sannysoft、BrowserScan 与 BrowserLeaks 各项核心指标采集浏览器运行时真实度特征。
 */

import { sha256Hex } from '@/crypto/signature'
import { collectFullFingerprint } from './fingerprint'
import { probeMultiChannelIpLeaks } from './ipLeak'
import type { BehaviorTracePayload, BotCheckPayload } from '@/types/lab'

async function probePermissionsConsistency(): Promise<{
  inconsistent: boolean
  detail: string
}> {
  try {
    const notifPerm = typeof Notification !== 'undefined' ? Notification.permission : 'unsupported'
    if (!navigator.permissions || typeof navigator.permissions.query !== 'function') {
      return { inconsistent: false, detail: `Notification=${notifPerm}, permissions=unsupported` }
    }
    const status = await navigator.permissions.query({ name: 'notifications' as PermissionName })
    const inconsistent = notifPerm === 'denied' && status.state === 'prompt'
    return {
      inconsistent,
      detail: `Notification=${notifPerm}, query=${status.state}`,
    }
  } catch {
    return { inconsistent: false, detail: 'query_error' }
  }
}

async function probeBrokenImage(): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      const img = document.createElement('img')
      img.width = 0
      img.height = 0
      const timer = window.setTimeout(() => resolve(true), 250)
      img.onerror = () => {
        clearTimeout(timer)
        resolve(img.naturalWidth === 0 && img.naturalHeight === 0)
      }
      img.onload = () => {
        clearTimeout(timer)
        resolve(true)
      }
      img.src = 'data:image/png;base64,invalid_acl_broken_img'
    } catch {
      resolve(true)
    }
  })
}

async function probeClientRects(): Promise<{ h1: string; h2: string; noise: boolean }> {
  try {
    const measureOnce = () => {
      const host = document.createElement('div')
      host.style.cssText =
        'position:fixed;left:-9999px;top:-9999px;width:317px;font-family:serif;font-size:15.3px;line-height:1.37;'
      host.innerHTML =
        '<span style="display:inline-block;transform:rotate(1.3deg)">BrowserLeaks DOMRect 12345 测</span>'
      document.body.appendChild(host)
      const rect = host.firstElementChild!.getBoundingClientRect()
      const sig = [
        rect.x.toFixed(6),
        rect.y.toFixed(6),
        rect.width.toFixed(6),
        rect.height.toFixed(6),
        rect.top.toFixed(6),
        rect.right.toFixed(6),
      ].join('|')
      document.body.removeChild(host)
      return sig
    }
    const s1 = measureOnce()
    const s2 = measureOnce()
    const [h1, h2] = await Promise.all([sha256Hex(s1), sha256Hex(s2)])
    return { h1: h1.slice(0, 24), h2: h2.slice(0, 24), noise: h1 !== h2 }
  } catch {
    return { h1: 'blocked', h2: 'blocked', noise: false }
  }
}

function probeWebGLExtra(): { extCount: number | null; maxTex: number | null } {
  try {
    const canvas = document.createElement('canvas')
    const gl =
      (canvas.getContext('webgl') as WebGLRenderingContext | null) ||
      (canvas.getContext('experimental-webgl') as WebGLRenderingContext | null)
    if (!gl) return { extCount: null, maxTex: null }
    const exts = gl.getSupportedExtensions() || []
    const maxTex = Number(gl.getParameter(gl.MAX_TEXTURE_SIZE) || 0)
    return { extCount: exts.length, maxTex }
  } catch {
    return { extCount: null, maxTex: null }
  }
}

async function probeMediaDevicesCount(): Promise<number | null> {
  try {
    if (!navigator.mediaDevices || typeof navigator.mediaDevices.enumerateDevices !== 'function') {
      return null
    }
    const list = await navigator.mediaDevices.enumerateDevices()
    return list.length
  } catch {
    return null
  }
}

function probeSpeechVoicesCount(): number | null {
  try {
    if (typeof speechSynthesis === 'undefined' || typeof speechSynthesis.getVoices !== 'function') {
      return null
    }
    return speechSynthesis.getVoices().length
  } catch {
    return null
  }
}

export async function collectBotAuditPayload(
  behavior?: BehaviorTracePayload
): Promise<BotCheckPayload> {
  const [baseFp, permRes, brokenOk, crRes, mediaCount, ipLeaks] = await Promise.all([
    collectFullFingerprint({ runDebuggerProbe: false }),
    probePermissionsConsistency(),
    probeBrokenImage(),
    probeClientRects(),
    probeMediaDevicesCount(),
    probeMultiChannelIpLeaks(),
  ])

  const glExtra = probeWebGLExtra()
  const speechCount = probeSpeechVoicesCount()

  const winAny = window as unknown as {
    chrome?: Record<string, unknown>
    PluginArray?: typeof PluginArray
    MimeTypeArray?: typeof MimeTypeArray
  }
  const chromeObj = winAny.chrome
  const chromeSubprops = {
    present: Boolean(chromeObj && typeof chromeObj === 'object'),
    runtime: Boolean(chromeObj && 'runtime' in chromeObj),
    app: Boolean(chromeObj && 'app' in chromeObj),
    csi: Boolean(chromeObj && 'csi' in chromeObj),
    loadTimes: Boolean(chromeObj && 'loadTimes' in chromeObj),
  }

  let getImageDataHooked = false
  try {
    const fnStr = Function.prototype.toString.call(CanvasRenderingContext2D.prototype.getImageData)
    getImageDataHooked = !fnStr.includes('[native code]')
  } catch {
    getImageDataHooked = true
  }

  const navAny = navigator as Navigator & {
    userAgentData?: {
      brands?: Array<{ brand: string; version: string }>
      mobile?: boolean
      platform?: string
    }
  }
  const uaData = navAny.userAgentData
    ? {
        brands: navAny.userAgentData.brands || [],
        mobile: Boolean(navAny.userAgentData.mobile),
        platform: navAny.userAgentData.platform || '',
      }
    : {}

  return {
    ...baseFp,
    extra_probes: {
      ...baseFp.extra_probes,
      webrtc: ipLeaks.webrtc,
      ip_channels: {
        overseas_echo_ip: ipLeaks.overseasEchoIp,
        domestic_echo_ip: ipLeaks.domesticEchoIp,
      },
      user_agent_data: uaData,
      window_dims: {
        outerWidth: window.outerWidth || 0,
        outerHeight: window.outerHeight || 0,
        innerWidth: window.innerWidth || 0,
        innerHeight: window.innerHeight || 0,
      },
      sannysoft: {
        chrome_subprops: chromeSubprops,
        permissions_inconsistent: permRes.inconsistent,
        perm_detail: permRes.detail,
        plugins_proto_valid:
          typeof winAny.PluginArray !== 'undefined' ? navigator.plugins instanceof winAny.PluginArray : true,
        mime_types_length: navigator.mimeTypes ? navigator.mimeTypes.length : 0,
        mime_types_proto_valid:
          typeof winAny.MimeTypeArray !== 'undefined' ? navigator.mimeTypes instanceof winAny.MimeTypeArray : true,
        language: navigator.language || '',
        broken_image_ok: brokenOk,
        get_image_data_hooked: getImageDataHooked,
      },
      browserleaks: {
        client_rects_hash: crRes.h1,
        client_rects_hash_2: crRes.h2,
        client_rects_noise: crRes.noise,
        webgl_extensions_count: glExtra.extCount,
        webgl_max_texture_size: glExtra.maxTex,
        media_devices_count: mediaCount,
        speech_voices_count: speechCount,
      },
    },
    ...(behavior ? { behavior } : {}),
  }
}
