/**
 * 多信道国内外分流探测模块（ipLeak.ts）。
 *
 * 检测什么：
 * - 并行请求海外 IP 回显接口（api.ipify.org / ipwho.is）与国内 IP 回显接口，
 *   并与当前站点直连 IP、WebRTC STUN 穿透 IP 进行交叉比对。
 * 为什么可疑：
 * - Clash / Mihomo / V2Ray 等代理工具在默认「规则模式 (Rule)」下会将国内域名直连、海外域名走代理；
 *   同时触发国内外双信道探测即可无感越过规则分流 VPN，同时捕获真实运营商 IP 与代理出口 IP！
 */

import { probeWebRTC, type WebRTCProbeResult } from './webrtc'

export interface MultiChannelIpResult {
  webrtc: WebRTCProbeResult
  overseasEchoIp: string
  domesticEchoIp: string
}

async function fetchJsonWithTimeout(url: string, timeoutMs = 2400): Promise<Record<string, unknown> | null> {
  const ctrl = new AbortController()
  const timer = window.setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const resp = await fetch(url, { signal: ctrl.signal, cache: 'no-store' })
    if (!resp.ok) return null
    return (await resp.json()) as Record<string, unknown>
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

async function probeOverseasEchoIp(): Promise<string> {
  const r1 = await fetchJsonWithTimeout('https://api.ipify.org?format=json', 2200)
  if (r1 && typeof r1.ip === 'string' && r1.ip) return r1.ip
  const r2 = await fetchJsonWithTimeout('https://ipwho.is/', 2200)
  if (r2 && typeof r2.ip === 'string' && r2.ip) return r2.ip
  return ''
}

async function probeDomesticEchoIp(): Promise<string> {
  const r1 = await fetchJsonWithTimeout('https://forge.speedtest.cn/api/location/info', 2200)
  if (r1 && typeof r1.ip === 'string' && r1.ip) return r1.ip
  return ''
}

export async function probeMultiChannelIpLeaks(): Promise<MultiChannelIpResult> {
  const [webrtc, overseasEchoIp, domesticEchoIp] = await Promise.all([
    probeWebRTC(1600),
    probeOverseasEchoIp(),
    probeDomesticEchoIp(),
  ])
  return {
    webrtc,
    overseasEchoIp,
    domesticEchoIp,
  }
}
