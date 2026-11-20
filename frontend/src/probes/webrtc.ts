/**
 * WebRTC STUN 穿透与 ICE 候选地址探针（模块二 & IP 穿透对抗）。
 *
 * 检测什么：
 * - 通过多组公网 STUN 服务器（小米/Cloudflare/Google）收集 RTCPeerConnection 的 ICE 候选地址，
 *   分离出 `srflx`（经 UDP STUN 反射出的公网真实 IP）与 `host`（内网/mDNS `.local`）。
 * 为什么可疑：
 * - 绝大多数浏览器 HTTP/SOCKS5 代理（如未开启全局 TUN UDP 的 Clash/Mihomo）仅代理 TCP，
 *   UDP STUN 包会直接绕过代理直连外网，从而越过 VPN 暴露用户真实运营商公网 IP！
 * 阈值依据：
 * - 超时 1600ms 安全结束不阻塞页面；若提取到的公网 IP 与 HTTP 出口 IP 不一致，后端记 +35 严重泄露。
 */

export interface WebRTCProbeResult {
  supported: boolean
  candidates: string[]
  publicIps: string[]
  localCandidates: string[]
  mdnsMasked: boolean
}

function isPrivateOrLocalIp(ip: string): boolean {
  if (!ip || ip.endsWith('.local')) return true
  if (
    ip.startsWith('10.') ||
    ip.startsWith('127.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('169.254.') ||
    ip.startsWith('fe80:') ||
    ip.startsWith('fc') ||
    ip.startsWith('fd') ||
    ip === '::1'
  ) {
    return true
  }
  const m172 = ip.match(/^172\.(\d+)\./)
  if (m172) {
    const second = Number(m172[1])
    if (second >= 16 && second <= 31) return true
  }
  return false
}

export async function probeWebRTC(timeoutMs = 1600): Promise<WebRTCProbeResult> {
  if (typeof RTCPeerConnection === 'undefined') {
    return {
      supported: false,
      candidates: [],
      publicIps: [],
      localCandidates: [],
      mdnsMasked: false,
    }
  }

  return new Promise((resolve) => {
    const allCands = new Set<string>()
    const publicIps = new Set<string>()
    const localCands = new Set<string>()
    let finished = false
    let pc: RTCPeerConnection | null = null

    const done = () => {
      if (finished) return
      finished = true
      try {
        pc?.close()
      } catch {
        // 忽略关闭异常
      }
      const list = Array.from(allCands)
      resolve({
        supported: true,
        candidates: list,
        publicIps: Array.from(publicIps),
        localCandidates: Array.from(localCands),
        mdnsMasked: list.some((c) => c.endsWith('.local')),
      })
    }

    try {
      pc = new RTCPeerConnection({
        iceServers: [
          {
            urls: [
              'stun:stun.miwifi.com:3478',
              'stun:stun.cloudflare.com:3478',
              'stun:stun.l.google.com:19302',
            ],
          },
        ],
      })
      pc.createDataChannel('acl_stun_probe')
      pc.onicecandidate = (ev) => {
        if (!ev.candidate) {
          done()
          return
        }
        const raw = ev.candidate.candidate || ''
        const ipMatch = raw.match(/([0-9a-fA-F:.]+\.local|\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})/)
        const addr = ipMatch?.[1]
        if (!addr) return
        allCands.add(addr)
        if (raw.includes(' typ srflx ') && !isPrivateOrLocalIp(addr)) {
          publicIps.add(addr)
        } else if (!isPrivateOrLocalIp(addr)) {
          publicIps.add(addr)
        } else {
          localCands.add(addr)
        }
      }
      pc.createOffer()
        .then((offer) => pc?.setLocalDescription(offer))
        .catch(() => done())
    } catch {
      done()
    }

    window.setTimeout(done, timeoutMs)
  })
}
