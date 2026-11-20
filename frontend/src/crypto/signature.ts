/**
 * 接口请求 HMAC-SHA256 签名与前端密钥混淆模块（模块四）。
 *
 * 【安全教学声明 · 必读】
 * 本文件中的 12 段异或密钥混淆是「刻意设计的逆向工程练习靶点」，不是安全边界！
 * 任何在客户端执行的密钥拼装最终都可被断点调试或 AST 反混淆还原；
 * 真正安全边界必须依赖服务端风控流水线、时间窗校验、Nonce 防重放与行为/指纹联动验证。
 */

// 12 段加密分片常量（与异或盐配合在运行时拼装默认实验室签名密钥）
const KEY_SEGMENTS: readonly (readonly number[])[] = [
  [89],
  [119],
  [70, 73],
  [35],
  [124],
  [127],
  [96],
  [86],
  [76],
  [66, 69],
  [99],
  [123, 118, 117],
]

const XOR_SALTS: readonly number[] = [58, 31, 39, 68, 25, 82, 13, 51, 97, 43, 78, 23]

/**
 * 在运行时还原 12 段异或混淆密钥。
 */
export function reconstructLabSecret(): string {
  let out = ''
  for (let i = 0; i < KEY_SEGMENTS.length; i++) {
    const salt = XOR_SALTS[i] ?? 0
    const seg = KEY_SEGMENTS[i] ?? []
    for (let j = 0; j < seg.length; j++) {
      out += String.fromCharCode((seg[j] ?? 0) ^ salt)
    }
  }
  return out
}

export function generateNonce(): string {
  const bytes = new Uint8Array(12)
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(bytes)
  } else {
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Math.floor(Math.random() * 256)
    }
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

function bytesToHex(buf: ArrayBuffer | Uint8Array): string {
  const arr = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('')
}

// 纯 TS SHA-256 兜底实现（确保极少数非安全上下文无 crypto.subtle 时仍可运行）
function sha256BytesFallback(data: Uint8Array): Uint8Array {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ])
  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ])

  const bitLen = data.length * 8
  const paddedLen = Math.ceil((data.length + 9) / 64) * 64
  const padded = new Uint8Array(paddedLen)
  padded.set(data)
  padded[data.length] = 0x80
  const view = new DataView(padded.buffer)
  view.setUint32(paddedLen - 4, bitLen >>> 0, false)
  view.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false)

  const w = new Uint32Array(64)
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n))

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false)
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15]!, 7) ^ rotr(w[i - 15]!, 18) ^ (w[i - 15]! >>> 3)
      const s1 = rotr(w[i - 2]!, 17) ^ rotr(w[i - 2]!, 19) ^ (w[i - 2]! >>> 10)
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0
    }
    let a = H[0]!
    let b = H[1]!
    let c = H[2]!
    let d = H[3]!
    let e = H[4]!
    let f = H[5]!
    let g = H[6]!
    let h = H[7]!

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      const ch = (e & f) ^ (~e & g)
      const temp1 = (h + S1 + ch + K[i]! + w[i]!) >>> 0
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const temp2 = (S0 + maj) >>> 0

      h = g
      g = f
      f = e
      e = (d + temp1) >>> 0
      d = c
      c = b
      b = a
      a = (temp1 + temp2) >>> 0
    }
    H[0] = (H[0]! + a) >>> 0
    H[1] = (H[1]! + b) >>> 0
    H[2] = (H[2]! + c) >>> 0
    H[3] = (H[3]! + d) >>> 0
    H[4] = (H[4]! + e) >>> 0
    H[5] = (H[5]! + f) >>> 0
    H[6] = (H[6]! + g) >>> 0
    H[7] = (H[7]! + h) >>> 0
  }

  const out = new Uint8Array(32)
  const outView = new DataView(out.buffer)
  for (let i = 0; i < 8; i++) {
    outView.setUint32(i * 4, H[i]!, false)
  }
  return out
}

export async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text)
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const digest = await crypto.subtle.digest('SHA-256', bytes)
    return bytesToHex(digest)
  }
  return bytesToHex(sha256BytesFallback(bytes))
}

export function sha256HexSync(text: string): string {
  return bytesToHex(sha256BytesFallback(new TextEncoder().encode(text)))
}

async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder()
  const keyBytes = enc.encode(secret)
  const msgBytes = enc.encode(message)

  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    )
    const sig = await crypto.subtle.sign('HMAC', key, msgBytes)
    return bytesToHex(sig)
  }

  const blockSize = 64
  const k = keyBytes.length > blockSize ? sha256BytesFallback(keyBytes) : keyBytes
  const kPad = new Uint8Array(blockSize)
  kPad.set(k)
  const oPad = new Uint8Array(blockSize)
  const iPad = new Uint8Array(blockSize)
  for (let i = 0; i < blockSize; i++) {
    oPad[i] = kPad[i]! ^ 0x5c
    iPad[i] = kPad[i]! ^ 0x36
  }
  const inner = new Uint8Array(blockSize + msgBytes.length)
  inner.set(iPad)
  inner.set(msgBytes, blockSize)
  const innerHash = sha256BytesFallback(inner)
  const outer = new Uint8Array(blockSize + innerHash.length)
  outer.set(oPad)
  outer.set(innerHash, blockSize)
  return bytesToHex(sha256BytesFallback(outer))
}

export interface SignedHeaders {
  'X-Signature': string
  'X-Timestamp': string
  'X-Nonce': string
}

/**
 * 为受保护数据接口生成标准 HMAC-SHA256 签名请求头组。
 * 原文算法：METHOD + "\n" + PATH + "\n" + X-Timestamp + "\n" + X-Nonce
 */
export async function signRequest(
  method: string,
  path: string,
  overrideTimestamp?: string,
  overrideNonce?: string,
  clockOffsetMs = 0
): Promise<SignedHeaders> {
  const ts = overrideTimestamp ?? String(Math.floor((Date.now() + clockOffsetMs) / 1000))
  const nonce = overrideNonce ?? generateNonce()
  const canonical = `${method.toUpperCase()}\n${path}\n${ts}\n${nonce}`
  const secret = reconstructLabSecret()
  const signature = await hmacSha256Hex(secret, canonical)
  return {
    'X-Signature': signature,
    'X-Timestamp': ts,
    'X-Nonce': nonce,
  }
}
