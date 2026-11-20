/**
 * WebGL 渲染器与驱动参数哈希探针（模块二）。
 *
 * 检测什么：
 * - 获取 WEBGL_debug_renderer_info 的 UNMASKED_VENDOR_WEBGL 与 UNMASKED_RENDERER_WEBGL，
 *   并汇总 WebGL 能力参数表计算参数哈希。
 * 为什么可疑：
 * - 无头浏览器或隐私插件会屏蔽调试扩展（webgl_masked=1）或回退到 SwiftShader/llvmpipe 软渲染器；
 * - 跨 OS 伪装（如 macOS UA 配 Windows Direct3D 渲染器）将直接暴露硬件矛盾。
 * 阈值依据：
 * - masked=true 或命中软渲染器在后端触发 WEBGL_MASKED（+15），OS 矛盾触发 FINGERPRINT_CONFLICT（+20）。
 */

import { sha256Hex } from '@/crypto/signature'
import type { WebGLInfo } from '@/types/lab'

export async function probeWebGL(): Promise<WebGLInfo> {
  try {
    const canvas = document.createElement('canvas')
    const gl =
      (canvas.getContext('webgl') as WebGLRenderingContext | null) ||
      (canvas.getContext('experimental-webgl') as WebGLRenderingContext | null)

    if (!gl) {
      return {
        vendor: 'webgl_unavailable',
        renderer: 'webgl_unavailable',
        masked: true,
        params_hash: 'unavailable',
      }
    }

    const debugExt = gl.getExtension('WEBGL_debug_renderer_info')
    let vendor = String(gl.getParameter(gl.VENDOR) || '')
    let renderer = String(gl.getParameter(gl.RENDERER) || '')
    let masked = false

    if (debugExt) {
      const unmaskedVendor = gl.getParameter(debugExt.UNMASKED_VENDOR_WEBGL)
      const unmaskedRenderer = gl.getParameter(debugExt.UNMASKED_RENDERER_WEBGL)
      if (unmaskedVendor) vendor = String(unmaskedVendor)
      if (unmaskedRenderer) renderer = String(unmaskedRenderer)
      if (!unmaskedVendor || !unmaskedRenderer) {
        masked = true
      }
    } else {
      masked = true
    }

    const params = [
      gl.getParameter(gl.VERSION),
      gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
      gl.getParameter(gl.MAX_TEXTURE_SIZE),
      gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
      gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
      gl.getParameter(gl.MAX_VIEWPORT_DIMS),
      gl.getSupportedExtensions()?.join(',') || '',
    ].join('|')

    const paramsHash = (await sha256Hex(params)).slice(0, 24)
    return { vendor, renderer, masked, params_hash: paramsHash }
  } catch {
    return {
      vendor: 'webgl_blocked',
      renderer: 'webgl_blocked',
      masked: true,
      params_hash: 'blocked',
    }
  }
}
