<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import ScoreBadge from '@/components/ScoreBadge.vue'
import {
  BehaviorTracker,
  collectFullFingerprint,
  runAntiDebugSelfCheck,
} from '@/probes'
import { buildLabHeaders, labState, setFpId } from '@/services/labState'
import type {
  BehaviorMetrics,
  BehaviorTraceResponse,
  FingerprintReportPayload,
  FingerprintReportResponse,
} from '@/types/lab'

const fpPayload = ref<FingerprintReportPayload | null>(null)
const fpResult = ref<FingerprintReportResponse | null>(null)
const fpLoading = ref(false)

const behMetrics = ref<BehaviorMetrics | null>(null)
const behResult = ref<BehaviorTraceResponse | null>(null)
const behLoading = ref(false)

const antiDebugStatus = ref<{ triggered: boolean; deltaMs: number }>({
  triggered: false,
  deltaMs: 0,
})
const antiDebugLoopEnabled = ref(false)
let antiDebugTimer: number | null = null

const canvasRef = ref<HTMLCanvasElement | null>(null)

const tracker = new BehaviorTracker(() => {
  behMetrics.value = tracker.estimateMetrics()
  drawTrajectoryCanvas()
})

function drawTrajectoryCanvas(): void {
  const canvas = canvasRef.value
  if (!canvas) return
  const ctx = canvas.getContext('2d')
  if (!ctx) return

  ctx.clearRect(0, 0, canvas.width, canvas.height)
  ctx.fillStyle = '#060a12'
  ctx.fillRect(0, 0, canvas.width, canvas.height)

  // 绘制网格背景
  ctx.strokeStyle = 'rgba(30, 44, 72, 0.55)'
  ctx.lineWidth = 1
  for (let x = 0; x < canvas.width; x += 40) {
    ctx.beginPath()
    ctx.moveTo(x, 0)
    ctx.lineTo(x, canvas.height)
    ctx.stroke()
  }
  for (let y = 0; y < canvas.height; y += 40) {
    ctx.beginPath()
    ctx.moveTo(0, y)
    ctx.lineTo(canvas.width, y)
    ctx.stroke()
  }

  const pts = tracker.points
  if (pts.length === 0) {
    ctx.fillStyle = '#64748b'
    ctx.font = '12px monospace'
    ctx.fillText('在页面任意位置移动鼠标或点击下方红队注入按钮以观测轨迹...', 18, 100)
    return
  }

  // 归一化映射到画布坐标
  const wScale = canvas.width / Math.max(window.innerWidth, 1)
  const hScale = canvas.height / Math.max(window.innerHeight, 1)

  for (let i = 1; i < pts.length; i++) {
    const p0 = pts[i - 1]!
    const p1 = pts[i]!
    ctx.beginPath()
    ctx.moveTo(p0.x * wScale, p0.y * hScale)
    ctx.lineTo(p1.x * wScale, p1.y * hScale)
    ctx.strokeStyle = p1.isTrusted ? '#00f5a0' : '#ef4444'
    ctx.lineWidth = 2
    ctx.stroke()
  }

  for (const p of pts) {
    ctx.beginPath()
    ctx.arc(p.x * wScale, p.y * hScale, 2.5, 0, Math.PI * 2)
    ctx.fillStyle = p.isTrusted ? '#00d9f5' : '#f43f5e'
    ctx.fill()
  }
}

async function runFingerprintProbe(customPayload?: FingerprintReportPayload, simIpOverride?: string): Promise<void> {
  fpLoading.value = true
  try {
    const collected = customPayload ?? (await collectFullFingerprint({ runDebuggerProbe: false }))
    fpPayload.value = collected
    const headers = buildLabHeaders({ 'Content-Type': 'application/json' })
    if (simIpOverride) {
      headers['X-Simulated-IP'] = simIpOverride
    }
    const resp = await fetch('/api/v1/fingerprint/report', {
      method: 'POST',
      headers,
      body: JSON.stringify(collected),
    })
    const data = (await resp.json()) as FingerprintReportResponse
    fpResult.value = data
    if (data.fp_id) {
      setFpId(data.fp_id)
    }
  } finally {
    fpLoading.value = false
  }
}

async function simulateCrossDimSpoof(): Promise<void> {
  const base = fpPayload.value ?? (await collectFullFingerprint())
  const spoofed: FingerprintReportPayload = {
    ...base,
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    platform: 'Win32',
    timezone: 'Asia/Shanghai',
    languages: ['zh-CN'],
    webgl: {
      vendor: 'Google Inc. (Intel)',
      renderer: 'ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0)',
      masked: false,
      params_hash: base.webgl.params_hash,
    },
    automation: {
      ...base.automation,
      webdriver: true,
      iframe_mismatch: true,
    },
    extra_probes: {
      ...base.extra_probes,
      canvas_hash_2: 'tampered_random_noise_hash_' + Math.random().toString(16).slice(2, 10),
    },
  }
  await runFingerprintProbe(spoofed, '52.95.10.20')
}

async function submitBehavior(zeroInteraction = false): Promise<void> {
  behLoading.value = true
  try {
    const body = zeroInteraction
      ? {
          points: [],
          keys: [],
          scrolls: [],
          page_focus_events: [],
          page_seconds: 0.3,
          visit_path: [...labState.visitPath],
        }
      : tracker.buildPayload()
    const resp = await fetch('/api/v1/behavior/trace', {
      method: 'POST',
      headers: buildLabHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(body),
    })
    behResult.value = (await resp.json()) as BehaviorTraceResponse
  } finally {
    behLoading.value = false
  }
}

function triggerSyntheticAndReport(): void {
  tracker.injectSyntheticEvents()
  void submitBehavior(false)
}

function triggerLinearAndReport(): void {
  tracker.injectLinearTrajectory()
  void submitBehavior(false)
}

function triggerRoboticKeysAndReport(): void {
  tracker.injectRoboticKeys()
  void submitBehavior(false)
}

function toggleAntiDebugLoop(): void {
  antiDebugLoopEnabled.value = !antiDebugLoopEnabled.value
  if (antiDebugLoopEnabled.value) {
    antiDebugStatus.value = runAntiDebugSelfCheck(1)
    antiDebugTimer = window.setInterval(() => {
      antiDebugStatus.value = runAntiDebugSelfCheck(1)
    }, 2500)
  } else if (antiDebugTimer !== null) {
    clearInterval(antiDebugTimer)
    antiDebugTimer = null
  }
}

const fpBadgeAction = computed(() => {
  const s = fpResult.value?.risk_score ?? 0
  if (s >= 70) return 'block'
  if (s >= 40 || (fpResult.value?.warnings?.length ?? 0) > 0) return 'warn'
  return 'pass'
})

onMounted(() => {
  tracker.attach()
  behMetrics.value = tracker.estimateMetrics()
  drawTrajectoryCanvas()
  // 11.4 页面加载即执行非阻断式反调试与完整性自检
  antiDebugStatus.value = runAntiDebugSelfCheck(1)
  void runFingerprintProbe()
})

onUnmounted(() => {
  tracker.detach()
  if (antiDebugTimer !== null) {
    clearInterval(antiDebugTimer)
  }
})
</script>

<template>
  <div class="mx-auto max-w-7xl space-y-6 px-4 py-6">
    <!-- 模块二：指纹探针与增强反伪装面板 -->
    <section class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <span class="rounded bg-cyan-500/15 px-2 py-0.5 font-mono text-[10px] text-cyan-300">
            LEVEL 02 & 03 · 浏览器指纹与反自动化探针
          </span>
          <h1 class="mt-1.5 text-xl font-bold text-white">浏览器指纹与环境一致性检测</h1>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <ScoreBadge v-if="fpResult" :action="fpBadgeAction" :score="fpResult.risk_score" />
          <button
            :disabled="fpLoading"
            class="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 font-mono text-xs text-emerald-300 hover:bg-emerald-500/20"
            @click="runFingerprintProbe()"
          >
            {{ fpLoading ? '采集中...' : '重新采集并上报本机指纹' }}
          </button>
          <button
            :disabled="fpLoading"
            class="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 font-mono text-xs text-rose-300 hover:bg-rose-500/20"
            @click="simulateCrossDimSpoof"
          >
            注入「跨维伪装破绽」测试包
          </button>
        </div>
      </div>

      <!-- 指纹概览网格 -->
      <div v-if="fpPayload" class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4 font-mono text-xs">
        <div class="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
          <div class="text-[10px] text-slate-400">复合 fp_id (Canvas + Audio)</div>
          <div class="mt-1 truncate text-emerald-300">{{ fpResult?.fp_id || '计算中' }}</div>
          <div class="mt-1 text-[10px] text-slate-500">跨 IP 命中数: {{ fpResult?.hit_ips ?? 1 }}</div>
        </div>
        <div class="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
          <div class="text-[10px] text-slate-400">Platform / 时区 / 语言</div>
          <div class="mt-1 truncate text-slate-200">{{ fpPayload.platform }} · {{ fpPayload.timezone }}</div>
          <div class="mt-1 truncate text-[10px] text-slate-400">{{ fpPayload.languages.join(', ') }}</div>
        </div>
        <div class="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
          <div class="text-[10px] text-slate-400">WebGL 渲染器 / 字体枚举</div>
          <div class="mt-1 truncate text-slate-200" :title="fpPayload.webgl.renderer">
            {{ fpPayload.webgl.renderer }}
          </div>
          <div class="mt-1 text-[10px] text-cyan-300">
            字体命中: {{ fpPayload.fonts.count }} 个 · masked={{ fpPayload.webgl.masked }}
          </div>
        </div>
        <div class="rounded-xl border border-slate-800 bg-slate-950/70 p-3">
          <div class="text-[10px] text-slate-400">增强反伪装探针状态</div>
          <div class="mt-1 text-slate-200">
            Canvas噪点={{ Boolean(fpPayload.extra_probes.canvas_noise_detected) }} ·
            Hook={{ fpPayload.automation.hooked_native }}
          </div>
          <div class="mt-1 text-[10px] text-slate-400">
            Iframe差异={{ fpPayload.automation.iframe_mismatch }} · CDP={{ fpPayload.automation.cdp_console_probe }}
          </div>
        </div>
      </div>

      <!-- 一致性破绽与自动化发现 -->
      <div v-if="fpResult && (fpResult.conflicts.length || fpResult.automation_findings.length)" class="mt-4 space-y-2">
        <div
          v-for="(cf, i) in fpResult.conflicts"
          :key="i"
          class="rounded-xl border border-rose-500/30 bg-rose-950/15 p-3 text-xs"
        >
          <div class="flex items-center justify-between font-mono">
            <span class="font-bold text-rose-300">[{{ cf.rule_id }}] {{ cf.message }}</span>
            <span v-if="cf.is_enhanced" class="rounded bg-indigo-500/20 px-1.5 py-0.5 text-[10px] text-indigo-300">
              增强检测
            </span>
          </div>
          <div class="mt-1 font-mono text-[11px] text-slate-400">
            左证: {{ cf.left_evidence }} | 右证: {{ cf.right_evidence }}
          </div>
        </div>
        <div
          v-for="(af, j) in fpResult.automation_findings"
          :key="'af-' + j"
          class="rounded-xl border border-amber-500/30 bg-amber-950/15 px-3 py-2 font-mono text-xs text-amber-300"
        >
          [AUTOMATION] {{ af }}
        </div>
      </div>
    </section>

    <!-- 模块三：实时鼠标轨迹画布与红队注入器 -->
    <section class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 class="text-lg font-bold text-white">行为轨迹实时采集与动力学分析</h2>
          <p class="text-xs text-slate-400">
            绿线为人类原生事件（isTrusted=true），红线为脚本合成事件（isTrusted=false）。
          </p>
        </div>
        <div class="flex flex-wrap gap-2">
          <button
            class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 font-mono text-xs text-slate-300 hover:bg-slate-800"
            @click="tracker.clear()"
          >
            清空画布
          </button>
          <button
            :disabled="behLoading"
            class="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 font-mono text-xs text-emerald-300 hover:bg-emerald-500/20"
            @click="submitBehavior(false)"
          >
            上报当前交互轨迹
          </button>
        </div>
      </div>

      <div class="mt-4 grid gap-4 lg:grid-cols-3">
        <div class="lg:col-span-2">
          <canvas
            ref="canvasRef"
            width="680"
            height="220"
            class="w-full rounded-xl border border-slate-800 bg-[#060a12]"
          ></canvas>
        </div>

        <div class="space-y-2 rounded-xl border border-slate-800 bg-slate-950/70 p-4 font-mono text-xs">
          <div class="flex justify-between">
            <span class="text-slate-400">轨迹点数 (阈值 ≥30):</span>
            <span :class="(behMetrics?.point_count ?? 0) < 30 ? 'text-amber-300' : 'text-emerald-300'">
              {{ behMetrics?.point_count ?? 0 }}
            </span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">方向转折次数 (阈值 ≥8):</span>
            <span :class="(behMetrics?.direction_changes ?? 0) < 8 ? 'text-amber-300' : 'text-emerald-300'">
              {{ behMetrics?.direction_changes ?? 0 }}
            </span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">速度标准差 (≥0.05):</span>
            <span class="text-slate-200">{{ behMetrics?.velocity_std ?? 0 }} px/ms</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">isTrusted 比例:</span>
            <span :class="(behMetrics?.trusted_ratio ?? 1) < 1 ? 'text-rose-400 font-bold' : 'text-emerald-300'">
              {{ ((behMetrics?.trusted_ratio ?? 1) * 100).toFixed(1) }}%
            </span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">击键间隔方差 (≥30):</span>
            <span class="text-slate-200">{{ behMetrics?.key_interval_variance ?? '—' }} ms²</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">页面停留时长 (≥2s):</span>
            <span class="text-slate-200">{{ behMetrics?.page_seconds ?? 0 }} s</span>
          </div>
        </div>
      </div>

      <!-- 一键红队注入器（对应验收用例 6、7 等） -->
      <div class="mt-4 flex flex-wrap gap-2">
        <button
          class="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 font-mono text-xs text-rose-300 hover:bg-rose-500/20"
          @click="triggerSyntheticAndReport"
        >
          红队注入：30 点 dispatchEvent 合成事件 (SYNTHETIC_EVENT)
        </button>
        <button
          class="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 font-mono text-xs text-amber-300 hover:bg-amber-500/20"
          @click="triggerLinearAndReport"
        >
          红队注入：30 点严格直线匀速轨迹 (BOT_TRAJECTORY)
        </button>
        <button
          class="rounded-lg border border-indigo-500/40 bg-indigo-500/10 px-3 py-1.5 font-mono text-xs text-indigo-300 hover:bg-indigo-500/20"
          @click="triggerRoboticKeysAndReport"
        >
          红队注入：等间隔机械击键 (KEYBOARD_ROBOTIC)
        </button>
        <button
          class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 font-mono text-xs text-slate-300 hover:bg-slate-800"
          @click="submitBehavior(true)"
        >
          模拟零交互上报 (NO_INTERACTION_DEEP_ACCESS)
        </button>
      </div>

      <div v-if="behResult" class="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-3 font-mono text-xs">
        <div class="flex items-center gap-3">
          <span class="text-slate-400">行为风险分:</span>
          <span class="font-bold text-amber-300">{{ behResult.behavior_score }}</span>
          <span v-for="f in behResult.flags" :key="f" class="rounded bg-rose-500/20 px-2 py-0.5 text-rose-300">
            {{ f }}
          </span>
        </div>
        <div v-if="behResult.details.length" class="mt-1.5 text-[11px] text-slate-400">
          {{ behResult.details.join('；') }}
        </div>
      </div>
    </section>

    <!-- 11.4 反调试与完整性自检 -->
    <section class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 class="text-base font-bold text-white">11.4 反调试与原生函数完整性自检</h2>
          <p class="text-xs text-slate-400">
            检测闭包内 debugger 单步时间差、DevTools 窗口内外差值，以及 fetch / XHR.open 原生原型链完整性。
          </p>
        </div>
        <button
          class="rounded-lg border px-3 py-1.5 font-mono text-xs transition"
          :class="
            antiDebugLoopEnabled
              ? 'border-rose-500/50 bg-rose-500/20 text-rose-300'
              : 'border-slate-700 bg-slate-900 text-slate-300 hover:border-cyan-500/50'
          "
          @click="toggleAntiDebugLoop"
        >
          {{ antiDebugLoopEnabled ? '停止持续 debugger 反调试循环' : '开启持续 debugger 反调试循环' }}
        </button>
      </div>
      <div class="mt-3 flex flex-wrap gap-3 font-mono text-xs">
        <span class="rounded border border-slate-800 bg-slate-950 px-3 py-1.5">
          DevTools 状态:
          <strong :class="antiDebugStatus.triggered ? 'text-rose-400' : 'text-emerald-300'">
            {{ antiDebugStatus.triggered ? '已打开/单步命中' : '未检出异常' }}
          </strong>
        </span>
        <span class="rounded border border-slate-800 bg-slate-950 px-3 py-1.5 text-slate-300">
          debugger 耗时差: {{ antiDebugStatus.deltaMs }} ms
        </span>
        <span class="rounded border border-slate-800 bg-slate-950 px-3 py-1.5 text-slate-300">
          fetch/XHR Hook 检测: {{ fpPayload?.automation.hooked_native ? '已被篡改!' : '原生 [native code]' }}
        </span>
      </div>
    </section>
  </div>
</template>
