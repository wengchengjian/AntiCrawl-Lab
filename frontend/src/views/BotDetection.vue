<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { BehaviorTracker, collectBotAuditPayload } from '@/probes'
import { buildLabHeaders, captureRateLimitHeaders } from '@/services/labState'
import type { BotCheckPayload, BotCheckResponse } from '@/types/lab'

const loading = ref(false)
const result = ref<BotCheckResponse | null>(null)
const lastPayload = ref<BotCheckPayload | null>(null)
const activeCategory = ref<string>('all')
const showRawJson = ref(false)
const quickHttpResult = ref<BotCheckResponse | null>(null)

const tracker = new BehaviorTracker()

const categories = [
  { id: 'all', label: '全部指标' },
  { id: 'sannysoft', label: 'Sannysoft 无头/自动化' },
  { id: 'browserscan', label: 'BrowserScan 一致性' },
  { id: 'browserleaks', label: 'BrowserLeaks 泄露审计' },
  { id: 'network', label: 'Network 网络协议' },
  { id: 'behavior', label: 'Behavior 行为动力学' },
]

const filteredChecks = computed(() => {
  if (!result.value) return []
  if (activeCategory.value === 'all') return result.value.checks
  return result.value.checks.filter((c) => c.category === activeCategory.value)
})

const verdictStyle = computed(() => {
  switch (result.value?.verdict) {
    case 'likely_human':
      return {
        border: 'border-emerald-500/40 bg-emerald-950/20',
        text: 'text-emerald-300',
        bar: 'bg-emerald-400',
        badge: 'LIKELY HUMAN · 真实人类浏览器',
      }
    case 'suspicious':
      return {
        border: 'border-amber-500/40 bg-amber-950/20',
        text: 'text-amber-300',
        bar: 'bg-amber-400',
        badge: 'SUSPICIOUS · 存在可疑破绽',
      }
    default:
      return {
        border: 'border-rose-500/40 bg-rose-950/20',
        text: 'text-rose-300',
        bar: 'bg-rose-500',
        badge: 'LIKELY BOT · 高概率机器人',
      }
  }
})

async function runFullAudit(customPayload?: BotCheckPayload, simIp?: string): Promise<void> {
  loading.value = true
  quickHttpResult.value = null
  try {
    const beh = tracker.points.length > 0 ? tracker.buildPayload() : undefined
    const payload = customPayload ?? (await collectBotAuditPayload(beh))
    lastPayload.value = payload

    const headers = buildLabHeaders({ 'Content-Type': 'application/json' })
    if (simIp) {
      headers['X-Simulated-IP'] = simIp
    }
    const resp = await fetch('/api/v1/bot/check', {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    })
    captureRateLimitHeaders(resp)
    result.value = (await resp.json()) as BotCheckResponse
  } finally {
    loading.value = false
  }
}

async function simulateHeadlessBot(): Promise<void> {
  const base = lastPayload.value ?? (await collectBotAuditPayload())
  const botPayload: BotCheckPayload = {
    ...base,
    ua: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/126.0.0.0 Safari/537.36',
    platform: 'Linux x86_64',
    webgl: {
      vendor: 'Google Inc. (Google)',
      renderer: 'ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)))',
      masked: false,
      params_hash: base.webgl.params_hash,
    },
    fonts: { detected: ['DejaVu Sans'], count: 1 },
    automation: {
      ...base.automation,
      webdriver: true,
      webdriver_getter_tampered: true,
      cdc_keys: ['$cdc_asdjflasutopfhvcZLmcfl_'],
      cdp_console_probe: true,
      has_window_chrome: false,
      plugins_length: 0,
      iframe_mismatch: true,
      stack_automation_frame: true,
    },
    extra_probes: {
      ...base.extra_probes,
      window_dims: { outerWidth: 0, outerHeight: 0, innerWidth: 1280, innerHeight: 720 },
      sannysoft: {
        ...(base.extra_probes.sannysoft as Record<string, unknown>),
        permissions_inconsistent: true,
        perm_detail: 'Notification=denied, query=prompt',
        chrome_subprops: { present: false, runtime: false },
        mime_types_length: 0,
      },
      browserleaks: {
        ...(base.extra_probes.browserleaks as Record<string, unknown>),
        media_devices_count: 0,
        speech_voices_count: 0,
      },
    },
  }
  await runFullAudit(botPayload, '52.95.10.20')
}

async function simulateNoiseAndProxySpoof(): Promise<void> {
  const base = lastPayload.value ?? (await collectBotAuditPayload())
  const spoofPayload: BotCheckPayload = {
    ...base,
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    platform: 'Win32',
    timezone: 'Asia/Shanghai',
    languages: ['zh-CN'],
    extra_probes: {
      ...base.extra_probes,
      canvas_hash_2: 'poisoned_noise_' + Math.random().toString(16).slice(2, 10),
      timezone_offset: 0,
      worker: {
        supported: true,
        ua: 'Mozilla/5.0 (Windows NT 10.0) Chrome/126.0.0.0',
        platform: 'MacIntel',
      },
      browserleaks: {
        ...(base.extra_probes.browserleaks as Record<string, unknown>),
        client_rects_hash: 'rect_a_1111',
        client_rects_hash_2: 'rect_b_9999',
      },
    },
  }
  await runFullAudit(spoofPayload, '52.95.10.20')
}

async function runQuickHttpGetCheck(): Promise<void> {
  loading.value = true
  try {
    const resp = await fetch('/api/v1/bot/check', {
      headers: buildLabHeaders(),
    })
    captureRateLimitHeaders(resp)
    quickHttpResult.value = (await resp.json()) as BotCheckResponse
  } finally {
    loading.value = false
  }
}

function exportReportJson(): void {
  if (!result.value) return
  const blob = new Blob([JSON.stringify(result.value, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `anticrawl-bot-audit-${result.value.request_id}.json`
  a.click()
  URL.revokeObjectURL(url)
}

function statusPillClass(status: string): string {
  switch (status) {
    case 'pass':
      return 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
    case 'warn':
      return 'border-amber-500/40 bg-amber-500/15 text-amber-300'
    case 'fail':
      return 'border-rose-500/40 bg-rose-500/15 text-rose-300'
    default:
      return 'border-cyan-500/40 bg-cyan-500/15 text-cyan-300'
  }
}

onMounted(() => {
  tracker.attach()
  void runFullAudit()
})

onUnmounted(() => {
  tracker.detach()
})
</script>

<template>
  <div class="mx-auto max-w-7xl space-y-6 px-4 py-6">
    <!-- 顶部标题与对抗操作栏 -->
    <section class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <span class="rounded bg-emerald-500/15 px-2 py-0.5 font-mono text-[10px] text-emerald-300">
            BOT DETECTION ENGINE · BrowserScan × BrowserLeaks × Sannysoft
          </span>
          <h1 class="mt-1.5 text-xl font-bold text-white sm:text-2xl">
            全维度机器人检测与置信分评估台
          </h1>
          <p class="mt-1 text-xs text-slate-400">
            对应 API：<code class="text-cyan-300">GET / POST /api/v1/bot/check</code> · 融合 5 大维度 30+ 项工业级自动化与伪装指纹指标，输出置信分与可解释原因。
          </p>
        </div>

        <div class="flex flex-wrap gap-2 font-mono text-xs">
          <button
            :disabled="loading"
            class="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-50"
            @click="runFullAudit()"
          >
            {{ loading ? '审计中...' : '重新执行全量体检' }}
          </button>
          <button
            :disabled="loading"
            class="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-rose-300 hover:bg-rose-500/20 disabled:opacity-50"
            @click="simulateHeadlessBot"
          >
            模拟无头 Playwright 机器人
          </button>
          <button
            :disabled="loading"
            class="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-amber-300 hover:bg-amber-500/20 disabled:opacity-50"
            @click="simulateNoiseAndProxySpoof"
          >
            模拟防指纹加噪 + 跨国代理
          </button>
          <button
            :disabled="loading"
            class="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50"
            @click="runQuickHttpGetCheck"
          >
            测试纯 HTTP GET 检测
          </button>
          <button
            v-if="result"
            class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-slate-300 hover:border-slate-500"
            @click="showRawJson = !showRawJson"
          >
            {{ showRawJson ? '隐藏 API JSON' : 'API JSON' }}
          </button>
          <button
            v-if="result"
            class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-slate-300 hover:border-emerald-500/50"
            @click="exportReportJson"
          >
            本地导出报告
          </button>
        </div>
      </div>
    </section>

    <!-- 置信分总览仪表区 -->
    <section v-if="result" class="grid gap-4 lg:grid-cols-3">
      <div class="rounded-2xl border p-5" :class="verdictStyle.border">
        <div class="flex items-center justify-between font-mono text-[11px]">
          <span :class="verdictStyle.text">{{ verdictStyle.badge }}</span>
          <span class="rounded bg-slate-900/90 px-2 py-0.5 text-slate-300">
            置信等级: {{ result.confidence_level.toUpperCase() }}
          </span>
        </div>

        <div class="mt-4 grid grid-cols-2 gap-3 font-mono">
          <div class="rounded-xl border border-slate-800/80 bg-slate-950/70 p-3">
            <div class="text-[11px] text-slate-400">真实度 (Human)</div>
            <div class="mt-1 text-3xl font-bold text-emerald-300">{{ result.human_confidence }}%</div>
          </div>
          <div class="rounded-xl border border-slate-800/80 bg-slate-950/70 p-3">
            <div class="text-[11px] text-slate-400">机器人置信分 (Bot)</div>
            <div class="mt-1 text-3xl font-bold" :class="verdictStyle.text">
              {{ result.bot_confidence }}%
            </div>
          </div>
        </div>

        <div class="mt-3 h-2.5 w-full overflow-hidden rounded-full bg-slate-900">
          <div
            class="h-full transition-all duration-300"
            :class="verdictStyle.bar"
            :style="{ width: `${result.bot_confidence}%` }"
          ></div>
        </div>

        <p class="mt-3 text-xs text-slate-300">{{ result.summary }}</p>
        <div class="mt-2 font-mono text-[11px] text-slate-400">
          IP: {{ result.effective_ip }} ({{ result.ip_geo.country }}/{{ result.ip_geo.city }}) · Log #{{ result.request_id }}
        </div>
      </div>

      <!-- Top 命中原因列表 -->
      <div class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5 lg:col-span-2">
        <div class="flex items-center justify-between">
          <h2 class="text-sm font-bold text-white">置信分归因明细（按权重降序）</h2>
          <span class="font-mono text-xs text-slate-400">共 {{ result.reasons.length }} 项扣分触发</span>
        </div>

        <div v-if="result.reasons.length" class="mt-3 max-h-56 space-y-2 overflow-y-auto pr-1 text-xs">
          <div
            v-for="r in result.reasons"
            :key="r.id"
            class="flex items-start justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950/70 p-3"
          >
            <div>
              <div class="flex flex-wrap items-center gap-2 font-mono">
                <span class="rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] text-rose-300">
                  +{{ r.weight }} 分
                </span>
                <span class="text-amber-300">{{ r.code }}</span>
                <span class="text-[10px] text-slate-400">[{{ r.source_ref }}]</span>
              </div>
              <p class="mt-1 text-slate-200">{{ r.message }}</p>
            </div>
          </div>
        </div>
        <div
          v-else
          class="mt-4 rounded-xl border border-emerald-500/30 bg-emerald-950/15 p-6 text-center text-xs text-emerald-300"
        >
          全部 30+ 项 Sannysoft / BrowserScan / BrowserLeaks 指标校验均未发现异常伪装或自动化痕迹。
        </div>
      </div>
    </section>

    <!-- 纯 HTTP GET /api/v1/bot/check 结果展示（如有） -->
    <section
      v-if="quickHttpResult"
      class="rounded-2xl border border-cyan-500/40 bg-cyan-950/15 p-4 font-mono text-xs"
    >
      <div class="flex items-center justify-between text-cyan-300">
        <span>GET /api/v1/bot/check（仅 HTTP 协议与 IP 维度快速评分）</span>
        <span>Bot={{ quickHttpResult.bot_confidence }}% · Verdict={{ quickHttpResult.verdict }}</span>
      </div>
      <div class="mt-1 text-slate-300">{{ quickHttpResult.summary }}</div>
    </section>

    <!-- 5 维度分类筛选卡片 -->
    <section v-if="result" class="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
      <button
        v-for="cat in categories"
        :key="cat.id"
        class="rounded-xl border p-3 text-left transition"
        :class="
          activeCategory === cat.id
            ? 'border-emerald-500/60 bg-emerald-500/10'
            : 'border-slate-800 bg-[#0d1422] hover:border-slate-600'
        "
        @click="activeCategory = cat.id"
      >
        <div class="text-[11px] font-medium text-slate-300">{{ cat.label }}</div>
        <div class="mt-1 font-mono text-base font-bold text-white">
          {{
            cat.id === 'all'
              ? `${result.bot_confidence}%`
              : `+${result.category_scores[cat.id] ?? 0}`
          }}
        </div>
      </button>
    </section>

    <!-- Sannysoft 风格逐项审计表格 -->
    <section v-if="result" class="overflow-hidden rounded-2xl border border-slate-800 bg-[#0d1422]">
      <div class="border-b border-slate-800 px-5 py-3 flex items-center justify-between">
        <h2 class="text-sm font-bold text-white">逐项浏览器指纹与自动化审计明细（{{ filteredChecks.length }} 项）</h2>
        <span class="font-mono text-[11px] text-slate-400">绿=正常 / 黄=警告 / 红=异常</span>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead class="border-b border-slate-800 bg-slate-950/70 font-mono text-[11px] text-slate-400">
            <tr>
              <th class="px-3 py-2.5">来源矩阵</th>
              <th class="px-3 py-2.5">检测项目</th>
              <th class="px-3 py-2.5">状态</th>
              <th class="px-3 py-2.5">当前观测值</th>
              <th class="px-3 py-2.5">期望基线</th>
              <th class="px-3 py-2.5 text-right">置信加分</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-800/70">
            <tr v-for="chk in filteredChecks" :key="chk.id" class="hover:bg-slate-800/40">
              <td class="whitespace-nowrap px-3 py-2.5 font-mono text-[11px] text-cyan-300">
                {{ chk.source_ref }}
              </td>
              <td class="px-3 py-2.5">
                <div class="font-semibold text-slate-100">{{ chk.name }}</div>
                <div class="text-[11px] text-slate-400">{{ chk.reason }}</div>
              </td>
              <td class="whitespace-nowrap px-3 py-2.5">
                <span
                  class="rounded-full border px-2 py-0.5 font-mono text-[10px] font-bold uppercase"
                  :class="statusPillClass(chk.status)"
                >
                  {{ chk.status }}
                </span>
              </td>
              <td class="max-w-[220px] truncate px-3 py-2.5 font-mono text-[11px] text-slate-300" :title="chk.observed">
                {{ chk.observed }}
              </td>
              <td class="max-w-[200px] truncate px-3 py-2.5 font-mono text-[11px] text-slate-500" :title="chk.expected">
                {{ chk.expected }}
              </td>
              <td class="whitespace-nowrap px-3 py-2.5 text-right font-mono font-bold">
                <span :class="chk.risk_delta > 0 ? 'text-rose-400' : 'text-slate-500'">
                  {{ chk.risk_delta > 0 ? `+${chk.risk_delta}` : '0' }}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- API 原始 JSON 抽屉 -->
    <section v-if="showRawJson && result" class="rounded-2xl border border-slate-800 bg-[#0d1422] p-4">
      <div class="font-mono text-xs font-semibold text-emerald-300">POST /api/v1/bot/check 完整响应载荷</div>
      <pre class="mt-2 max-h-96 overflow-auto rounded-xl bg-slate-950 p-3 font-mono text-[11px] text-slate-300">{{
        JSON.stringify(result, null, 2)
      }}</pre>
    </section>
  </div>
</template>
