<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import ProfileDrawer from '@/components/ProfileDrawer.vue'
import RequestList from '@/components/RequestList.vue'
import { labState } from '@/services/labState'
import type {
  BanRecord,
  DashboardStats,
  FingerprintProfile,
  RiskLogItem,
} from '@/types/lab'

const events = ref<RiskLogItem[]>([])
const seenIds = new Set<number>()
const stats = ref<DashboardStats>({
  today_requests: 0,
  block_rate: 0,
  warn_rate: 0,
  active_fingerprints: 0,
  decoy_served_count: 0,
})
const bans = ref<BanRecord[]>([])

const moduleFilter = ref('')
const actionFilter = ref('')
const sseConnected = ref(false)
const showRulesModal = ref(false)

const drawerVisible = ref(false)
const drawerLoading = ref(false)
const selectedItem = ref<RiskLogItem | null>(null)
const selectedFingerprint = ref<FingerprintProfile | null>(null)

let eventSource: EventSource | null = null

async function loadInitialData(): Promise<void> {
  if (!labState.labMode) return
  const params = new URLSearchParams({ page: '1', size: '80' })
  if (moduleFilter.value) params.set('module', moduleFilter.value)
  if (actionFilter.value) params.set('action', actionFilter.value)

  const [reqResp, statResp, banResp] = await Promise.all([
    fetch(`/api/v1/admin/requests?${params.toString()}`),
    fetch('/api/v1/admin/stats'),
    fetch('/api/v1/admin/bans'),
  ])

  if (reqResp.ok) {
    const data = (await reqResp.json()) as { items: RiskLogItem[] }
    seenIds.clear()
    for (const item of data.items) seenIds.add(item.id)
    events.value = data.items
  }
  if (statResp.ok) {
    stats.value = (await statResp.json()) as DashboardStats
  }
  if (banResp.ok) {
    const bData = (await banResp.json()) as { items: BanRecord[] }
    bans.value = bData.items
  }
}

function connectSse(): void {
  if (eventSource) {
    eventSource.close()
  }
  // 契约第 12 章：必须使用原生 EventSource，禁止轮询
  eventSource = new EventSource('/api/v1/events')
  eventSource.onopen = () => {
    sseConnected.value = true
  }
  eventSource.onerror = () => {
    sseConnected.value = false
  }
  eventSource.addEventListener('risk', (ev: MessageEvent<string>) => {
    try {
      const payload = JSON.parse(ev.data) as RiskLogItem
      if (seenIds.has(payload.id)) return
      if (moduleFilter.value && payload.module !== moduleFilter.value) return
      if (actionFilter.value && payload.action !== actionFilter.value) return

      seenIds.add(payload.id)
      events.value = [payload, ...events.value].slice(0, 150)

      // 实时刷新顶部统计指标
      stats.value.today_requests += 1
      if (payload.decoy_served) stats.value.decoy_served_count += 1
      if (payload.reasons.includes('HONEYPOT_TRIGGERED')) {
        void refreshBansAndStats()
      }
    } catch {
      // 忽略畸形事件帧
    }
  })
}

async function refreshBansAndStats(): Promise<void> {
  const [statResp, banResp] = await Promise.all([
    fetch('/api/v1/admin/stats'),
    fetch('/api/v1/admin/bans'),
  ])
  if (statResp.ok) stats.value = (await statResp.json()) as DashboardStats
  if (banResp.ok) {
    const bData = (await banResp.json()) as { items: BanRecord[] }
    bans.value = bData.items
  }
}

async function openProfile(item: RiskLogItem): Promise<void> {
  drawerVisible.value = true
  drawerLoading.value = true
  selectedItem.value = item
  selectedFingerprint.value = null
  try {
    const resp = await fetch(`/api/v1/admin/requests?id=${item.id}`)
    if (resp.ok) {
      const data = (await resp.json()) as {
        item: RiskLogItem
        fingerprint: FingerprintProfile | null
      }
      selectedItem.value = data.item
      selectedFingerprint.value = data.fingerprint
    }
  } finally {
    drawerLoading.value = false
  }
}

async function handleUnban(ip: string): Promise<void> {
  await fetch('/api/v1/admin/unban', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, operator: 'dashboard' }),
  })
  await refreshBansAndStats()
}

async function handleReset(ip: string): Promise<void> {
  await fetch('/api/v1/admin/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, operator: 'dashboard' }),
  })
  await refreshBansAndStats()
}

function downloadLocalExport(): void {
  window.open('/api/v1/admin/export?limit=200', '_blank')
}

onMounted(() => {
  void loadInitialData()
  connectSse()
})

onUnmounted(() => {
  eventSource?.close()
})
</script>

<template>
  <div class="mx-auto max-w-7xl space-y-5 px-4 py-6">
    <!-- LAB_MODE=0 安全保护提示 -->
    <div
      v-if="!labState.labMode"
      class="rounded-2xl border border-rose-500/40 bg-rose-950/20 p-6 text-center text-sm text-rose-300"
    >
      当前运行在生产语义模式（LAB_MODE=0），未鉴权管理端点已安全关闭；仅 SSE 实时事件流仍可按需观测。
    </div>

    <!-- 顶部状态栏 & 5 张统计卡片 -->
    <section class="flex flex-wrap items-center justify-between gap-3">
      <div class="flex items-center gap-3">
        <h1 class="text-xl font-bold text-white">SOC 实时风控监测仪表盘</h1>
        <span
          class="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[11px]"
          :class="
            sseConnected
              ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
              : 'border-amber-500/40 bg-amber-500/15 text-amber-300'
          "
        >
          <span class="h-1.5 w-1.5 rounded-full" :class="sseConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'"></span>
          {{ sseConnected ? 'SSE 实时流已连接' : 'SSE 重连中...' }}
        </span>
      </div>

      <div class="flex flex-wrap items-center gap-2 font-mono text-xs">
        <button
          class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-slate-300 hover:border-cyan-500/50"
          @click="showRulesModal = !showRulesModal"
        >
          {{ showRulesModal ? '隐藏规则权重表' : '查看动态规则权重表' }}
        </button>
        <button
          v-if="labState.labMode"
          class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-slate-300 hover:border-emerald-500/50"
          @click="downloadLocalExport"
        >
          本地导出日志 JSON
        </button>
      </div>
    </section>

    <section class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      <div class="rounded-xl border border-slate-800 bg-[#0d1422] p-4">
        <div class="text-xs text-slate-400">今日请求量</div>
        <div class="mt-1 font-mono text-2xl font-bold text-white">{{ stats.today_requests }}</div>
      </div>
      <div class="rounded-xl border border-slate-800 bg-[#0d1422] p-4">
        <div class="text-xs text-slate-400">拦截率 (Block)</div>
        <div class="mt-1 font-mono text-2xl font-bold text-rose-400">{{ stats.block_rate }}%</div>
      </div>
      <div class="rounded-xl border border-slate-800 bg-[#0d1422] p-4">
        <div class="text-xs text-slate-400">警告/挑战率</div>
        <div class="mt-1 font-mono text-2xl font-bold text-amber-300">{{ stats.warn_rate }}%</div>
      </div>
      <div class="rounded-xl border border-slate-800 bg-[#0d1422] p-4">
        <div class="text-xs text-slate-400">活跃指纹数</div>
        <div class="mt-1 font-mono text-2xl font-bold text-cyan-300">{{ stats.active_fingerprints }}</div>
      </div>
      <div class="rounded-xl border border-slate-800 bg-[#0d1422] p-4">
        <div class="text-xs text-slate-400">诱饵投喂数</div>
        <div class="mt-1 font-mono text-2xl font-bold text-emerald-300">{{ stats.decoy_served_count }}</div>
      </div>
    </section>

    <!-- 规则权重参考面板（来自后端 rules_meta，无硬编码） -->
    <section
      v-if="showRulesModal && labState.rulesMeta"
      class="rounded-2xl border border-cyan-500/30 bg-[#0d1422] p-4 text-xs"
    >
      <h2 class="font-mono font-bold text-cyan-300">风控原因码与评分权重（GET /api/v1/health 实时下发）</h2>
      <div class="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        <div
          v-for="(meta, code) in labState.rulesMeta.reasons"
          :key="code"
          class="rounded-lg border border-slate-800 bg-slate-950/70 p-2.5"
        >
          <div class="flex items-center justify-between font-mono">
            <span class="text-amber-300">{{ code }}</span>
            <span class="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">{{ meta.module }}</span>
          </div>
          <div class="mt-1 font-semibold text-slate-200">{{ meta.label }}</div>
          <div class="mt-0.5 text-[11px] text-slate-400">{{ meta.description }}</div>
        </div>
      </div>
    </section>

    <!-- 筛选栏 -->
    <section class="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-[#0d1422] px-4 py-3 text-xs">
      <div class="flex flex-wrap items-center gap-2">
        <span class="text-slate-400">关卡筛选:</span>
        <select
          v-model="moduleFilter"
          class="rounded border border-slate-700 bg-slate-900 px-2.5 py-1 font-mono text-slate-200"
          @change="loadInitialData"
        >
          <option value="">全部模块</option>
          <option value="network">network (网络/协议)</option>
          <option value="fingerprint">fingerprint (指纹)</option>
          <option value="automation">automation (自动化)</option>
          <option value="behavior">behavior (行为)</option>
          <option value="business">business (签名/业务)</option>
        </select>

        <span class="ml-2 text-slate-400">处置状态:</span>
        <select
          v-model="actionFilter"
          class="rounded border border-slate-700 bg-slate-900 px-2.5 py-1 font-mono text-slate-200"
          @change="loadInitialData"
        >
          <option value="">全部状态</option>
          <option value="pass">PASS 放行</option>
          <option value="warn">WARN 警告</option>
          <option value="challenge">CHALLENGE 挑战</option>
          <option value="block">BLOCK 拦截</option>
        </select>
      </div>

      <button
        class="rounded border border-slate-700 bg-slate-900 px-3 py-1 font-mono text-slate-300 hover:bg-slate-800"
        @click="loadInitialData"
      >
        手动刷新历史
      </button>
    </section>

    <!-- 实时请求列表 -->
    <RequestList :items="events" :selected-id="selectedItem?.id" @select="openProfile" />

    <!-- 封禁列表与一键解封视图 -->
    <section v-if="labState.labMode" class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5">
      <div class="flex items-center justify-between">
        <h2 class="text-base font-bold text-white">IP 封禁列表与解封审计（bans 表）</h2>
        <button
          class="rounded border border-slate-700 bg-slate-900 px-2.5 py-1 font-mono text-xs text-slate-300 hover:bg-slate-800"
          @click="refreshBansAndStats"
        >
          刷新封禁列表
        </button>
      </div>
      <div class="mt-3 overflow-x-auto">
        <table class="w-full text-left font-mono text-xs">
          <thead class="border-b border-slate-800 text-[11px] text-slate-400">
            <tr>
              <th class="py-2">IP 地址</th>
              <th class="py-2">原因码</th>
              <th class="py-2">封禁时间</th>
              <th class="py-2">解封状态 / 操作人</th>
              <th class="py-2 text-right">操作</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-800/70">
            <tr v-for="b in bans" :key="b.id">
              <td class="py-2 text-slate-200">{{ b.ip }}</td>
              <td class="py-2 text-amber-300">{{ b.reason_code }}</td>
              <td class="py-2 text-slate-400">{{ b.banned_at }}</td>
              <td class="py-2">
                <span v-if="b.active" class="rounded bg-rose-500/20 px-2 py-0.5 text-rose-300">封禁生效中</span>
                <span v-else class="text-emerald-300">已解封 ({{ b.lifted_by || 'auto' }})</span>
              </td>
              <td class="py-2 text-right">
                <button
                  v-if="b.active"
                  class="mr-2 rounded border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-emerald-300 hover:bg-emerald-500/20"
                  @click="handleUnban(b.ip)"
                >
                  解封
                </button>
                <button
                  class="rounded border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 text-cyan-300 hover:bg-cyan-500/20"
                  @click="handleReset(b.ip)"
                >
                  重置计数
                </button>
              </td>
            </tr>
            <tr v-if="bans.length === 0">
              <td colspan="5" class="py-4 text-center text-slate-500">当前无封禁记录</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <ProfileDrawer
      :visible="drawerVisible"
      :item="selectedItem"
      :fingerprint="selectedFingerprint"
      :loading="drawerLoading"
      @close="drawerVisible = false"
      @unban="handleUnban"
      @reset="handleReset"
    />
  </div>
</template>
