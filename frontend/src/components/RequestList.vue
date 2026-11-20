<script setup lang="ts">
import { ref } from 'vue'
import ScoreBadge from './ScoreBadge.vue'
import { getReasonMeta } from '@/services/labState'
import type { RiskLogItem } from '@/types/lab'

defineProps<{
  items: RiskLogItem[]
  selectedId?: number | null
}>()

const emit = defineEmits<{
  select: [item: RiskLogItem]
}>()

const expandedIds = ref<Set<number>>(new Set())

function toggleExpand(id: number, ev: Event): void {
  ev.stopPropagation()
  if (expandedIds.value.has(id)) {
    expandedIds.value.delete(id)
  } else {
    expandedIds.value.add(id)
  }
}

function formatTime(iso: string): string {
  const tIdx = iso.indexOf('T')
  if (tIdx === -1) return iso
  return iso.slice(tIdx + 1, tIdx + 13)
}
</script>

<template>
  <div class="overflow-hidden rounded-xl border border-slate-800 bg-[#0d1422]">
    <div class="overflow-x-auto">
      <table class="w-full text-left text-xs">
        <thead class="border-b border-slate-800 bg-slate-950/70 font-mono text-[11px] uppercase text-slate-400">
          <tr>
            <th class="px-3 py-2.5">ID / 时间</th>
            <th class="px-3 py-2.5">Client IP</th>
            <th class="px-3 py-2.5">Effective IP</th>
            <th class="px-3 py-2.5">关卡 / 路径</th>
            <th class="px-3 py-2.5">状态</th>
            <th class="px-3 py-2.5">风险分</th>
            <th class="px-3 py-2.5">原因码 / 诱饵</th>
            <th class="px-3 py-2.5 text-right">耗时</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-800/70">
          <template v-for="item in items" :key="item.id">
            <tr
              class="cursor-pointer transition hover:bg-slate-800/50"
              :class="selectedId === item.id ? 'bg-emerald-500/10' : ''"
              @click="emit('select', item)"
            >
              <td class="whitespace-nowrap px-3 py-2.5 font-mono">
                <div class="text-slate-200">#{{ item.id }}</div>
                <div class="text-[10px] text-slate-500">{{ formatTime(item.ts) }}</div>
              </td>
              <td class="whitespace-nowrap px-3 py-2.5 font-mono text-slate-400">
                {{ item.client_ip }}
              </td>
              <td class="whitespace-nowrap px-3 py-2.5 font-mono">
                <span :class="item.effective_ip !== item.client_ip ? 'text-amber-300' : 'text-slate-200'">
                  {{ item.effective_ip }}
                </span>
              </td>
              <td class="px-3 py-2.5">
                <span class="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-cyan-300">
                  {{ item.module }}
                </span>
                <div class="mt-0.5 max-w-[200px] truncate font-mono text-[11px] text-slate-300">
                  {{ item.path }}
                </div>
              </td>
              <td class="whitespace-nowrap px-3 py-2.5">
                <ScoreBadge :action="item.action" />
              </td>
              <td class="whitespace-nowrap px-3 py-2.5 font-mono font-bold">
                <span
                  :class="
                    item.risk_score >= 70
                      ? 'text-rose-400'
                      : item.risk_score >= 40
                        ? 'text-amber-300'
                        : 'text-emerald-300'
                  "
                >
                  {{ item.risk_score }}
                </span>
              </td>
              <td class="px-3 py-2.5">
                <div class="flex flex-wrap items-center gap-1">
                  <span
                    v-for="r in item.reasons"
                    :key="r"
                    class="rounded border border-slate-700 bg-slate-900 px-1.5 py-0.5 font-mono text-[10px] text-slate-200"
                    :title="getReasonMeta(r)?.description || r"
                  >
                    {{ getReasonMeta(r)?.label || r }}
                  </span>
                  <span
                    v-if="item.decoy_served"
                    class="rounded border border-amber-500/40 bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] text-amber-300"
                  >
                    已投喂诱饵
                  </span>
                  <button
                    v-if="item.reasons.length > 0"
                    class="ml-1 font-mono text-[10px] text-cyan-400 hover:underline"
                    @click="toggleExpand(item.id, $event)"
                  >
                    {{ expandedIds.has(item.id) ? '收起释义' : '展开释义' }}
                  </button>
                </div>
              </td>
              <td class="whitespace-nowrap px-3 py-2.5 text-right font-mono text-[11px] text-slate-400">
                {{ item.latency_ms.toFixed(1) }} ms
              </td>
            </tr>
            <tr v-if="expandedIds.has(item.id)" class="bg-slate-950/70">
              <td colspan="8" class="px-4 py-2.5 text-xs">
                <div class="space-y-1">
                  <div v-for="r in item.reasons" :key="r" class="flex items-start gap-2">
                    <code class="rounded bg-slate-900 px-1.5 py-0.5 text-[11px] text-amber-300">{{ r }}</code>
                    <span class="text-slate-300">
                      <strong class="text-slate-100">{{ getReasonMeta(r)?.label || r }}</strong>：
                      {{ getReasonMeta(r)?.description || '命中风控规则' }}
                    </span>
                  </div>
                </div>
              </td>
            </tr>
          </template>
          <tr v-if="items.length === 0">
            <td colspan="8" class="px-4 py-10 text-center text-slate-500">
              暂无风控事件，请在关卡页面或演练台发起请求，事件将在 1 秒内经 SSE 实时推送至此。
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
