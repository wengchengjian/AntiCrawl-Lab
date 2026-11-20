<script setup lang="ts">
import ScoreBadge from './ScoreBadge.vue'
import { getReasonMeta } from '@/services/labState'
import type { FingerprintProfile, RiskLogItem } from '@/types/lab'

const props = defineProps<{
  visible: boolean
  item: RiskLogItem | null
  fingerprint: FingerprintProfile | null
  loading: boolean
}>()

const emit = defineEmits<{
  close: []
  unban: [ip: string]
  reset: [ip: string]
}>()

function exportSingleJson(): void {
  if (!props.item) return
  const payload = {
    request: props.item,
    fingerprint: props.fingerprint,
    exported_at: new Date().toISOString(),
  }
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `anticrawl-profile-${props.item.id}.json`
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <div v-if="visible" class="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm" @click.self="emit('close')">
    <aside class="h-full w-full max-w-2xl overflow-y-auto border-l border-slate-800 bg-[#0b111e] p-6 shadow-2xl">
      <div class="flex items-start justify-between border-b border-slate-800 pb-4">
        <div>
          <div class="font-mono text-xs text-slate-400">请求详情与浏览器指纹画像</div>
          <h2 class="mt-1 font-mono text-lg font-bold text-white">
            事件 #{{ item?.id }} · {{ item?.effective_ip }}
          </h2>
        </div>
        <div class="flex items-center gap-2">
          <button
            class="rounded border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs text-slate-300 hover:border-cyan-500/50"
            @click="exportSingleJson"
          >
            本地导出 JSON
          </button>
          <button class="rounded border border-slate-700 px-2.5 py-1 text-xs text-slate-400 hover:text-white" @click="emit('close')">
            关闭
          </button>
        </div>
      </div>

      <div v-if="loading" class="py-12 text-center font-mono text-xs text-slate-400">正在加载完整画像...</div>

      <div v-else-if="item" class="mt-5 space-y-5 text-xs">
        <!-- 决策摘要与管理动作 -->
        <div class="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950/60 p-4">
          <div class="flex items-center gap-3">
            <ScoreBadge :action="item.action" :score="item.risk_score" />
            <span
              v-if="item.decoy_served"
              class="rounded border border-amber-500/40 bg-amber-500/15 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-amber-300"
            >
              该会话已投喂诱饵
            </span>
          </div>
          <div class="flex items-center gap-2">
            <button
              class="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 font-mono text-[11px] text-emerald-300 hover:bg-emerald-500/20"
              @click="emit('unban', item.effective_ip)"
            >
              一键解封 IP
            </button>
            <button
              class="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 font-mono text-[11px] text-cyan-300 hover:bg-cyan-500/20"
              @click="emit('reset', item.effective_ip)"
            >
              清空限流/告警缓存
            </button>
          </div>
        </div>

        <!-- 8 步流水线轨迹 -->
        <div v-if="item.extra?.pipeline_steps?.length" class="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
          <h3 class="font-mono text-xs font-semibold uppercase text-cyan-300">风控中间件流水线执行轨迹</h3>
          <div class="mt-3 space-y-1.5">
            <div
              v-for="st in item.extra.pipeline_steps"
              :key="`${st.step}-${st.name}`"
              class="flex items-start justify-between gap-2 rounded border border-slate-800/70 bg-slate-900/60 px-3 py-2"
            >
              <div>
                <span class="font-mono text-slate-400">Step {{ st.step }}</span>
                <span class="ml-2 font-semibold text-slate-200">{{ st.name }}</span>
                <div class="mt-0.5 text-[11px] text-slate-400">{{ st.detail }}</div>
              </div>
              <div class="whitespace-nowrap font-mono text-[11px]">
                <span
                  :class="
                    st.status === 'blocked' || st.status === 'block'
                      ? 'text-rose-400'
                      : st.status === 'warn' || st.status === 'challenge'
                        ? 'text-amber-300'
                        : st.status === 'skip'
                          ? 'text-slate-500'
                          : 'text-emerald-400'
                  "
                >
                  {{ st.status.toUpperCase() }}
                </span>
                <span v-if="st.delta > 0" class="ml-1.5 text-amber-300">+{{ st.delta }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- 原因码释义 -->
        <div v-if="item.reasons.length" class="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
          <h3 class="font-mono text-xs font-semibold uppercase text-amber-300">拦截/告警原因码</h3>
          <div class="mt-2 space-y-2">
            <div v-for="r in item.reasons" :key="r" class="rounded border border-slate-800 bg-slate-900/60 p-2.5">
              <div class="flex items-center gap-2">
                <code class="font-mono text-amber-300">{{ r }}</code>
                <span class="font-semibold text-slate-100">{{ getReasonMeta(r)?.label || r }}</span>
              </div>
              <p class="mt-1 text-[11px] text-slate-400">{{ getReasonMeta(r)?.description }}</p>
            </div>
          </div>
        </div>

        <!-- 环境伪装破绽分组（9.3） -->
        <div
          v-if="item.extra?.conflicts?.length || item.extra?.conflict_item"
          class="rounded-xl border border-rose-500/30 bg-rose-950/10 p-4"
        >
          <h3 class="font-mono text-xs font-semibold uppercase text-rose-300">环境伪装破绽（一致性矩阵）</h3>
          <div class="mt-2.5 space-y-2">
            <div
              v-for="(cf, idx) in item.extra?.conflicts || (item.extra?.conflict_item ? [item.extra.conflict_item] : [])"
              :key="idx"
              class="rounded border border-rose-500/20 bg-slate-950/80 p-3"
            >
              <div class="flex items-center justify-between">
                <span class="font-mono font-semibold text-rose-300">{{ cf.rule_id }}</span>
                <span v-if="cf.is_enhanced" class="rounded bg-indigo-500/20 px-1.5 py-0.5 font-mono text-[10px] text-indigo-300">
                  增强对抗检测
                </span>
              </div>
              <div class="mt-1 text-slate-200">{{ cf.message }}</div>
              <div class="mt-1.5 grid grid-cols-2 gap-2 font-mono text-[11px]">
                <div class="rounded bg-slate-900 p-1.5 text-slate-300">左证: {{ cf.left_evidence }}</div>
                <div class="rounded bg-slate-900 p-1.5 text-slate-300">右证: {{ cf.right_evidence }}</div>
              </div>
            </div>
          </div>
        </div>

        <!-- 自动化与行为指标 -->
        <div
          v-if="item.extra?.automation_findings?.length || item.extra?.behavior_metrics"
          class="rounded-xl border border-slate-800 bg-slate-950/60 p-4"
        >
          <h3 class="font-mono text-xs font-semibold uppercase text-indigo-300">自动化与行为特征</h3>
          <ul v-if="item.extra?.automation_findings?.length" class="mt-2 list-disc space-y-1 pl-4 text-rose-300">
            <li v-for="(af, idx) in item.extra.automation_findings" :key="idx">{{ af }}</li>
          </ul>
          <div v-if="item.extra?.behavior_metrics" class="mt-3 grid grid-cols-3 gap-2 font-mono text-[11px]">
            <div class="rounded bg-slate-900 p-2">
              <div class="text-slate-400">isTrusted 比例</div>
              <div class="mt-0.5 font-bold text-emerald-300">
                {{ (item.extra.behavior_metrics.trusted_ratio * 100).toFixed(1) }}%
              </div>
            </div>
            <div class="rounded bg-slate-900 p-2">
              <div class="text-slate-400">轨迹点数 / 方向变化</div>
              <div class="mt-0.5 font-bold text-slate-100">
                {{ item.extra.behavior_metrics.point_count }} / {{ item.extra.behavior_metrics.direction_changes }}
              </div>
            </div>
            <div class="rounded bg-slate-900 p-2">
              <div class="text-slate-400">速度标准差 / 停留</div>
              <div class="mt-0.5 font-bold text-slate-100">
                {{ item.extra.behavior_metrics.velocity_std }} px/ms · {{ item.extra.behavior_metrics.page_seconds }}s
              </div>
            </div>
          </div>
        </div>

        <!-- 指纹画像详情 -->
        <div v-if="fingerprint" class="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
          <div class="flex items-center justify-between">
            <h3 class="font-mono text-xs font-semibold uppercase text-emerald-300">关联浏览器指纹画像</h3>
            <span class="font-mono text-[11px] text-amber-300">
              命中不同 IP 数: {{ fingerprint.hit_ips }}
            </span>
          </div>
          <div class="mt-3 grid grid-cols-2 gap-2.5 font-mono text-[11px]">
            <div class="col-span-2 rounded bg-slate-900 p-2">
              <span class="text-slate-400">fp_id:</span>
              <span class="ml-2 text-emerald-300">{{ fingerprint.fp_id }}</span>
            </div>
            <div class="col-span-2 rounded bg-slate-900 p-2 break-all">
              <span class="text-slate-400">User-Agent:</span>
              <span class="ml-2 text-slate-200">{{ fingerprint.ua }}</span>
            </div>
            <div class="rounded bg-slate-900 p-2">
              <span class="text-slate-400">Platform:</span> {{ fingerprint.platform }}
            </div>
            <div class="rounded bg-slate-900 p-2">
              <span class="text-slate-400">Timezone:</span> {{ fingerprint.timezone }}
            </div>
            <div class="rounded bg-slate-900 p-2">
              <span class="text-slate-400">Languages:</span> {{ fingerprint.languages.join(', ') }}
            </div>
            <div class="rounded bg-slate-900 p-2">
              <span class="text-slate-400">Screen / DPR:</span>
              {{ fingerprint.screen.width }}x{{ fingerprint.screen.height }} @{{ fingerprint.screen.device_pixel_ratio }}x
            </div>
            <div class="rounded bg-slate-900 p-2">
              <span class="text-slate-400">Canvas Hash:</span> {{ fingerprint.canvas_hash.slice(0, 16) }}...
            </div>
            <div class="rounded bg-slate-900 p-2">
              <span class="text-slate-400">Audio Hash:</span> {{ fingerprint.audio_hash.slice(0, 16) }}...
            </div>
            <div class="col-span-2 rounded bg-slate-900 p-2 break-all">
              <span class="text-slate-400">WebGL:</span>
              {{ fingerprint.webgl.vendor }} / {{ fingerprint.webgl.renderer }}
              <span v-if="fingerprint.webgl.masked" class="ml-1 text-rose-400">(MASKED)</span>
            </div>
            <div class="rounded bg-slate-900 p-2">
              <span class="text-slate-400">Fonts:</span> {{ fingerprint.font_count }} 个
            </div>
            <div class="rounded bg-slate-900 p-2">
              <span class="text-slate-400">webdriver / cdp:</span>
              <span :class="fingerprint.automation_flags.webdriver ? 'text-rose-400 font-bold' : 'text-emerald-300'">
                {{ fingerprint.automation_flags.webdriver }}
              </span>
              / {{ fingerprint.automation_flags.cdp_console_probe }}
            </div>
          </div>
        </div>
      </div>
    </aside>
  </div>
</template>
