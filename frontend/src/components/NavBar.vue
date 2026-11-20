<script setup lang="ts">
import { useRoute } from 'vue-router'
import { PRESET_SIMULATED_IPS, labState, setSimulatedIp } from '@/services/labState'

const route = useRoute()

const navItems = [
  { path: '/', label: '关卡导航' },
  { path: '/probes', label: '指纹与行为探针' },
  { path: '/bot-check', label: '机器人检测' },
  { path: '/ip-intel', label: 'IP 与地域穿透' },
  { path: '/price', label: '动态字体价格页' },
  { path: '/dashboard', label: '实时风控仪表盘' },
]

function onIpChange(ev: Event): void {
  const target = ev.target as HTMLSelectElement
  setSimulatedIp(target.value)
}
</script>

<template>
  <header class="sticky top-0 z-40 border-b border-slate-800/90 bg-[#060a12]/90 backdrop-blur">
    <div class="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3">
      <div class="flex items-center gap-6">
        <router-link to="/" class="flex items-center gap-2.5">
          <div class="flex h-8 w-8 items-center justify-center rounded-lg border border-emerald-400/40 bg-emerald-500/10 font-mono text-sm font-bold text-emerald-300">
            AC
          </div>
          <div>
            <div class="font-mono text-sm font-bold tracking-wider text-slate-100">
              AntiCrawl <span class="text-emerald-400">Lab</span>
            </div>
            <div class="text-[10px] text-slate-400">本地安全教学与反爬对抗靶场</div>
          </div>
        </router-link>

        <nav class="flex flex-wrap items-center gap-1">
          <router-link
            v-for="item in navItems"
            :key="item.path"
            :to="item.path"
            class="rounded-lg px-3 py-1.5 text-xs font-medium transition"
            :class="
              route.path === item.path
                ? 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/40'
                : 'text-slate-300 hover:bg-slate-800/70 hover:text-white'
            "
          >
            {{ item.label }}
          </router-link>
        </nav>
      </div>

      <div class="flex flex-wrap items-center gap-2.5 text-xs">
        <span
          v-if="labState.lastRateLimit"
          class="rounded-md border border-indigo-500/40 bg-indigo-500/10 px-2 py-1 font-mono text-[11px] text-indigo-300"
          :title="`Request ID: ${labState.lastRateLimit.requestId}`"
        >
          Bucket[{{ labState.lastRateLimit.tier }}] {{ labState.lastRateLimit.remaining }}/{{ labState.lastRateLimit.burst }}
        </span>
        <span
          class="rounded-md border px-2 py-1 font-mono text-[11px]"
          :class="
            labState.redisMode === 'real'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
              : 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300'
          "
        >
          Cache: {{ labState.redisMode }}
        </span>
        <span
          class="rounded-md border px-2 py-1 font-mono text-[11px]"
          :class="
            labState.labMode
              ? 'border-amber-500/40 bg-amber-500/10 text-amber-300'
              : 'border-rose-500/40 bg-rose-500/10 text-rose-300'
          "
        >
          LAB_MODE={{ labState.labMode ? '1' : '0' }}
        </span>

        <div v-if="labState.labMode" class="flex items-center gap-1.5">
          <span class="text-[11px] text-slate-400">模拟IP:</span>
          <select
            :value="labState.simulatedIp"
            class="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-[11px] text-slate-200 focus:border-emerald-400 focus:outline-none"
            @change="onIpChange"
          >
            <option v-for="opt in PRESET_SIMULATED_IPS" :key="opt.label" :value="opt.ip">
              {{ opt.label }}
            </option>
          </select>
        </div>
      </div>
    </div>
  </header>
</template>
