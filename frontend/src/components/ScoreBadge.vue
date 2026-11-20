<script setup lang="ts">
import { computed } from 'vue'
import type { RiskAction } from '@/types/lab'

const props = defineProps<{
  action: RiskAction | string
  score?: number
}>()

const badgeClass = computed(() => {
  switch (props.action) {
    case 'pass':
      return 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
    case 'warn':
      return 'border-amber-500/40 bg-amber-500/15 text-amber-300'
    case 'block':
      return 'border-rose-500/40 bg-rose-500/15 text-rose-300'
    case 'challenge':
      return 'border-cyan-500/40 bg-cyan-500/15 text-cyan-300'
    default:
      return 'border-slate-600 bg-slate-800 text-slate-300'
  }
})

const actionLabel = computed(() => {
  switch (props.action) {
    case 'pass':
      return 'PASS 放行'
    case 'warn':
      return 'WARN 警告'
    case 'block':
      return 'BLOCK 拦截'
    case 'challenge':
      return 'CHALLENGE PoW'
    default:
      return props.action.toUpperCase()
  }
})
</script>

<template>
  <span
    class="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[11px] font-semibold"
    :class="badgeClass"
  >
    <span>{{ actionLabel }}</span>
    <span v-if="score !== undefined" class="opacity-85">{{ score }}</span>
  </span>
</template>
