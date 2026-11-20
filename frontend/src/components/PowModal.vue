<script setup lang="ts">
import { ref, watch } from 'vue'
import { sha256Hex } from '@/crypto/signature'
import { buildLabHeaders, setPowToken } from '@/services/labState'
import type { PowChallenge } from '@/types/lab'

const props = defineProps<{
  visible: boolean
  challenge: PowChallenge | null
}>()

const emit = defineEmits<{
  close: []
  solved: [token: string]
}>()

const solving = ref(false)
const attempts = ref(0)
const elapsedMs = ref(0)
const hashRate = ref(0)
const foundHash = ref('')
const errorMsg = ref('')

watch(
  () => props.visible,
  (val) => {
    if (val) {
      attempts.value = 0
      elapsedMs.value = 0
      hashRate.value = 0
      foundHash.value = ''
      errorMsg.value = ''
    }
  }
)

async function solvePow(): Promise<void> {
  if (!props.challenge || solving.value) return
  solving.value = true
  errorMsg.value = ''
  attempts.value = 0

  const prefix = '0'.repeat(props.challenge.difficulty)
  const start = performance.now()
  let nonce = 0

  try {
    while (true) {
      // 每批计算 250 次后让出事件循环，保持界面与统计实时刷新
      for (let i = 0; i < 250; i++) {
        const candidate = String(nonce)
        const digest = await sha256Hex(`${props.challenge.data}:${candidate}`)
        attempts.value = nonce + 1
        if (digest.startsWith(prefix)) {
          const dt = Math.max(1, Math.round(performance.now() - start))
          elapsedMs.value = dt
          hashRate.value = Math.round((attempts.value / dt) * 1000)
          foundHash.value = digest

          const resp = await fetch('/api/v1/challenge/pow', {
            method: 'POST',
            headers: buildLabHeaders({ 'Content-Type': 'application/json' }),
            body: JSON.stringify({ data: props.challenge.data, answer: candidate }),
          })
          const body = (await resp.json()) as { token?: string; message?: string }
          if (!resp.ok || !body.token) {
            errorMsg.value = body.message || 'PoW 服务端核验失败'
            solving.value = false
            return
          }
          setPowToken(body.token)
          solving.value = false
          emit('solved', body.token)
          return
        }
        nonce++
      }
      const dt = Math.max(1, Math.round(performance.now() - start))
      elapsedMs.value = dt
      hashRate.value = Math.round((attempts.value / dt) * 1000)
      await new Promise((r) => setTimeout(r, 0))
    }
  } catch (err) {
    errorMsg.value = err instanceof Error ? err.message : '算力求解异常'
    solving.value = false
  }
}
</script>

<template>
  <div
    v-if="visible && challenge"
    class="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm"
  >
    <div class="w-full max-w-lg rounded-2xl border border-cyan-500/40 bg-[#0d1422] p-6 shadow-2xl">
      <div class="flex items-start justify-between">
        <div>
          <span class="rounded bg-cyan-500/15 px-2 py-0.5 font-mono text-[11px] text-cyan-300">
            POW_REQUIRED · 40–69 灰区挑战
          </span>
          <h3 class="mt-2 text-lg font-bold text-white">工作量证明（PoW）算力挑战</h3>
        </div>
        <button class="text-slate-400 hover:text-white" @click="emit('close')">✕</button>
      </div>

      <p class="mt-2 text-xs text-slate-300">
        当前会话风险分处于 40–69 灰区。请寻找满足
        <code class="rounded bg-slate-900 px-1.5 py-0.5 text-emerald-300">
          SHA-256(data + ":" + nonce)
        </code>
        以 <strong class="text-cyan-300">{{ challenge.difficulty }} 个 0</strong> 开头的 nonce，以换取 10 分钟有效的
        <code class="text-cyan-300">X-PoW-Token</code>。
      </p>

      <div class="mt-4 space-y-2 rounded-xl border border-slate-800 bg-slate-950/80 p-3 font-mono text-xs">
        <div class="flex justify-between">
          <span class="text-slate-400">Challenge Data:</span>
          <span class="text-slate-200">{{ challenge.data }}</span>
        </div>
        <div class="flex justify-between">
          <span class="text-slate-400">尝试次数 / 算力:</span>
          <span class="text-emerald-300">{{ attempts }} 次 · {{ hashRate }} H/s</span>
        </div>
        <div class="flex justify-between">
          <span class="text-slate-400">耗时:</span>
          <span class="text-slate-200">{{ elapsedMs }} ms</span>
        </div>
        <div v-if="foundHash" class="break-all text-[11px] text-emerald-400">
          命中哈希: {{ foundHash }}
        </div>
      </div>

      <div v-if="errorMsg" class="mt-3 rounded-lg border border-rose-500/40 bg-rose-500/10 p-2 text-xs text-rose-300">
        {{ errorMsg }}
      </div>

      <div class="mt-5 flex justify-end gap-2">
        <button
          class="rounded-lg border border-slate-700 px-4 py-2 text-xs text-slate-300 hover:bg-slate-800"
          @click="emit('close')"
        >
          取消
        </button>
        <button
          :disabled="solving"
          class="rounded-lg bg-cyan-500 px-4 py-2 font-mono text-xs font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-50"
          @click="solvePow"
        >
          {{ solving ? '正在计算 SHA-256...' : '开始客户端 PoW 求解并重放请求' }}
        </button>
      </div>
    </div>
  </div>
</template>
