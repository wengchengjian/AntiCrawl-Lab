<script setup lang="ts">
import { ref } from 'vue'
import { buildLabHeaders } from '@/services/labState'

const trapField = ref('')
const emailTrap = ref('')
const statusMsg = ref('')

async function submitHiddenTrapForm(): Promise<void> {
  const resp = await fetch('/api/v1/trap/form', {
    method: 'POST',
    headers: buildLabHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      honeypot_field: trapField.value,
      email_trap: emailTrap.value,
      note: 'human-visible-submit',
    }),
  })
  const data = (await resp.json()) as { message?: string; risk_reason?: string }
  statusMsg.value = `${resp.status} ${data.risk_reason || 'OK'}: ${data.message || ''}`
}
</script>

<template>
  <!-- 8.4 四形态蜜罐矩阵：真实可见 UI 完全无感，专为诱捕 DOM 解析 / 可见性绕过 / 自动填表 / CSS 解析爬虫 -->
  <section class="relative overflow-hidden rounded-xl border border-dashed border-slate-800 bg-slate-950/60 p-4 text-xs text-slate-400">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <div>
        <span class="font-mono font-semibold text-amber-400">[8.4 蜜罐诱捕矩阵已就绪]</span>
        <span class="ml-2 text-slate-400">页面已静默埋入 4 类陷阱节点（仅自动化解析器会误触）：</span>
      </div>
      <div class="flex flex-wrap gap-1.5 font-mono text-[11px]">
        <span class="rounded bg-slate-900 px-2 py-0.5 text-slate-300">1. display:none 链接</span>
        <span class="rounded bg-slate-900 px-2 py-0.5 text-slate-300">2. opacity:0 视口外链接</span>
        <span class="rounded bg-slate-900 px-2 py-0.5 text-slate-300">3. 隐藏表单诱饵域</span>
        <span class="rounded bg-slate-900 px-2 py-0.5 text-slate-300">4. CSS ::before 伪元素链接</span>
      </div>
    </div>

    <!-- 形态 1：display:none 隐藏链接（诱捕 DOM 全量解析型爬虫） -->
    <a href="/api/v1/trap" style="display: none" aria-hidden="true" tabindex="-1">
      /api/v1/trap?source=hidden_dom
    </a>

    <!-- 形态 2：opacity:0 且定位到视口外（诱捕绕过 display:none 但忽略视口边界检查的爬虫） -->
    <a
      href="/api/v1/trap"
      style="opacity: 0; position: fixed; left: -9999px; top: -9999px; width: 1px; height: 1px"
      aria-hidden="true"
      tabindex="-1"
    >
      Export Full Price Database
    </a>

    <!-- 形态 3：隐藏表单字段（若自动化工具自动填充所有 input 即触发封禁） -->
    <form class="mt-2 flex flex-wrap items-center gap-2" @submit.prevent="submitHiddenTrapForm">
      <div style="display: none" aria-hidden="true">
        <label>Leave Empty (Honeypot)</label>
        <input v-model="trapField" name="honeypot_field" type="text" autocomplete="off" tabindex="-1" />
        <input v-model="emailTrap" name="email_trap" type="email" autocomplete="off" tabindex="-1" />
      </div>
      <button
        type="submit"
        class="rounded border border-slate-700 bg-slate-900 px-2.5 py-1 font-mono text-[11px] text-slate-300 hover:border-emerald-500/60 hover:text-emerald-300"
      >
        测试正常提交（隐藏域为空）
      </button>
      <span v-if="statusMsg" class="font-mono text-[11px] text-cyan-300">{{ statusMsg }}</span>
    </form>

    <!-- 形态 4：纯 CSS ::before 生成 trap 路径文本（诱捕 CSS 规则/正则提取型采集器） -->
    <div class="acl-css-trap mt-1 text-[11px] text-slate-600" aria-hidden="true"></div>
  </section>
</template>

<style scoped>
.acl-css-trap::before {
  content: '/api/v1/trap';
  position: absolute;
  left: -9999px;
  opacity: 0;
  pointer-events: none;
}
</style>
