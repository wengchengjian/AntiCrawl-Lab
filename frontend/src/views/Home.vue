<script setup lang="ts">
import { onMounted, ref } from 'vue'
import HoneypotMatrix from '@/components/HoneypotMatrix.vue'
import { buildLabHeaders, labState, recordRouteVisit } from '@/services/labState'

interface DrillResult {
  title: string
  status: number
  summary: string
  raw: string
}

const drillResult = ref<DrillResult | null>(null)
const drillLoading = ref(false)

onMounted(() => {
  recordRouteVisit('/')
})

const levels = [
  {
    level: 'LEVEL 01',
    title: '网络与协议层检测',
    route: '/dashboard',
    accent: 'border-emerald-500/40 text-emerald-300',
    desc: '滑动窗口限流（IP & 指纹双维度）、定频轮询 CV 检测、Header 条件规则、JA4 TLS 指纹与 4 形态蜜罐矩阵。',
  },
  {
    level: 'LEVEL 02',
    title: '浏览器指纹与环境检测',
    route: '/probes',
    accent: 'border-cyan-500/40 text-cyan-300',
    desc: 'Canvas 双渲染噪点检测、WebGL 软渲染/掩码、OfflineAudio、7 维一致性矩阵、Web Worker 跨线程与 Math 引擎指纹。',
  },
  {
    level: 'LEVEL 03',
    title: '自动化与行为动力学',
    route: '/probes',
    accent: 'border-amber-500/40 text-amber-300',
    desc: 'webdriver/getter 篡改、$cdc_/CDP Runtime.enable、Iframe 跨 Realm 一致性、轨迹直线度、isTrusted 与访问顺序图。',
  },
  {
    level: 'LEVEL 04',
    title: '前端防逆向与业务混淆',
    route: '/price',
    accent: 'border-indigo-500/40 text-indigo-300',
    desc: '12 段异或签名 + Nonce 防重放、8 变体动态字体（控制点微扰）、Shadow DOM、Canvas/CSS-Order、PoW 与诱饵投毒。',
  },
]

async function runBurstRateLimitDrill(): Promise<void> {
  drillLoading.value = true
  const testIp = '116.228.99.1'
  try {
    // 先清理测试 IP 状态，确保连续 11 次测试可复现
    await fetch('/api/v1/admin/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: testIp }),
    })

    const statuses: number[] = []
    let lastBody = ''
    for (let i = 0; i < 11; i++) {
      const r = await fetch('/api/v1/font/session', {
        headers: buildLabHeaders({ 'X-Simulated-IP': testIp }),
      })
      statuses.push(r.status)
      if (r.status === 429) {
        lastBody = await r.text()
      }
    }
    drillResult.value = {
      title: '1 秒内 11 连打滑动窗口限流演练（IP=116.228.99.1）',
      status: statuses[10] ?? 0,
      summary: `前 10 次状态: [${statuses.slice(0, 10).join(', ')}]，第 11 次状态: ${statuses[10]}`,
      raw: lastBody || '未触发 429（请检查 RATE_LIMIT_QPS 配置）',
    }
  } finally {
    drillLoading.value = false
  }
}

async function runDatacenterIpDrill(): Promise<void> {
  drillLoading.value = true
  try {
    const r = await fetch('/api/v1/challenge/pow', {
      method: 'POST',
      headers: buildLabHeaders({
        'X-Simulated-IP': '52.95.10.20',
        'X-JA4': 't13d1516h2_8daaf6152771_b0da82dd1658',
      }),
    })
    const body = await r.text()
    drillResult.value = {
      title: '美国 AWS 机房 IP + python-requests JA4 联合探针演练',
      status: r.status,
      summary: '已触发 DATACENTER_IP (+25) 与 JA4 矛盾 (+20)，请前往仪表盘查看详情',
      raw: body,
    }
  } finally {
    drillLoading.value = false
  }
}

async function runTrapAndUnbanDrill(): Promise<void> {
  drillLoading.value = true
  const trapIp = '114.242.77.77'
  try {
    const r1 = await fetch('/api/v1/trap', {
      headers: buildLabHeaders({ 'X-Simulated-IP': trapIp }),
    })
    const b1 = await r1.text()
    const r2 = await fetch('/api/v1/font/session', {
      headers: buildLabHeaders({ 'X-Simulated-IP': trapIp }),
    })
    const r3 = await fetch('/api/v1/admin/unban', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: trapIp, operator: 'home_drill' }),
    })
    const b3 = await r3.text()
    drillResult.value = {
      title: `蜜罐触发 → 封禁拦截 → 一键解封全链路（IP=${trapIp}）`,
      status: r1.status,
      summary: `踩蜜罐=${r1.status} -> 后续业务请求=${r2.status} -> 解封结果=${r3.status}`,
      raw: `Trap 响应: ${b1}\nUnban 响应: ${b3}`,
    }
  } finally {
    drillLoading.value = false
  }
}
</script>

<template>
  <div class="mx-auto max-w-7xl space-y-6 px-4 py-6">
    <!-- 顶部横幅 -->
    <section class="rounded-2xl border border-slate-800 bg-gradient-to-br from-[#0d1422] via-[#0a1220] to-[#081b1a] p-6">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div class="max-w-3xl">
          <div class="inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 font-mono text-[11px] text-emerald-300">
            ● LOCAL SECURITY LAB · 127.0.0.1 ISOLATED
          </div>
          <h1 class="mt-3 text-2xl font-bold tracking-tight text-white sm:text-3xl">
            AntiCrawl Lab · Web 反爬攻防实验室
          </h1>
          <p class="mt-2 text-sm text-slate-300">
            面向安全研究员与风控工程师的本地教学靶场：集成 4 层攻防关卡、8 步风控中间件流水线、
            16+ 现代指纹与行为对抗技术，以及基于 SSE 的毫秒级实时风控仪表盘。
          </p>
        </div>

        <div class="grid grid-cols-2 gap-2 font-mono text-xs">
          <div class="rounded-xl border border-slate-800 bg-slate-950/70 px-3 py-2">
            <div class="text-[10px] text-slate-400">缓存降级模式</div>
            <div class="mt-0.5 font-bold text-cyan-300">{{ labState.redisMode }}</div>
          </div>
          <div class="rounded-xl border border-slate-800 bg-slate-950/70 px-3 py-2">
            <div class="text-[10px] text-slate-400">单 IP 限流阈值</div>
            <div class="mt-0.5 font-bold text-emerald-300">
              {{ labState.rulesMeta?.runtime_limits.rate_limit_qps ?? 10 }} QPS
            </div>
          </div>
          <div class="rounded-xl border border-slate-800 bg-slate-950/70 px-3 py-2">
            <div class="text-[10px] text-slate-400">PoW 挑战难度</div>
            <div class="mt-0.5 font-bold text-amber-300">
              {{ labState.rulesMeta?.runtime_limits.pow_difficulty ?? 4 }} 前导零
            </div>
          </div>
          <div class="rounded-xl border border-slate-800 bg-slate-950/70 px-3 py-2">
            <div class="text-[10px] text-slate-400">当前 Session</div>
            <div class="mt-0.5 max-w-[120px] truncate text-slate-200">{{ labState.sessionId }}</div>
          </div>
        </div>
      </div>
    </section>

    <!-- 四大关卡导航 -->
    <section class="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <router-link
        v-for="lv in levels"
        :key="lv.level"
        :to="lv.route"
        class="group flex flex-col justify-between rounded-2xl border border-slate-800 bg-[#0d1422] p-5 transition hover:-translate-y-0.5 hover:border-emerald-500/50"
      >
        <div>
          <span class="inline-block rounded border px-2 py-0.5 font-mono text-[10px] font-bold" :class="lv.accent">
            {{ lv.level }}
          </span>
          <h2 class="mt-3 text-base font-bold text-white group-hover:text-emerald-300">
            {{ lv.title }}
          </h2>
          <p class="mt-2 text-xs leading-relaxed text-slate-400">{{ lv.desc }}</p>
        </div>
        <div class="mt-4 font-mono text-xs text-emerald-400">进入演练 →</div>
      </router-link>
    </section>

    <!-- 专项扩展：全维度机器人检测台 & 商业防线实验室入口 -->
    <section class="grid gap-4 md:grid-cols-2">
      <router-link
        to="/bot-check"
        class="flex items-center justify-between rounded-2xl border border-emerald-500/30 bg-gradient-to-r from-[#0d1422] to-[#081c19] p-5 transition hover:border-emerald-400/70"
      >
        <div>
          <span class="rounded bg-emerald-500/15 px-2 py-0.5 font-mono text-[10px] font-bold text-emerald-300">
            NEW · 机器人检测与置信分引擎
          </span>
          <h3 class="mt-2 text-base font-bold text-white">
            BrowserScan × BrowserLeaks × Sannysoft 体检台
          </h3>
          <p class="mt-1 text-xs text-slate-400">
            30+ 项工业级自动化与隐私泄露指标审计，实时输出 Bot/Human 置信分、判定结论与归因权重（API: <code class="text-cyan-300">/api/v1/bot/check</code>）。
          </p>
        </div>
        <span class="ml-4 shrink-0 font-mono text-sm text-emerald-300">进入检测 →</span>
      </router-link>

      <router-link
        to="/price"
        class="flex items-center justify-between rounded-2xl border border-indigo-500/30 bg-gradient-to-r from-[#0d1422] to-[#11152c] p-5 transition hover:border-indigo-400/70"
      >
        <div>
          <span class="rounded bg-indigo-500/15 px-2 py-0.5 font-mono text-[10px] font-bold text-indigo-300">
            NEW · 商业站点实战防线复刻
          </span>
          <h3 class="mt-2 text-base font-bold text-white">
            200 HTML 动态 JS 挑战 + 匿名浏览配额 + 分级令牌桶
          </h3>
          <p class="mt-1 text-xs text-slate-400">
            复刻透明 JS 挑战（<code class="text-amber-300">timestamp__1366</code>）、深度翻页登录拦截与 <code class="text-cyan-300">X-RateLimit-*</code> 网关限流及授时校准。
          </p>
        </div>
        <span class="ml-4 shrink-0 font-mono text-sm text-indigo-300">进入实战 →</span>
      </router-link>
    </section>

    <!-- 本地红队快速演练台（仅请求本机 /api/v1/*） -->
    <section class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 class="text-base font-bold text-white">模块一 · 本地快速攻防演练台</h2>
          <p class="text-xs text-slate-400">
            利用 LAB_MODE=1 的 <code class="text-amber-300">X-Simulated-IP</code> 与 <code class="text-amber-300">X-JA4</code> 请求头在本机直接复现限流、机房识别与蜜罐封禁全链路。
          </p>
        </div>
        <router-link
          to="/dashboard"
          class="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 font-mono text-xs text-cyan-300 hover:bg-cyan-500/20"
        >
          打开实时仪表盘观测 →
        </router-link>
      </div>

      <div class="mt-4 flex flex-wrap gap-2.5">
        <button
          :disabled="drillLoading"
          class="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3.5 py-2 font-mono text-xs text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-50"
          @click="runBurstRateLimitDrill"
        >
          1. 触发 1 秒 11 连打限流 (429)
        </button>
        <button
          :disabled="drillLoading"
          class="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3.5 py-2 font-mono text-xs text-amber-300 hover:bg-amber-500/20 disabled:opacity-50"
          @click="runDatacenterIpDrill"
        >
          2. 模拟美国 AWS 机房 + JA4 异常
        </button>
        <button
          :disabled="drillLoading"
          class="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3.5 py-2 font-mono text-xs text-rose-300 hover:bg-rose-500/20 disabled:opacity-50"
          @click="runTrapAndUnbanDrill"
        >
          3. 踩蜜罐封禁 → 拦截 → 解封闭环
        </button>
      </div>

      <div v-if="drillResult" class="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-xs">
        <div class="flex items-center justify-between text-emerald-300">
          <span>{{ drillResult.title }}</span>
          <span>HTTP {{ drillResult.status }}</span>
        </div>
        <div class="mt-1.5 text-slate-200">{{ drillResult.summary }}</div>
        <pre class="mt-2 overflow-x-auto rounded bg-slate-900/90 p-2.5 text-[11px] text-slate-400">{{ drillResult.raw }}</pre>
      </div>
    </section>

    <!-- 8 步风控流水线一览（来自后端 rules_meta） -->
    <section v-if="labState.rulesMeta?.pipeline_steps" class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5">
      <h2 class="text-base font-bold text-white">全局风控中间件 8 步流水线（由后端单源契约下发）</h2>
      <div class="mt-4 grid gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
        <div
          v-for="st in labState.rulesMeta.pipeline_steps"
          :key="st.step"
          class="rounded-xl border border-slate-800/80 bg-slate-950/70 p-3"
        >
          <div class="font-mono text-[11px] font-bold text-cyan-400">STEP {{ st.step }} · {{ st.name }}</div>
          <div class="mt-1 text-xs text-slate-400">{{ st.desc }}</div>
        </div>
      </div>
    </section>

    <!-- 8.4 蜜罐矩阵 -->
    <HoneypotMatrix />
  </div>
</template>
