<script setup lang="ts">
import { onMounted, ref } from 'vue'
import HoneypotMatrix from '@/components/HoneypotMatrix.vue'
import PowModal from '@/components/PowModal.vue'
import {
  ensureSessionFontLoaded,
  registerPriceTagElement,
  type PriceRenderMode,
} from '@/components/PriceTagElement'
import { sha256Hex, signRequest, type SignedHeaders } from '@/crypto/signature'
import {
  buildLabHeaders,
  captureRateLimitHeaders,
  labState,
  recordRouteVisit,
  setLabAuth,
  syncServerClock,
} from '@/services/labState'
import type { BrowseQuotaInfo, PowChallenge, ProductItem } from '@/types/lab'

const renderMode = ref<PriceRenderMode>('font')
const fontSeed = ref('loading...')
const fontVariant = ref('-')
const products = ref<ProductItem[]>([])
const decoyHint = ref('')
const loading = ref(false)
const actionLog = ref('')
const lastSignedHeaders = ref<SignedHeaders | null>(null)

const currentPage = ref(1)
const totalPages = ref(5)
const browseQuota = ref<BrowseQuotaInfo | null>(null)
const pendingAction = ref<'price' | 'page'>('price')

const selectedPriceResult = ref<Record<string, unknown> | null>(null)
const pendingProductId = ref<number>(1)
const powModalVisible = ref(false)
const powChallenge = ref<PowChallenge | null>(null)

// WAF 200 HTML/JS 动态挑战演练状态
const wafChallengeHtml = ref('')
const wafJsonResult = ref<Record<string, unknown> | null>(null)
const wafLoading = ref(false)
const gatewayTestLog = ref('')

async function refreshBrowseQuota(): Promise<void> {
  const resp = await fetch('/api/v1/browse/limit', {
    headers: buildLabHeaders(),
  })
  captureRateLimitHeaders(resp)
  if (resp.ok) {
    browseQuota.value = (await resp.json()) as BrowseQuotaInfo
  }
}

async function loadProducts(includeVisitOrigin = true, targetPage = currentPage.value): Promise<void> {
  loading.value = true
  actionLog.value = ''
  try {
    const fontInfo = await ensureSessionFontLoaded(labState.sessionId, labState.simulatedIp)
    fontSeed.value = fontInfo.seed
    fontVariant.value = fontInfo.variant

    const path = '/api/v1/products'
    const sigHeaders = await signRequest('GET', path, undefined, undefined, labState.clockOffsetMs)
    lastSignedHeaders.value = sigHeaders

    const headers = buildLabHeaders({
      ...sigHeaders,
      ...(includeVisitOrigin && labState.visitPath.includes('/') ? { 'X-Visit-Origin': '/' } : {}),
    })

    const url = targetPage > 1 ? `${path}?page=${targetPage}&size=6` : path
    const resp = await fetch(url, { headers })
    captureRateLimitHeaders(resp)
    const data = (await resp.json()) as {
      items?: ProductItem[]
      decoy_hint?: string
      font_seed?: string
      variant?: number
      page?: number
      total_pages?: number
      browse_quota?: BrowseQuotaInfo
      message?: string
      risk_reason?: string
      detail_code?: string
      challenge?: PowChallenge
    }

    if (data.browse_quota) {
      browseQuota.value = data.browse_quota
    }

    if (resp.status === 403 && data.risk_reason === 'POW_REQUIRED' && data.challenge) {
      pendingAction.value = 'page'
      currentPage.value = targetPage
      powChallenge.value = data.challenge
      powModalVisible.value = true
      actionLog.value = `HTTP 403 [${data.detail_code || data.risk_reason}]: ${data.message || ''}`
      return
    }

    if (!resp.ok) {
      actionLog.value = `HTTP ${resp.status} [${data.risk_reason || 'ERROR'}]: ${data.message || ''}`
      products.value = []
      return
    }

    currentPage.value = data.page || targetPage
    totalPages.value = data.total_pages || 5
    products.value = data.items || []
    decoyHint.value = data.decoy_hint || ''
    recordRouteVisit(path)
    actionLog.value = `第 ${currentPage.value} 页拉取 ${products.value.length} 个商品（variant=${data.variant}, seed=${data.font_seed}${decoyHint.value ? ', 已触发诱饵' : ''}）`
  } finally {
    loading.value = false
  }
}

async function switchPage(page: number): Promise<void> {
  await loadProducts(true, page)
}

async function toggleMockLogin(): Promise<void> {
  if (labState.labAuthToken) {
    await fetch('/api/v1/browse/mock-logout', {
      method: 'POST',
      headers: buildLabHeaders(),
    })
    setLabAuth('', '')
    actionLog.value = '已退出模拟登录，恢复匿名浏览配额限制（仅免费前 2 页）'
  } else {
    const resp = await fetch('/api/v1/browse/mock-login', {
      method: 'POST',
      headers: buildLabHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ username: 'sec_researcher' }),
    })
    const data = (await resp.json()) as { token: string; username: string }
    setLabAuth(data.token, data.username)
    actionLog.value = `已模拟登录为 ${data.username}（已携带 X-Lab-Auth 解锁第 3–5 页）`
  }
  await refreshBrowseQuota()
}

async function queryProductPrice(productId: number): Promise<void> {
  pendingAction.value = 'price'
  pendingProductId.value = productId
  const path = `/api/v1/products/${productId}/price`
  const sigHeaders = await signRequest('GET', path, undefined, undefined, labState.clockOffsetMs)
  const resp = await fetch(path, {
    headers: buildLabHeaders({ ...sigHeaders }),
  })
  captureRateLimitHeaders(resp)
  const data = (await resp.json()) as Record<string, unknown>

  if (resp.status === 403 && data.risk_reason === 'POW_REQUIRED' && data.challenge) {
    powChallenge.value = data.challenge as PowChallenge
    powModalVisible.value = true
    actionLog.value = `触发 403 POW_REQUIRED（风险分 ${data.risk_score}），请在弹窗完成 PoW 算力挑战`
    return
  }

  selectedPriceResult.value = data
  actionLog.value = resp.ok
    ? `已获取商品 #${productId} 单品底价响应（pow_verified=${data.pow_verified}, decoy=${data.decoy_served}）`
    : `HTTP ${resp.status} [${data.risk_reason}]: ${data.message}`
}

async function testUnsignedRequest(): Promise<void> {
  const resp = await fetch('/api/v1/products', { headers: buildLabHeaders() })
  captureRateLimitHeaders(resp)
  const data = await resp.text()
  actionLog.value = `无签名直连测试 -> HTTP ${resp.status}: ${data}`
}

async function testNonceReplay(): Promise<void> {
  if (!lastSignedHeaders.value) {
    await loadProducts(true, 1)
  }
  if (!lastSignedHeaders.value) return
  const resp = await fetch('/api/v1/products', {
    headers: buildLabHeaders({ ...lastSignedHeaders.value }),
  })
  captureRateLimitHeaders(resp)
  const data = await resp.text()
  actionLog.value = `重放上次 X-Signature + X-Nonce -> HTTP ${resp.status}: ${data}`
}

async function testWafNakedRequest(): Promise<void> {
  wafLoading.value = true
  wafJsonResult.value = null
  try {
    const resp = await fetch('/api/v1/waf/protected-feed', {
      headers: buildLabHeaders(),
    })
    captureRateLimitHeaders(resp)
    const ct = resp.headers.get('content-type') || ''
    const text = await resp.text()
    if (ct.includes('text/html')) {
      wafChallengeHtml.value = text
    } else {
      wafJsonResult.value = JSON.parse(text) as Record<string, unknown>
    }
  } finally {
    wafLoading.value = false
  }
}

async function solveWafChallengeAndRetry(): Promise<void> {
  wafLoading.value = true
  try {
    // 若尚未获取挑战页则先请求一次获取混淆脚本
    if (!wafChallengeHtml.value) {
      await testWafNakedRequest()
    }
    const html = wafChallengeHtml.value
    // 解析挑战 HTML 中嵌入的异或数组和 ts，在客户端沙盒还原令牌
    const argMatch = html.match(/\}\)\((\d+),(\[[^\]]+\]),(\[[^\]]+\]),(\[[^\]]+\])\)/)
    const tsMatch = html.match(/ts='(\d+)'/)
    if (!argMatch || !tsMatch) {
      gatewayTestLog.value = '未能从挑战 HTML 中解析动态参数'
      return
    }
    const xorKey = Number(argMatch[1])
    const decArr = (arrJson: string) =>
      (JSON.parse(arrJson) as number[]).map((c) => String.fromCharCode(c ^ xorKey)).join('')

    const nid = decArr(argMatch[2]!)
    const salt = decArr(argMatch[3]!)
    const paramName = decArr(argMatch[4]!)
    const ts = tsMatch[1]!
    const envTag = navigator.webdriver === true ? 'wd1' : 'dom1'
    const digest = (await sha256Hex(`${nid}:${salt}:${ts}:${envTag}`)).slice(0, 24)
    const token = `${nid}-${ts}-${digest}-${envTag}`

    const resp = await fetch(`/api/v1/waf/protected-feed?${encodeURIComponent(paramName)}=${encodeURIComponent(token)}`, {
      headers: buildLabHeaders(),
    })
    captureRateLimitHeaders(resp)
    wafJsonResult.value = (await resp.json()) as Record<string, unknown>
  } finally {
    wafLoading.value = false
  }
}

async function testClockDriftExpired(): Promise<void> {
  const path = '/api/v1/products'
  const driftedTs = String(Math.floor(Date.now() / 1000) + 300)
  const sig = await signRequest('GET', path, driftedTs)
  const resp = await fetch(path, {
    headers: buildLabHeaders({ ...sig }),
  })
  captureRateLimitHeaders(resp)
  gatewayTestLog.value = `模拟时钟漂移 +300s 签名请求 -> HTTP ${resp.status}: ${await resp.text()}`
}

async function testSensitiveBucketBurst(): Promise<void> {
  const statuses: number[] = []
  let hit429 = ''
  for (let i = 0; i < 10; i++) {
    const r = await fetch('/api/v1/challenge/pow', {
      method: 'POST',
      headers: buildLabHeaders(),
    })
    captureRateLimitHeaders(r)
    statuses.push(r.status)
    if (r.status === 429 && !hit429) {
      hit429 = await r.text()
    }
  }
  gatewayTestLog.value = `高敏桶 (burst=8) 连续 10 次状态: [${statuses.join(', ')}] ${hit429}`
}

async function onPowSolved(): Promise<void> {
  powModalVisible.value = false
  if (pendingAction.value === 'page') {
    await loadProducts(true, currentPage.value)
  } else {
    await queryProductPrice(pendingProductId.value)
  }
}

onMounted(() => {
  registerPriceTagElement()
  const urlMode = new URLSearchParams(window.location.search).get('render')
  if (urlMode === 'canvas' || urlMode === 'css-order' || urlMode === 'closed-shadow') {
    renderMode.value = urlMode
  }
  void syncServerClock()
  void refreshBrowseQuota()
  void loadProducts(true, 1)
})
</script>

<template>
  <div class="mx-auto max-w-7xl space-y-6 px-4 py-6">
    <!-- 顶部控制区 -->
    <section class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <span class="rounded bg-indigo-500/15 px-2 py-0.5 font-mono text-[10px] text-indigo-300">
            LEVEL 04 · 动态字体 + Shadow DOM + HMAC 签名 + PoW + 诱饵 + 商业级 WAF/限流/配额
          </span>
          <h1 class="mt-1.5 text-xl font-bold text-white">防逆向与业务数据混淆价格页</h1>
          <p class="mt-1 text-xs text-slate-400">
            价格文本在网络传输与 DOM 中均为 Unicode 私用区乱码（U+E000–U+E00A），并包裹于
            <code class="text-emerald-300">&lt;price-tag&gt;</code> Shadow Root 内。
          </p>
        </div>

        <div class="flex flex-wrap items-center gap-2 font-mono text-xs">
          <span class="rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-cyan-300">
            Font Variant #{{ fontVariant }} · Seed: {{ fontSeed }}
          </span>
          <a
            href="/ssr/price"
            target="_blank"
            class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-slate-300 hover:border-emerald-500/50"
          >
            打开后端 SSR /price 页 ↗
          </a>
        </div>
      </div>

      <!-- 渲染模式切换 & 红队签名演练 -->
      <div class="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 pt-4">
        <div class="flex flex-wrap items-center gap-1.5 text-xs">
          <span class="mr-1 text-slate-400">混淆渲染模式:</span>
          <button
            v-for="m in [
              { id: 'font', label: 'Shadow DOM + 动态字体' },
              { id: 'closed-shadow', label: 'Closed Shadow' },
              { id: 'canvas', label: 'Canvas 位图 (?render=canvas)' },
              { id: 'css-order', label: 'CSS Order 乱序' },
            ]"
            :key="m.id"
            class="rounded-lg border px-2.5 py-1 font-mono text-[11px] transition"
            :class="
              renderMode === m.id
                ? 'border-emerald-500/60 bg-emerald-500/15 text-emerald-300'
                : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
            "
            @click="renderMode = m.id as PriceRenderMode"
          >
            {{ m.label }}
          </button>
        </div>

        <div class="flex flex-wrap gap-2 font-mono text-xs">
          <button
            class="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-emerald-300 hover:bg-emerald-500/20"
            @click="loadProducts(true, currentPage)"
          >
            {{ loading ? '加载中...' : '刷新签名列表' }}
          </button>
          <button
            class="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-rose-300 hover:bg-rose-500/20"
            @click="testUnsignedRequest"
          >
            无签名直连 (401)
          </button>
          <button
            class="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-amber-300 hover:bg-amber-500/20"
            @click="testNonceReplay"
          >
            重放 Nonce (401)
          </button>
        </div>
      </div>

      <!-- 匿名浏览深度配额 & 分页控制（复刻 pxb7 queryBrowseLimit） -->
      <div class="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-slate-800 pt-4 text-xs">
        <div class="flex flex-wrap items-center gap-2">
          <span class="font-mono text-slate-400">翻页深度配额:</span>
          <button
            v-for="p in totalPages"
            :key="p"
            class="rounded-lg border px-2.5 py-1 font-mono transition"
            :class="
              currentPage === p
                ? 'border-cyan-500 bg-cyan-500/20 text-cyan-200'
                : p > (browseQuota?.max_anon_page ?? 2) && !labState.labAuthToken
                  ? 'border-amber-500/40 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20'
                  : 'border-slate-800 bg-slate-950 text-slate-300 hover:border-slate-600'
            "
            @click="switchPage(p)"
          >
            第 {{ p }} 页{{ p > (browseQuota?.max_anon_page ?? 2) && !labState.labAuthToken ? ' 🔒' : '' }}
          </button>
        </div>

        <div class="flex flex-wrap items-center gap-2 font-mono text-[11px]">
          <span v-if="browseQuota" class="text-slate-400">
            {{
              browseQuota.logged_in
                ? `已登录: ${browseQuota.username} (不限翻页)`
                : `匿名配额: 免费第1-${browseQuota.max_anon_page}页 · 剩余 ${browseQuota.remaining_views}/${browseQuota.max_anon_views} 次`
            }}
          </span>
          <button
            class="rounded-lg border px-2.5 py-1 transition"
            :class="
              labState.labAuthToken
                ? 'border-rose-500/40 bg-rose-500/10 text-rose-300'
                : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
            "
            @click="toggleMockLogin"
          >
            {{ labState.labAuthToken ? '退出模拟登录' : '模拟登录解锁深翻页' }}
          </button>
        </div>
      </div>

      <div v-if="actionLog" class="mt-3 rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 font-mono text-xs text-cyan-300">
        {{ actionLog }}
      </div>

      <div
        v-if="decoyHint"
        class="mt-3 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-300"
      >
        ⚠ <strong>诱饵警告：</strong>{{ decoyHint }}（当前卡片已展示掺假价格与假 SKU）。
      </div>
    </section>

    <!-- 商品卡片网格 -->
    <section class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
      <div
        v-for="item in products"
        :key="item.id"
        class="flex flex-col justify-between rounded-2xl border border-slate-800 bg-[#0d1422] p-5"
      >
        <div>
          <div class="flex items-center justify-between font-mono text-[11px]">
            <span class="rounded bg-slate-900 px-2 py-0.5 text-cyan-300">{{ item.category }}</span>
            <span :class="item.decoy ? 'text-amber-300' : 'text-slate-400'">{{ item.sku }}</span>
          </div>
          <h3 class="mt-3 text-base font-bold text-white">{{ item.name }}</h3>
          <p class="mt-1.5 text-xs text-slate-400">{{ item.spec }}</p>
        </div>

        <div class="mt-5 border-t border-slate-800/80 pt-4">
          <div class="flex items-end justify-between">
            <div>
              <div class="font-mono text-[10px] text-slate-500">
                原始响应 PUA: {{ item.price_pua }}
              </div>
              <price-tag
                class="mt-1"
                :price-pua="item.price_pua"
                :render-mode="renderMode"
                :decoy="String(item.decoy)"
                :seed="fontSeed"
              ></price-tag>
            </div>
            <button
              class="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 font-mono text-xs text-cyan-300 hover:bg-cyan-500/20"
              @click="queryProductPrice(item.id)"
            >
              单品底价 API
            </button>
          </div>
        </div>
      </div>
    </section>

    <!-- 单品底价接口返回结果 -->
    <section v-if="selectedPriceResult" class="rounded-2xl border border-slate-800 bg-[#0d1422] p-4 font-mono text-xs">
      <div class="text-emerald-300">单品价格接口（端点 5）响应载荷：</div>
      <pre class="mt-2 overflow-x-auto rounded-lg bg-slate-950 p-3 text-slate-300">{{
        JSON.stringify(selectedPriceResult, null, 2)
      }}</pre>
    </section>

    <!-- 商业防线扩展实验区：200 HTML JS 挑战 + 分级令牌桶 + 服务端授时 -->
    <section class="grid gap-4 lg:grid-cols-2">
      <!-- 实验 A：阿里云 ESA 同款透明 JS 挑战（timestamp__1366） -->
      <div class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5">
        <div class="flex items-center justify-between">
          <span class="rounded bg-amber-500/15 px-2 py-0.5 font-mono text-[10px] text-amber-300">
            ESA / WAF DYNAMIC TOKEN · timestamp__1366
          </span>
          <a
            href="/api/v1/waf/protected-feed"
            target="_blank"
            class="font-mono text-[11px] text-cyan-300 hover:underline"
          >
            新窗口体验自动跳转通关 ↗
          </a>
        </div>
        <h2 class="mt-2 text-base font-bold text-white">透明 200 HTML/JS 动态挑战页实验</h2>
        <p class="mt-1 text-xs text-slate-400">
          复刻真实商业站点 WAF：首次请求不返回 403，而是返回 200 HTML 混淆 JS 挑战；浏览器算完一次性
          <code class="text-amber-300">?timestamp__1366=...</code> 后才放行 JSON。
        </p>

        <div class="mt-3 flex flex-wrap gap-2 font-mono text-xs">
          <button
            :disabled="wafLoading"
            class="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-amber-300 hover:bg-amber-500/20"
            @click="testWafNakedRequest"
          >
            1. 裸请求 /waf/protected-feed (看 HTML 挑战)
          </button>
          <button
            :disabled="wafLoading"
            class="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-emerald-300 hover:bg-emerald-500/20"
            @click="solveWafChallengeAndRetry"
          >
            2. 解析 JS 计算 timestamp__1366 并解锁 JSON
          </button>
        </div>

        <pre
          v-if="wafJsonResult"
          class="mt-3 max-h-44 overflow-auto rounded-lg border border-emerald-500/30 bg-slate-950 p-3 font-mono text-[11px] text-emerald-300"
        >{{ JSON.stringify(wafJsonResult, null, 2) }}</pre>
        <pre
          v-else-if="wafChallengeHtml"
          class="mt-3 max-h-44 overflow-auto rounded-lg border border-amber-500/30 bg-slate-950 p-3 font-mono text-[11px] text-slate-400"
        >{{ wafChallengeHtml.slice(0, 900) }}...</pre>
      </div>

      <!-- 实验 B：分级令牌桶限流 + 服务端授时校准 -->
      <div class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5">
        <span class="rounded bg-cyan-500/15 px-2 py-0.5 font-mono text-[10px] text-cyan-300">
          GATEWAY TOKEN BUCKET & SERVER TIME SYNC
        </span>
        <h2 class="mt-2 text-base font-bold text-white">分级令牌桶限流与服务端授时校准</h2>
        <p class="mt-1 text-xs text-slate-400">
          复刻 <code class="text-cyan-300">pzds</code> 网关策略：普通列表域（60 burst）与高敏域（8 burst）独立计桶，同时通过 <code class="text-cyan-300">/api/v1/time</code> 校准签名时钟偏差。
        </p>

        <div class="mt-3 grid grid-cols-2 gap-2 font-mono text-xs">
          <div class="rounded-lg border border-slate-800 bg-slate-950 p-2.5">
            <div class="text-[10px] text-slate-400">最近响应令牌桶</div>
            <div class="mt-0.5 text-cyan-300">
              {{
                labState.lastRateLimit
                  ? `${labState.lastRateLimit.tier} · 余 ${labState.lastRateLimit.remaining}/${labState.lastRateLimit.burst} (${labState.lastRateLimit.replenishRate}/s)`
                  : '等待请求...'
              }}
            </div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-950 p-2.5">
            <div class="text-[10px] text-slate-400">服务端授时偏移</div>
            <div class="mt-0.5 text-emerald-300">
              {{ labState.clockOffsetMs }} ms
            </div>
          </div>
        </div>

        <div class="mt-3 flex flex-wrap gap-2 font-mono text-xs">
          <button
            class="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-cyan-300 hover:bg-cyan-500/20"
            @click="syncServerClock()"
          >
            同步 /api/v1/time 授时
          </button>
          <button
            class="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-amber-300 hover:bg-amber-500/20"
            @click="testClockDriftExpired"
          >
            模拟本地时钟偏差 +300s (401)
          </button>
          <button
            class="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-rose-300 hover:bg-rose-500/20"
            @click="testSensitiveBucketBurst"
          >
            连打高敏桶 10 次 (第 9 次 429)
          </button>
        </div>

        <div v-if="gatewayTestLog" class="mt-3 rounded-lg border border-slate-800 bg-slate-950 p-2.5 font-mono text-[11px] text-slate-300">
          {{ gatewayTestLog }}
        </div>
      </div>
    </section>

    <PowModal :visible="powModalVisible" :challenge="powChallenge" @close="powModalVisible = false" @solved="onPowSolved" />
    <HoneypotMatrix />
  </div>
</template>
