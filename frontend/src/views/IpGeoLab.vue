<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { probeMultiChannelIpLeaks } from '@/probes'
import { buildLabHeaders, captureRateLimitHeaders } from '@/services/labState'

interface IpProfile {
  ip: string
  source: string
  is_simulated?: boolean
  country: string
  country_code: string
  region: string
  city: string
  lat: number
  lon: number
  timezone: string
  isp: string
  org: string
  asn: string
  rdns: string
  rdns_cloud_tag: string | null
  cloud_provider?: string | null
  cloud_match_by?: string | null
  is_mobile: boolean
  is_proxy: boolean
  is_hosting: boolean
  is_blacklist: boolean
}

interface IpFinding {
  id: string
  title: string
  severity: string
  weight: number
  detail: string
  evasion_tip: string
  defense_tip: string
}

interface IpAuditReport {
  request_id: number
  effective_ip: string
  primary_profile: IpProfile
  channels: {
    direct_origin: IpProfile | null
    overseas_echo: IpProfile | null
    domestic_echo: IpProfile | null
    webrtc_public_ips: string[]
    webrtc_local_candidates: string[]
    webrtc_leaked_profiles: IpProfile[]
  }
  vpn_pierced: boolean
  suspected_real_ip: string | null
  suspected_proxy_ip: string | null
  proxy_headers: string[]
  risk_score: number
  concealment_score: number
  findings: IpFinding[]
}

const loading = ref(false)
const report = ref<IpAuditReport | null>(null)
const mapFocus = ref<'primary' | 'leaked'>('primary')
const browserTz = ref(Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC')
const browserLangs = ref<string[]>(Array.from(navigator.languages || [navigator.language || 'zh-CN']))

const activeMapProfile = computed<IpProfile | null>(() => {
  if (!report.value) return null
  if (mapFocus.value === 'leaked') {
    if (report.value.channels.webrtc_leaked_profiles.length > 0) {
      return report.value.channels.webrtc_leaked_profiles[0] ?? report.value.primary_profile
    }
    if (
      report.value.channels.overseas_echo &&
      report.value.channels.overseas_echo.ip !== report.value.primary_profile.ip
    ) {
      return report.value.channels.overseas_echo
    }
  }
  return report.value.primary_profile
})

const osmEmbedUrl = computed(() => {
  const p = activeMapProfile.value
  if (!p || (!p.lat && !p.lon)) return ''
  const dLat = 0.09
  const dLon = 0.18
  const bbox = [p.lon - dLon, p.lat - dLat, p.lon + dLon, p.lat + dLat]
    .map((n) => n.toFixed(5))
    .join(',')
  return `https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&layer=mapnik&marker=${p.lat.toFixed(5)},${p.lon.toFixed(5)}`
})

async function runAudit(override?: {
  simIp?: string
  webrtcPublicIps?: string[]
  overseasEchoIp?: string
  domesticEchoIp?: string
  proxyVia?: string
}): Promise<void> {
  loading.value = true
  try {
    let webrtcPublicIps = override?.webrtcPublicIps
    let webrtcLocal: string[] = []
    let overseasIp = override?.overseasEchoIp ?? ''
    let domesticIp = override?.domesticEchoIp ?? ''

    if (!override) {
      const probed = await probeMultiChannelIpLeaks()
      webrtcPublicIps = probed.webrtc.publicIps
      webrtcLocal = probed.webrtc.localCandidates
      overseasIp = probed.overseasEchoIp
      domesticIp = probed.domesticEchoIp
    }

    const headers = buildLabHeaders({ 'Content-Type': 'application/json' })
    if (override?.simIp) {
      headers['X-Simulated-IP'] = override.simIp
    }
    if (override?.proxyVia) {
      headers['Via'] = override.proxyVia
    }

    const resp = await fetch('/api/v1/ip/audit', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        webrtc_public_ips: webrtcPublicIps || [],
        webrtc_local_candidates: webrtcLocal,
        overseas_echo_ip: overseasIp,
        domestic_echo_ip: domesticIp,
        browser_timezone: browserTz.value,
        browser_tz_offset: new Date().getTimezoneOffset(),
        browser_languages: browserLangs.value,
      }),
    })
    captureRateLimitHeaders(resp)
    report.value = (await resp.json()) as IpAuditReport
    mapFocus.value = 'primary'
  } finally {
    loading.value = false
  }
}

function simulateWebRtcVpnLeak(): void {
  void runAudit({
    simIp: '52.95.10.20',
    webrtcPublicIps: ['116.228.10.5'],
    overseasEchoIp: '52.95.10.20',
    domesticEchoIp: '116.228.10.5',
    proxyVia: '1.1 clash-proxy.local',
  })
}

function simulateSplitTunnelRuleMode(): void {
  void runAudit({
    simIp: '116.228.10.5',
    webrtcPublicIps: ['116.228.10.5'],
    overseasEchoIp: '52.95.10.20',
    domesticEchoIp: '116.228.10.5',
  })
}

const cnCloudPresets = [
  { label: '阿里云', ip: '47.96.10.20' },
  { label: '腾讯云', ip: '119.29.10.20' },
  { label: '华为云', ip: '114.115.10.20' },
  { label: '火山引擎', ip: '180.184.10.20' },
  { label: '百度云', ip: '180.76.10.20' },
  { label: '京东云', ip: '114.67.10.20' },
  { label: 'UCloud', ip: '106.75.10.20' },
  { label: '金山云', ip: '120.92.10.20' },
]

function simulateCnCloudIp(ip: string): void {
  void runAudit({
    simIp: ip,
    webrtcPublicIps: [ip],
  })
}

onMounted(() => {
  void runAudit()
})
</script>

<template>
  <div class="mx-auto max-w-7xl space-y-6 px-4 py-6">
    <!-- 顶部标题与演练控制 -->
    <section class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <span class="rounded bg-cyan-500/15 px-2 py-0.5 font-mono text-[10px] text-cyan-300">
            IP INTELLIGENCE × WEBRTC STUN × SPLIT-TUNNEL VPN PENETRATION
          </span>
          <h1 class="mt-1.5 text-xl font-bold text-white sm:text-2xl">
            IP 地域透视、VPN 穿透检测与攻防对抗台
          </h1>
          <p class="mt-1 text-xs text-slate-400">
            整合实时 GeoIP / ASN / rDNS 反向解析、OpenStreetMap 实景定位，并利用
            <strong class="text-emerald-300">WebRTC UDP STUN 穿透</strong> 与
            <strong class="text-amber-300">国内外双信道分流探测</strong> 尝试越过代理/VPN 捕获真实出口 IP。
          </p>
        </div>

        <div class="flex flex-wrap gap-2 font-mono text-xs">
          <button
            :disabled="loading"
            class="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-50"
            @click="runAudit()"
          >
            {{ loading ? '多信道探测中...' : '实时探测本机 IP 与 VPN 泄露' }}
          </button>
          <button
            :disabled="loading"
            class="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-rose-300 hover:bg-rose-500/20 disabled:opacity-50"
            @click="simulateWebRtcVpnLeak"
          >
            模拟：WebRTC STUN 穿透 VPN 泄露
          </button>
          <button
            :disabled="loading"
            class="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-amber-300 hover:bg-amber-500/20 disabled:opacity-50"
            @click="simulateSplitTunnelRuleMode"
          >
            模拟：Clash 规则分流多出口暴露
          </button>
        </div>
      </div>

      <!-- 国内云厂商机房一键模拟测试 -->
      <div class="mt-4 flex flex-wrap items-center gap-1.5 border-t border-slate-800/80 pt-3 font-mono text-[11px]">
        <span class="mr-1 text-slate-400">国内云机房一键验证:</span>
        <button
          v-for="preset in cnCloudPresets"
          :key="preset.ip"
          :disabled="loading"
          class="rounded border border-slate-700 bg-slate-900/80 px-2 py-0.5 text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 disabled:opacity-50"
          :title="`模拟 ${preset.label} 机房 IP (${preset.ip})`"
          @click="simulateCnCloudIp(preset.ip)"
        >
          {{ preset.label }}
        </button>
      </div>
    </section>

    <!-- VPN 穿透告警横幅 -->
    <section
      v-if="report?.vpn_pierced"
      class="rounded-2xl border border-rose-500/50 bg-rose-950/25 p-4 text-xs"
    >
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="font-mono text-sm font-bold text-rose-300">
          ⚡ 已穿透代理 / 检测到 VPN 多出口差异！
        </div>
        <div class="flex flex-wrap gap-2 font-mono">
          <span v-if="report.suspected_real_ip" class="rounded bg-emerald-500/20 px-2.5 py-1 text-emerald-300">
            疑似真实直连 IP: {{ report.suspected_real_ip }}
          </span>
          <span v-if="report.suspected_proxy_ip" class="rounded bg-amber-500/20 px-2.5 py-1 text-amber-300">
            疑似 VPN/代理出口 IP: {{ report.suspected_proxy_ip }}
          </span>
        </div>
      </div>
    </section>

    <!-- 实景地图（OpenStreetMap） + Whoer 风格情报卡片 -->
    <section v-if="report" class="grid gap-4 lg:grid-cols-12">
      <!-- 左侧：Whoer 风格详细情报 -->
      <div class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5 lg:col-span-6">
        <div class="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <div class="font-mono text-[11px] text-slate-400">当前主出口 IP</div>
            <div class="mt-0.5 font-mono text-2xl font-bold text-cyan-300">
              {{ report.primary_profile.ip }}
            </div>
            <div v-if="report.primary_profile.cloud_provider" class="mt-1 flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
              <span class="rounded bg-amber-500/20 px-2 py-0.5 text-amber-300">
                云机房识别: {{ report.primary_profile.cloud_provider }}
              </span>
              <span v-if="report.primary_profile.cloud_match_by" class="text-slate-500">
                ({{ report.primary_profile.cloud_match_by }})
              </span>
            </div>
          </div>
          <div class="text-right font-mono">
            <div class="text-[11px] text-slate-400">隐匿度 / 暴露风险</div>
            <div class="mt-0.5 text-lg font-bold">
              <span class="text-emerald-300">{{ report.concealment_score }}%</span>
              <span class="mx-1 text-slate-600">/</span>
              <span :class="report.risk_score >= 50 ? 'text-rose-400' : report.risk_score >= 25 ? 'text-amber-300' : 'text-emerald-300'">
                {{ report.risk_score }} 分
              </span>
            </div>
          </div>
        </div>

        <div class="mt-4 grid grid-cols-2 gap-3 text-xs">
          <div class="rounded-xl border border-slate-800/80 bg-slate-950/70 p-3">
            <div class="text-[10px] text-slate-400">提供商 (ISP / Org)</div>
            <div class="mt-1 truncate font-mono text-slate-100" :title="report.primary_profile.isp">
              {{ report.primary_profile.isp || 'Unknown' }}
            </div>
          </div>
          <div class="rounded-xl border border-slate-800/80 bg-slate-950/70 p-3">
            <div class="text-[10px] text-slate-400">ASN 自治域</div>
            <div class="mt-1 truncate font-mono text-slate-100" :title="report.primary_profile.asn">
              {{ report.primary_profile.asn || 'AS0' }}
            </div>
          </div>
          <div class="col-span-2 rounded-xl border border-slate-800/80 bg-slate-950/70 p-3">
            <div class="text-[10px] text-slate-400">主机名 (rDNS PTR 反向解析)</div>
            <div class="mt-1 break-all font-mono text-slate-200">
              {{ report.primary_profile.rdns || '无 PTR 记录' }}
              <span
                v-if="report.primary_profile.rdns_cloud_tag"
                class="ml-2 rounded bg-amber-500/20 px-1.5 py-0.5 text-[10px] text-amber-300"
              >
                {{ report.primary_profile.rdns_cloud_tag }}
              </span>
            </div>
          </div>
          <div class="rounded-xl border border-slate-800/80 bg-slate-950/70 p-3">
            <div class="text-[10px] text-slate-400">地域与经纬度</div>
            <div class="mt-1 font-mono text-slate-100">
              {{ report.primary_profile.country }} · {{ report.primary_profile.region }} {{ report.primary_profile.city }}
            </div>
            <div class="mt-0.5 font-mono text-[10px] text-slate-500">
              ({{ report.primary_profile.lat.toFixed(4) }}, {{ report.primary_profile.lon.toFixed(4) }})
            </div>
          </div>
          <div class="rounded-xl border border-slate-800/80 bg-slate-950/70 p-3">
            <div class="text-[10px] text-slate-400">IP 时区 vs 浏览器时区</div>
            <div class="mt-1 font-mono text-slate-100">
              {{ report.primary_profile.timezone || 'N/A' }}
            </div>
            <div class="mt-0.5 font-mono text-[10px] text-cyan-300">
              本机: {{ browserTz }}
            </div>
          </div>
        </div>

        <!-- Whoer 风格 4 项布尔信誉状态 -->
        <div class="mt-3 grid grid-cols-4 gap-2 font-mono text-xs">
          <div class="rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-center">
            <div class="text-[10px] text-slate-400">代理服务器</div>
            <div class="mt-1 font-bold" :class="report.primary_profile.is_proxy ? 'text-rose-400' : 'text-emerald-400'">
              ● {{ report.primary_profile.is_proxy ? '是' : '否' }}
            </div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-center">
            <div class="text-[10px] text-slate-400">机房/托管</div>
            <div class="mt-1 font-bold" :class="report.primary_profile.is_hosting ? 'text-amber-300' : 'text-emerald-400'">
              ● {{ report.primary_profile.is_hosting ? '是' : '否' }}
            </div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-center">
            <div class="text-[10px] text-slate-400">VPN 穿透</div>
            <div class="mt-1 font-bold" :class="report.vpn_pierced ? 'text-rose-400' : 'text-emerald-400'">
              ● {{ report.vpn_pierced ? '已泄露' : '未检出' }}
            </div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-center">
            <div class="text-[10px] text-slate-400">黑名单</div>
            <div class="mt-1 font-bold" :class="report.primary_profile.is_blacklist ? 'text-rose-400' : 'text-emerald-400'">
              ● {{ report.primary_profile.is_blacklist ? '是' : '否' }}
            </div>
          </div>
        </div>
      </div>

      <!-- 右侧：OpenStreetMap 实时地理地图 -->
      <div class="flex flex-col rounded-2xl border border-slate-800 bg-[#0d1422] p-5 lg:col-span-6">
        <div class="flex flex-wrap items-center justify-between gap-2 pb-3">
          <h2 class="text-sm font-bold text-white">IP 实时地理定位地图（OpenStreetMap）</h2>
          <div class="flex gap-1.5 font-mono text-[11px]">
            <button
              class="rounded border px-2 py-0.5"
              :class="mapFocus === 'primary' ? 'border-cyan-500 bg-cyan-500/20 text-cyan-200' : 'border-slate-700 text-slate-400'"
              @click="mapFocus = 'primary'"
            >
              主出口 IP
            </button>
            <button
              v-if="report.vpn_pierced"
              class="rounded border px-2 py-0.5"
              :class="mapFocus === 'leaked' ? 'border-rose-500 bg-rose-500/20 text-rose-200' : 'border-slate-700 text-slate-400'"
              @click="mapFocus = 'leaked'"
            >
              穿透/分流 IP
            </button>
          </div>
        </div>

        <div v-if="osmEmbedUrl" class="relative flex-1 overflow-hidden rounded-xl border border-slate-800 bg-slate-950 min-h-[290px]">
          <iframe
            :src="osmEmbedUrl"
            class="h-full min-h-[290px] w-full border-0"
            loading="lazy"
            referrerpolicy="no-referrer"
          ></iframe>
        </div>
        <div
          v-else
          class="flex flex-1 min-h-[290px] items-center justify-center rounded-xl border border-slate-800 bg-slate-950 font-mono text-xs text-slate-500"
        >
          当前 IP 无有效经纬度坐标（本地回环或未命中 GeoIP）
        </div>
      </div>
    </section>

    <!-- 四信道 VPN 穿透对比矩阵 -->
    <section v-if="report" class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5">
      <h2 class="text-base font-bold text-white">四信道真实 IP 穿透对比矩阵</h2>
      <p class="mt-1 text-xs text-slate-400">
        并行比对本服直连、WebRTC UDP STUN 反射、海外回显与国内回显四条通道；任一通道返回不同公网 IP 即可识破未完全封装的代理或规则分流 VPN。
      </p>
      <div class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4 font-mono text-xs">
        <div class="rounded-xl border border-slate-800 bg-slate-950/80 p-3.5">
          <div class="text-[10px] text-cyan-300">通道 1 · 本服直连 IP</div>
          <div class="mt-1 text-sm font-bold text-white">{{ report.channels.direct_origin?.ip || '-' }}</div>
          <div class="mt-1 text-[11px] text-slate-400">
            {{ report.channels.direct_origin?.country }} · {{ report.channels.direct_origin?.city }}
          </div>
          <div class="mt-0.5 truncate text-[10px] text-slate-500">{{ report.channels.direct_origin?.isp }}</div>
        </div>

        <div
          class="rounded-xl border p-3.5"
          :class="
            report.channels.webrtc_leaked_profiles.length
              ? 'border-rose-500/50 bg-rose-950/20'
              : 'border-slate-800 bg-slate-950/80'
          "
        >
          <div class="text-[10px] text-emerald-300">通道 2 · WebRTC UDP STUN</div>
          <div class="mt-1 text-sm font-bold text-white">
            {{ report.channels.webrtc_public_ips.join(', ') || '未暴露公网 srflx (安全/被阻断)' }}
          </div>
          <div v-if="report.channels.webrtc_leaked_profiles.length" class="mt-1 text-[11px] text-rose-300">
            穿透捕获: {{ report.channels.webrtc_leaked_profiles[0]?.country }} / {{ report.channels.webrtc_leaked_profiles[0]?.city }}
          </div>
          <div v-else class="mt-1 text-[10px] text-slate-500">
            本地/mDNS: {{ report.channels.webrtc_local_candidates.slice(0, 2).join(', ') || '无' }}
          </div>
        </div>

        <div class="rounded-xl border border-slate-800 bg-slate-950/80 p-3.5">
          <div class="text-[10px] text-amber-300">通道 3 · 海外出口探测 (ipify/ipwho)</div>
          <div class="mt-1 text-sm font-bold text-white">
            {{ report.channels.overseas_echo?.ip || '未探测到 / 超时' }}
          </div>
          <div v-if="report.channels.overseas_echo" class="mt-1 text-[11px] text-slate-400">
            {{ report.channels.overseas_echo.country }} · {{ report.channels.overseas_echo.city }}
          </div>
          <div v-if="report.channels.overseas_echo" class="mt-0.5 truncate text-[10px] text-slate-500">
            {{ report.channels.overseas_echo.isp }}
          </div>
        </div>

        <div class="rounded-xl border border-slate-800 bg-slate-950/80 p-3.5">
          <div class="text-[10px] text-indigo-300">通道 4 · 国内直连探测</div>
          <div class="mt-1 text-sm font-bold text-white">
            {{ report.channels.domestic_echo?.ip || '未探测到 / 超时' }}
          </div>
          <div v-if="report.channels.domestic_echo" class="mt-1 text-[11px] text-slate-400">
            {{ report.channels.domestic_echo.country }} · {{ report.channels.domestic_echo.city }}
          </div>
          <div v-if="report.channels.domestic_echo" class="mt-0.5 truncate text-[10px] text-slate-500">
            {{ report.channels.domestic_echo.isp }}
          </div>
        </div>
      </div>
    </section>

    <!-- 攻防对抗升级对照表（检测 vs 反检测） -->
    <section v-if="report" class="rounded-2xl border border-slate-800 bg-[#0d1422] p-5">
      <div class="flex items-center justify-between">
        <h2 class="text-base font-bold text-white">攻防对抗升级分析（命中破绽 × 红队反检测加固 × 蓝队反制）</h2>
        <span class="font-mono text-xs text-slate-400">命中 {{ report.findings.length }} 项风险</span>
      </div>

      <div v-if="report.findings.length" class="mt-4 space-y-3 text-xs">
        <div
          v-for="f in report.findings"
          :key="f.id"
          class="rounded-xl border border-slate-800 bg-slate-950/80 p-4"
        >
          <div class="flex flex-wrap items-center justify-between gap-2 font-mono">
            <div class="flex items-center gap-2">
              <span class="rounded bg-rose-500/20 px-2 py-0.5 text-rose-300">+{{ f.weight }} 分</span>
              <span class="font-bold text-slate-100">{{ f.title }}</span>
              <span class="text-[10px] text-slate-500">[{{ f.id }}]</span>
            </div>
            <span class="uppercase text-[10px] text-amber-300">{{ f.severity }}</span>
          </div>
          <p class="mt-2 text-slate-300">{{ f.detail }}</p>
          <div class="mt-3 grid gap-2 sm:grid-cols-2">
            <div class="rounded-lg border border-amber-500/25 bg-amber-950/15 p-2.5">
              <div class="font-mono text-[10px] font-bold text-amber-300">红队反检测思路（如何隐藏）</div>
              <div class="mt-1 text-slate-300">{{ f.evasion_tip }}</div>
            </div>
            <div class="rounded-lg border border-cyan-500/25 bg-cyan-950/15 p-2.5">
              <div class="font-mono text-[10px] font-bold text-cyan-300">蓝队检测升级（如何反制）</div>
              <div class="mt-1 text-slate-300">{{ f.defense_tip }}</div>
            </div>
          </div>
        </div>
      </div>

      <div
        v-else
        class="mt-4 rounded-xl border border-emerald-500/30 bg-emerald-950/15 p-5 text-center text-xs text-emerald-300"
      >
        当前连接未检出代理、机房、WebRTC 穿透或规则分流泄露（隐匿度 100%）。可点击顶部按钮模拟 VPN 穿透与分流对抗场景。
      </div>
    </section>
  </div>
</template>
