import { reactive } from 'vue'
import type {
  HealthResponse,
  RateLimitSnapshot,
  ReasonMeta,
  RulesMeta,
  ServerTimeResponse,
} from '@/types/lab'

function loadOrCreateSessionId(): string {
  const existing = sessionStorage.getItem('acl_session_id')
  if (existing) return existing
  const generated = `sess_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`
  sessionStorage.setItem('acl_session_id', generated)
  return generated
}

function loadVisitHistory(): string[] {
  try {
    const raw = sessionStorage.getItem('acl_visit_path')
    if (raw) {
      const parsed = JSON.parse(raw)
      if (Array.isArray(parsed)) return parsed.map(String)
    }
  } catch {
    // 忽略解析异常
  }
  return []
}

export const labState = reactive({
  healthLoaded: false,
  redisMode: 'fakeredis' as 'real' | 'fakeredis',
  labMode: true,
  rulesMeta: null as RulesMeta | null,
  sessionId: loadOrCreateSessionId(),
  fpId: sessionStorage.getItem('acl_fp_id') || '',
  simulatedIp: sessionStorage.getItem('acl_sim_ip') || '',
  powToken: sessionStorage.getItem('acl_pow_token') || '',
  labAuthToken: sessionStorage.getItem('acl_lab_auth') || '',
  labUsername: sessionStorage.getItem('acl_lab_user') || '',
  clockOffsetMs: 0,
  serverIsoTime: '',
  lastRateLimit: null as RateLimitSnapshot | null,
  visitPath: loadVisitHistory(),
})

export const PRESET_SIMULATED_IPS = [
  { label: '真实本机 (不注入模拟头)', ip: '', tag: 'LOCAL' },
  { label: '上海住宅宽带 (116.228.x)', ip: '116.228.10.5', tag: 'CN-RES' },
  { label: '北京住宅宽带 (123.125.x)', ip: '123.125.20.8', tag: 'CN-RES' },
  { label: '美国 AWS 机房 (52.95.x)', ip: '52.95.10.20', tag: 'US-DC' },
  { label: '香港阿里云机房 (47.242.x)', ip: '47.242.30.40', tag: 'HK-DC' },
  { label: '黑名单高危池 (198.51.100.x)', ip: '198.51.100.88', tag: 'BLACK' },
]

export function setSimulatedIp(ip: string): void {
  labState.simulatedIp = ip.trim()
  sessionStorage.setItem('acl_sim_ip', labState.simulatedIp)
}

export function setFpId(fpId: string): void {
  labState.fpId = fpId
  sessionStorage.setItem('acl_fp_id', fpId)
}

export function setPowToken(token: string): void {
  labState.powToken = token
  sessionStorage.setItem('acl_pow_token', token)
}

export function setLabAuth(token: string, username: string): void {
  labState.labAuthToken = token
  labState.labUsername = username
  if (token) {
    sessionStorage.setItem('acl_lab_auth', token)
    sessionStorage.setItem('acl_lab_user', username)
  } else {
    sessionStorage.removeItem('acl_lab_auth')
    sessionStorage.removeItem('acl_lab_user')
  }
}

export function captureRateLimitHeaders(resp: Response): void {
  const tier = resp.headers.get('X-RateLimit-Tier')
  const burst = resp.headers.get('X-RateLimit-Burst-Capacity')
  const rate = resp.headers.get('X-RateLimit-Replenish-Rate')
  const rem = resp.headers.get('X-RateLimit-Remaining')
  const reqTok = resp.headers.get('X-RateLimit-Requested-Tokens')
  const reqId = resp.headers.get('X-Request-Id')
  if (tier && burst && rem) {
    labState.lastRateLimit = {
      tier,
      burst: Number(burst),
      replenishRate: Number(rate || 0),
      remaining: Number(rem),
      requestedTokens: Number(reqTok || 1),
      requestId: reqId || '',
    }
  }
}

export async function syncServerClock(): Promise<void> {
  try {
    const t0 = Date.now()
    const resp = await fetch('/api/v1/time')
    if (!resp.ok) return
    const t1 = Date.now()
    const data = (await resp.json()) as ServerTimeResponse
    const midpoint = Math.round((t0 + t1) / 2)
    labState.clockOffsetMs = data.server_time_ms - midpoint
    labState.serverIsoTime = data.iso_time
  } catch {
    // 授时失败时保持 0 偏移
  }
}

export function recordRouteVisit(path: string): void {
  if (!path) return
  if (labState.visitPath[labState.visitPath.length - 1] !== path) {
    labState.visitPath.push(path)
    if (labState.visitPath.length > 20) {
      labState.visitPath = labState.visitPath.slice(-20)
    }
    sessionStorage.setItem('acl_visit_path', JSON.stringify(labState.visitPath))
  }
}

export async function fetchHealthMeta(force = false): Promise<void> {
  if (labState.healthLoaded && !force) return
  try {
    const [healthResp] = await Promise.all([fetch('/api/v1/health'), syncServerClock()])
    if (!healthResp.ok) return
    const data = (await healthResp.json()) as HealthResponse
    labState.redisMode = data.redis_mode
    labState.labMode = data.lab_mode
    labState.rulesMeta = data.rules_meta
    labState.healthLoaded = true
  } catch {
    // 网络异常时保持降级展示
  }
}

export function getReasonMeta(code: string): ReasonMeta | null {
  return labState.rulesMeta?.reasons?.[code] ?? null
}

export function buildLabHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const headers: Record<string, string> = {
    'X-Session-Id': labState.sessionId,
    ...extra,
  }
  if (labState.fpId) {
    headers['X-Fp-Id'] = labState.fpId
  }
  if (labState.labMode && labState.simulatedIp) {
    headers['X-Simulated-IP'] = labState.simulatedIp
  }
  if (labState.powToken) {
    headers['X-PoW-Token'] = labState.powToken
  }
  if (labState.labAuthToken) {
    headers['X-Lab-Auth'] = labState.labAuthToken
  }
  return headers
}
