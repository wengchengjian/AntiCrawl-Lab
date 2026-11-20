export type RiskAction = 'pass' | 'warn' | 'block' | 'challenge'
export type RiskModule = 'network' | 'fingerprint' | 'automation' | 'behavior' | 'business'

export interface ReasonMeta {
  code: string
  label: string
  description: string
  module: RiskModule
  severity: string
}

export interface PipelineStepMeta {
  step: number
  name: string
  desc: string
}

export interface RulesMeta {
  reasons: Record<string, ReasonMeta>
  weights: Record<string, number>
  decision_thresholds: Record<string, number>
  behavior_thresholds: Record<string, number>
  runtime_limits: {
    rate_limit_qps: number
    fp_rate_limit_qps: number
    ban_seconds: number
    sign_window_seconds: number
    nonce_ttl_seconds: number
    pow_difficulty: number
    data_retention_days: number
  }
  rate_limit_tiers?: Record<string, { burst: number; replenish_rate: number; desc: string }>
  browse_quota?: { max_anon_page: number; max_anon_views: number }
  waf_challenge?: { param_name: string; ttl_seconds: number }
  bot_check_categories?: Array<{ id: string; label: string }>
  pipeline_steps: PipelineStepMeta[]
}

export interface HealthResponse {
  status: string
  redis_mode: 'real' | 'fakeredis'
  redis_ok: boolean
  lab_mode: boolean
  rules_meta: RulesMeta
}

export interface ScreenInfo {
  width: number
  height: number
  availWidth: number
  availHeight: number
  colorDepth: number
  devicePixelRatio: number
}

export interface WebGLInfo {
  vendor: string
  renderer: string
  masked: boolean
  params_hash: string
}

export interface AutomationSignals {
  webdriver: boolean
  webdriver_getter_tampered: boolean
  cdc_keys: string[]
  selenium_keys: string[]
  legacy_keys: string[]
  cdp_console_probe: boolean
  has_window_chrome: boolean | null
  plugins_length: number | null
  hooked_native: boolean
  iframe_mismatch: boolean
  devtools_open: boolean
  stack_automation_frame: boolean
}

export interface FingerprintReportPayload {
  ua: string
  platform: string
  languages: string[]
  timezone: string
  screen: ScreenInfo
  device_memory: number
  hardware_concurrency: number
  touch_points: number
  canvas_hash: string
  audio_hash: string
  webgl: WebGLInfo
  fonts: {
    detected: string[]
    count: number
  }
  automation: AutomationSignals
  extra_probes: Record<string, unknown>
}

export interface ConflictItem {
  rule_id: string
  left_evidence: string
  right_evidence: string
  message: string
  is_enhanced?: boolean
}

export interface FingerprintReportResponse {
  fp_id: string
  risk_score: number
  warnings: string[]
  conflicts: ConflictItem[]
  enhanced_findings: ConflictItem[]
  automation_findings: string[]
  hit_ips: number
}

export interface BehaviorPoint {
  x: number
  y: number
  t: number
  isTrusted: boolean
}

export interface BehaviorKey {
  key: string
  downTs: number
  upTs: number
  isTrusted: boolean
}

export interface BehaviorScroll {
  scrollY: number
  t: number
  isTrusted: boolean
}

export interface BehaviorFocusEvent {
  type: 'focus' | 'blur' | 'visibilitychange'
  hidden: boolean
  t: number
}

export interface BehaviorTracePayload {
  points: BehaviorPoint[]
  keys: BehaviorKey[]
  scrolls: BehaviorScroll[]
  page_focus_events: BehaviorFocusEvent[]
  page_seconds: number
  visit_path: string[]
}

export interface BehaviorMetrics {
  point_count: number
  key_count: number
  scroll_count: number
  trusted_ratio: number
  untrusted_count: number
  direction_changes: number
  velocity_std: number
  key_interval_variance: number | null
  page_seconds: number
}

export interface BehaviorTraceResponse {
  behavior_score: number
  flags: string[]
  metrics: BehaviorMetrics
  details: string[]
}

export interface PipelineStepTrace {
  step: number
  name: string
  status: string
  delta: number
  detail: string
}

export interface RiskLogItem {
  id: number
  ts: string
  client_ip: string
  effective_ip: string
  path: string
  module: string
  action: RiskAction
  risk_score: number
  reasons: string[]
  ua: string
  fingerprint_id: string
  decoy_served: boolean
  latency_ms: number
  extra?: {
    simulated?: boolean
    pipeline_steps?: PipelineStepTrace[]
    details?: string[]
    conflicts?: ConflictItem[]
    conflict_item?: ConflictItem
    enhanced_findings?: ConflictItem[]
    automation_findings?: string[]
    behavior_metrics?: BehaviorMetrics
  }
}

export interface FingerprintProfile {
  fp_id: string
  ua: string
  platform: string
  languages: string[]
  timezone: string
  screen: {
    width: number
    height: number
    color_depth: number
    device_pixel_ratio: number
  }
  device_memory: number
  hardware_concurrency: number
  touch_points: number
  canvas_hash: string
  webgl: {
    vendor: string
    renderer: string
    masked: boolean
  }
  audio_hash: string
  font_count: number
  fonts_hash: string
  automation_flags: AutomationSignals
  extra_probes: Record<string, unknown>
  hit_ips: number
  created_at: string
  last_seen_at: string
}

export interface DashboardStats {
  today_requests: number
  block_rate: number
  warn_rate: number
  active_fingerprints: number
  decoy_served_count: number
}

export interface BanRecord {
  id: number
  ip: string
  reason_code: string
  banned_at: string
  ban_until: string
  lifted_at: string | null
  lifted_by: string | null
  active: boolean
}

export interface ProductItem {
  id: number
  sku: string
  name: string
  category: string
  spec: string
  price_pua: string
  decoy: boolean
}

export interface PowChallenge {
  difficulty: number
  data: string
  expires: number
}

export interface RateLimitSnapshot {
  tier: string
  burst: number
  replenishRate: number
  remaining: number
  requestedTokens: number
  requestId: string
}

export interface ServerTimeResponse {
  server_time_sec: number
  server_time_ms: number
  iso_time: string
  sign_window_seconds: number
}

export interface BrowseQuotaInfo {
  logged_in: boolean
  username: string | null
  max_anon_page: number
  max_anon_views: number
  current_views: number
  remaining_views: number
  require_login: boolean
}

export interface BotCheckMetric {
  id: string
  category: 'sannysoft' | 'browserscan' | 'browserleaks' | 'network' | 'behavior'
  source_ref: string
  name: string
  status: 'pass' | 'warn' | 'fail' | 'info'
  observed: string
  expected: string
  risk_delta: number
  reason: string
}

export interface BotCheckReason {
  id: string
  code: string
  category: string
  source_ref: string
  weight: number
  severity: string
  message: string
}

export interface BotCheckPayload extends FingerprintReportPayload {
  behavior?: BehaviorTracePayload
}

export interface BotCheckResponse {
  request_id: number
  effective_ip: string
  ip_geo: {
    country: string
    city: string
    asn: string
    is_datacenter: boolean
  }
  bot_confidence: number
  human_confidence: number
  verdict: 'likely_human' | 'suspicious' | 'likely_bot'
  verdict_label: string
  confidence_level: 'high' | 'medium' | 'low'
  summary: string
  category_scores: Record<string, number>
  reasons: BotCheckReason[]
  checks: BotCheckMetric[]
  telemetry_coverage: {
    mode: string
    checked_items: number
    pass_count?: number
    warn_count?: number
    fail_count?: number
  }
}
