// Thin API client. No auth header: the app is localhost-only and the real gate is Azure.

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(opts.headers ?? {}),
    },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return res.json() as Promise<T>;
}

// ---- types -----------------------------------------------------------------
export interface AzureTarget {
  storage_account: string;
  container: string;
  subscription: string;
}
export interface AzureStatus {
  logged_in: boolean;
  user: string | null;
  subscription: string | null;
  subscription_id: string | null;
  detail: string | null;
}
export interface AzureSubscription {
  id: string;
  name: string;
  is_default: boolean;
}
export interface AzureStorageAccount {
  name: string;
  resource_group: string;
}
export interface AzureContainer {
  name: string;
}
export interface DatasetMeta {
  dataset_id: string;
  date: string;
  hour: number | null;
  line_count: number;
  merged_path: string;
  cached: boolean;
}
export interface EstimateDay {
  date: string;
  bytes: number;
  blob_count: number;
  cached: boolean;
}
export interface EstimateResult {
  days: EstimateDay[];
  cached_days: number;
  download_bytes: number;
  download_blob_count: number;
  on_disk_bytes: number;
  estimated_seconds: number;
  blobs_per_sec: number;
}
export interface IpVerdict {
  ip: string;
  blocks: number;
  distinct_rule_groups: number;
  distinct_rules: number;
  distinct_uris: number;
  verdict: "scanner" | "fp_candidate";
}
export interface ScannerReport {
  dataset_id: string;
  total_blocks: number;
  scanner_ips: string[];
  genuine_fp_candidate_blocks: number;
  thresholds: Record<string, number>;
  by_ip: IpVerdict[];
}
export interface CauseRule {
  rule_name: string;
  rule_group: string;
  rule_id: string;
  msg: string;
  hits: number;
  distinct_ips: number;
}
export interface FiringRule {
  action: string;
  rule_name: string;
  rule_group: string;
  rule_id: string;
  total: number;
}
export interface TimelineBucket {
  bucket: string;
  block: number;
  anomaly: number;
  log: number;
}
export interface DatasetSummary {
  dataset_id: string;
  dataset_ids?: string[];
  policy?: string | null;
  actions: Record<string, number>;
  distinct_client_ips: number;
  distinct_rules: number;
  distinct_hosts: number;
  policy_modes: { mode: string; n: number }[];
  policies: { policy: string; n: number }[];
  top_hosts: { host: string; n: number }[];
  top_ips: { client_ip: string; n: number; blocks: number }[];
  timeline: TimelineBucket[];
}
export interface ExclusionContextItem {
  match_variable_name: string;
  terraform: { match_variable: string; selector: string | null } | null;
  not_excludable_reason: string | null;
  suggested_operator: string;
  classification: "false_positive" | "attack" | "scanner_noise" | "mixed" | "not_excludable" | "unknown";
  evidence: string[];
  hit_count: number;
  non_scanner_hits: number;
  scanner_share: number | null;
  distinct_ips: number;
  sample_values: string[];
  affected_uris: string[];
}
export interface ExclusionContext {
  dataset_id: string;
  rule_id: string;
  rule_group: string | null;
  contexts: ExclusionContextItem[];
}
export interface ConsolidationHint {
  match_variable: string;
  selectors: string[];
  suggestion: string;
  slots_saved: number;
}
export interface ExclusionCount {
  count: number;
  limit: number;
  remaining: number;
  by_match_variable: Record<string, number>;
  consolidation_hints: ConsolidationHint[];
}
export interface RuleEvent {
  time: string;
  client_ip: string;
  host: string;
  request_uri: string;
  action: string;
  policy_mode: string | null;
  msg: string | null;
  tracking_reference: string;
  match_variable_name: string;
  match_value: string;
}
export interface SearchEvent {
  time: string;
  client_ip: string;
  host: string;
  request_uri: string;
  action: string;
  policy_mode: string | null;
  msg: string | null;
  rule_group: string;
  rule_id: string;
  tracking_reference: string;
}
export interface RequestRow {
  time: string;
  client_ip: string;
  host: string;
  request_uri: string;
  action: string;
  policy: string | null;
  policy_mode: string | null;
  rule_name: string;
  rule_group: string;
  rule_id: string;
  msg: string | null;
  data: string | null;
  match_variable_names: string[];
  match_values: string[];
}
export interface RequestDetail {
  dataset_id: string;
  tracking_reference: string;
  anomaly_score: number | null;
  rows: RequestRow[];
}
export interface FiringDiffRow {
  rule_id: string;
  rule_group: string;
  before: number;
  after: number;
  delta: number;
  status: "new" | "gone" | "increased" | "reduced" | "unchanged" | "resolved";
}
export interface FiringDiff {
  before_id: string;
  after_id: string;
  policy: string | null;
  rules: FiringDiffRow[];
}
export interface RuleDiffItem {
  match_variable_name: string;
  before_hits: number;
  after_hits: number;
  delta: number;
  status: "new" | "increased" | "reduced" | "unchanged" | "resolved";
}
export interface RuleDiff {
  before_id: string;
  after_id: string;
  rule_id: string;
  before_hits: number;
  after_hits: number;
  resolved: boolean;
  match_variables: RuleDiffItem[];
}
export interface ParsedExclusion {
  match_variable: string;
  operator: string;
  selector: string;
}
export interface CoverageRow {
  rule_id: string;
  rule_group: string | null;
  match_variable_name: string;
  classification: string;
  terraform: { match_variable: string; selector: string | null } | null;
  hit_count: number;
  covered_by: ParsedExclusion | null;
}
export interface Coverage {
  dataset_id: string;
  total_exclusions: number;
  limit: number;
  remaining: number;
  rules_checked: number;
  truncated: boolean;
  coverage: CoverageRow[];
  uncovered_candidates: CoverageRow[];
  duplicates: ParsedExclusion[];
  conflicts: (ParsedExclusion & { conflicts_with_operator: string })[];
  stale_exclusions: ParsedExclusion[];
}
export interface ScopeParams {
  datasets?: string[];
  policy?: string | null;
}

// Build the ?dataset=&policy=&... query string shared by every scoped analysis call.
function scopeQuery(scope?: ScopeParams, extra?: Record<string, string | number | boolean | undefined>): string {
  const p = new URLSearchParams();
  for (const d of scope?.datasets ?? []) p.append("dataset", d);
  if (scope?.policy) p.set("policy", scope.policy);
  for (const [k, v] of Object.entries(extra ?? {})) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export interface DownloadProgress {
  phase: "cached" | "listing" | "start" | "progress" | "done" | "error";
  downloaded?: number;
  total?: number | null;
  dataset?: DatasetMeta;
  detail?: string;
}

// Consume the SSE download stream, invoking `onEvent` for each progress event. Resolves with
// the dataset meta on completion, rejects with the server's detail on an error event.
async function streamDataset(
  date: string,
  hour: number | null,
  opts: { force?: boolean; total?: number | null },
  onEvent: (p: DownloadProgress) => void,
): Promise<DatasetMeta> {
  const p = new URLSearchParams({ date });
  if (hour !== null) p.set("hour", String(hour));
  if (opts.force) p.set("force", "true");
  if (opts.total != null) p.set("total", String(opts.total));

  const res = await fetch(`/api/datasets/stream?${p}`);
  if (!res.ok || !res.body) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let meta: DatasetMeta | null = null;

  for (;;) {
    const { done, value } = await reader.read();
    if (value) buffer += decoder.decode(value, { stream: true });
    let sep: number;
    while ((sep = buffer.indexOf("\n\n")) !== -1) {
      const frame = buffer.slice(0, sep).trim();
      buffer = buffer.slice(sep + 2);
      if (!frame.startsWith("data:")) continue;
      const ev = JSON.parse(frame.slice(5).trim()) as DownloadProgress;
      onEvent(ev);
      if (ev.phase === "error") throw new ApiError(502, ev.detail ?? "download failed");
      if (ev.phase === "done" || ev.phase === "cached") meta = ev.dataset ?? null;
    }
    if (done) break;
  }
  if (!meta) throw new ApiError(502, "download stream ended without a result");
  return meta;
}

// ---- endpoints -------------------------------------------------------------
export const api = {
  streamDataset,
  health: () => request<{ status: string; offline: boolean }>("/healthz"),
  getConfig: () => request<AzureTarget>("/config"),
  putConfig: (t: AzureTarget) => request<AzureTarget>("/config", { method: "PUT", body: JSON.stringify(t) }),
  azureStatus: () => request<AzureStatus>("/azure/status"),
  azureSubscriptions: () => request<{ subscriptions: AzureSubscription[] }>("/azure/subscriptions"),
  azureStorageAccounts: (subscription: string) =>
    request<{ storage_accounts: AzureStorageAccount[] }>(
      `/azure/storage-accounts?subscription=${encodeURIComponent(subscription)}`,
    ),
  azureContainers: (account: string, subscription: string) =>
    request<{ containers: AzureContainer[] }>(
      `/azure/containers?account=${encodeURIComponent(account)}&subscription=${encodeURIComponent(subscription)}`,
    ),
  listDatasets: () => request<{ datasets: DatasetMeta[] }>("/datasets"),
  deleteDataset: (id: string) => request<{ dataset_id: string; deleted: boolean }>(`/datasets/${id}`, { method: "DELETE" }),
  clearDatasets: () => request<{ deleted: number }>("/datasets", { method: "DELETE" }),
  createDataset: (date: string, hour: number | null, force = false, incremental = false) =>
    request<DatasetMeta>("/datasets", {
      method: "POST",
      body: JSON.stringify({ date, hour, force, incremental }),
    }),
  estimate: (dateFrom: string, dateTo: string, hour: number | null) =>
    request<EstimateResult>("/datasets/estimate", {
      method: "POST",
      body: JSON.stringify({ date_from: dateFrom, date_to: dateTo, hour }),
    }),
  speedtest: () =>
    request<{ blobs_per_sec: number; blobs: number; bytes: number; seconds: number; mbps: number }>(
      "/datasets/speedtest",
      { method: "POST" },
    ),
  summary: (id: string, scope?: ScopeParams) => request<DatasetSummary>(`/datasets/${id}/summary${scopeQuery(scope)}`),
  policies: (id: string, scope?: ScopeParams) =>
    request<{ dataset_id: string; policies: string[] }>(`/datasets/${id}/policies${scopeQuery(scope)}`),
  firingRules: (id: string, scope?: ScopeParams) =>
    request<{ dataset_id: string; rules: FiringRule[] }>(`/datasets/${id}/firing-rules${scopeQuery(scope)}`),
  scannerReport: (id: string, scope?: ScopeParams) =>
    request<ScannerReport>(`/datasets/${id}/scanner-report${scopeQuery(scope)}`),
  blocksByCause: (id: string, excludeScanners = true, scope?: ScopeParams) =>
    request<{ rules: CauseRule[]; excluded_ips: string[] }>(
      `/datasets/${id}/blocks-by-cause${scopeQuery(scope, { exclude_scanners: excludeScanners })}`,
    ),
  searchEvents: (id: string, q: string, limit = 100, scope?: ScopeParams) =>
    request<{ dataset_id: string; query: string; events: SearchEvent[] }>(
      `/datasets/${id}/search${scopeQuery(scope, { q, limit })}`,
    ),
  actionEvents: (id: string, action: string | null, limit = 200, scope?: ScopeParams) =>
    request<{ dataset_id: string; action: string | null; events: SearchEvent[] }>(
      `/datasets/${id}/events${scopeQuery(scope, { action: action ?? undefined, limit })}`,
    ),
  requestDetail: (id: string, trackingRef: string, scope?: ScopeParams) =>
    request<RequestDetail>(`/datasets/${id}/requests/${encodeURIComponent(trackingRef)}${scopeQuery(scope)}`),
  diffFiring: (id: string, against: string, scope?: ScopeParams) =>
    request<FiringDiff>(`/datasets/${id}/diff${scopeQuery(scope, { against })}`),
  ruleDiff: (id: string, ruleId: string, against: string, matchVariable: string | null = null, scope?: ScopeParams) =>
    request<RuleDiff>(
      `/datasets/${id}/rules/${ruleId}/diff${scopeQuery(scope, { against, match_variable: matchVariable ?? undefined })}`,
    ),
  exclusionContext: (id: string, ruleId: string, scope?: ScopeParams) =>
    request<ExclusionContext>(`/datasets/${id}/rules/${ruleId}/exclusion-context${scopeQuery(scope)}`),
  ruleEvents: (id: string, ruleId: string, matchVariable: string | null = null, limit = 50, scope?: ScopeParams) =>
    request<{ events: RuleEvent[] }>(
      `/datasets/${id}/rules/${ruleId}/events${scopeQuery(scope, { limit, match_variable: matchVariable ?? undefined })}`,
    ),
  exclusionCoverage: (id: string, tfContent: string, scope?: ScopeParams) =>
    request<Coverage>(`/datasets/${id}/exclusions/coverage${scopeQuery(scope)}`, {
      method: "POST",
      body: JSON.stringify({ tf_content: tfContent }),
    }),
  exclusionsCount: (tfContent: string) =>
    request<ExclusionCount>("/exclusions/count", {
      method: "POST",
      body: JSON.stringify({ tf_content: tfContent }),
    }),
};
