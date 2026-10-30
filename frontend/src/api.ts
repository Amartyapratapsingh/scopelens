/** Typed client for the ScopeLens API.
 *
 * Kept deliberately small and dependency-free: plain `fetch`, no state library, no
 * generated client. M0's dashboard has four views and does not need more.
 */

export type AuthorityDomain = "production" | "lab";
export type ScanStatus =
  | "queued"
  | "recon"
  | "planning"
  | "testing"
  | "confirming"
  | "reporting"
  | "completed"
  | "completed_partial"
  | "failed"
  | "cancelled"
  | "paused";

export interface Operator {
  id: string;
  username: string;
  last_login_at: string | null;
}

export interface LabBinding {
  service: string;
  address: string;
  port: number;
  environment: string;
}

export interface LabService {
  id: string;
  description: string;
  environment: string;
  addresses: string[];
  ports: number[];
  schemes: string[];
}

export interface ScopeView {
  id: string;
  version: number;
  authority_domain: AuthorityDomain;
  origin: string;
  scheme: string;
  host: string;
  port: number;
  allowed_path_prefixes: string[];
  excluded_paths: string[];
  allowed_methods: string[];
  allowed_check_profile: string;
  authorization_expires_at: string;
  owner_note: string;
  lab_binding: LabBinding | null;
  expired: boolean;
  content_hash: string;
  created_at: string;
  scan_count: number;
}

export interface ExecutionState {
  execution: string;
  execution_enabled: boolean;
  dispatch_implemented: boolean;
  responsible_milestone: string;
  detail: string;
}

export interface ScanView {
  id: string;
  scope_version_id: string;
  target_origin: string;
  profile: string;
  score_version: string;
  status: ScanStatus;
  status_reason: string | null;
  progress_percent: number;
  findings_count: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  execution: ExecutionState;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    // Send the session cookie, and never cache an authorised response.
    credentials: "same-origin",
    cache: "no-store",
    headers: init?.body ? { "content-type": "application/json" } : undefined,
    ...init,
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  const payload: unknown = text ? safeJsonParse(text) : null;

  if (!response.ok) {
    throw new ApiError(response.status, detailOf(payload) ?? response.statusText);
  }
  return payload as T;
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/** FastAPI returns `detail` as a string, or as a list of validation objects. */
function detailOf(payload: unknown): string | null {
  if (payload === null || typeof payload !== "object" || !("detail" in payload)) {
    return null;
  }
  const detail = (payload as { detail: unknown }).detail;
  if (typeof detail === "string") {
    return detail;
  }
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (item !== null && typeof item === "object" && "msg" in item) {
          const loc = "loc" in item && Array.isArray(item.loc) ? item.loc.join(".") : "";
          return `${loc}: ${String((item as { msg: unknown }).msg)}`;
        }
        return JSON.stringify(item);
      })
      .join("; ");
  }
  return null;
}

export const api = {
  saveCredential: (body: {scope_version_id: string; value: string; expires_at: string}) =>
    request<{reference: string; scope_version_id: string; expires_at: string}>("/api/assessments/credentials", {method: "POST", body: JSON.stringify(body)}),
  me: () => request<Operator>("/api/auth/me"),

  login: (username: string, password: string) =>
    request<Operator>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  logout: () => request<void>("/api/auth/logout", { method: "POST" }),

  labServices: () => request<LabService[]>("/api/lab-services"),

  listScopes: () => request<ScopeView[]>("/api/scopes"),

  createLabScope: (body: {
    lab_service: string;
    scheme: string;
    lab_port?: number | undefined;
    owner_note?: string;
    authorization_expires_at: string;
  }) => request<ScopeView>("/api/scopes", { method: "POST", body: JSON.stringify(body) }),

  createProductionScope: (body: {
    host: string;
    scheme: string;
    owner_note?: string;
    authorization_expires_at: string;
  }) => request<ScopeView>("/api/scopes", { method: "POST", body: JSON.stringify(body) }),

  listScans: () => request<ScanView[]>("/api/scans"),

  createScan: (scopeVersionId: string) =>
    request<ScanView>("/api/scans", {
      method: "POST",
      body: JSON.stringify({ scope_version_id: scopeVersionId }),
    }),

  execution: () =>
    request<ExecutionState & { milestone: string; default_profile: string }>(
      "/api/system/execution",
    ),
};

export type HostSource = "crawl" | "link" | "certificate-transparency" | "dns";
// Passive-discovery fields are optional so older API builds still type-check.
export interface HostMetadata {
  sources?: HostSource[];
  observations?: { source: HostSource; observed_at: string; provider: string; wildcard: boolean }[];
  dns_status?: "resolvable" | "unresolved" | "unavailable" | "not_checked";
  dns_addresses?: string[];
  dns_observed_at?: string | null;
}
export interface HostInventoryEntry extends HostMetadata {
  host: string; role: "primary" | "inventory_only"; evidence: string | null;
}
export interface HostDiscoveryCoverage {
  version: string; registrable_domain: string | null; observed_at: string | null;
  state: "complete" | "partial" | "source_unavailable" | "not_applicable" | "not_run";
  coverage_notes: string[]; target_http_requests: number; dns_provider: string;
}
export interface Summary {
  scan_id: string; target_origin: string; profile: string; status: string;
  status_reason: string | null; overall_score: number | null; overall_state: string;
  overall_reason: string; overall_label: string; coverage_percent: number;
  findings_count: number; severity_counts: Record<string, number>; verdict: string;
  reach?: {planned: number; fully_assessed: number; blocked: number; error: number; unassessed: number; not_applicable: number; out_of_profile_categories?: string[]} | null;
  discovery?: {pages_fetched: number; stopped_by: string | null} | null;
}
export interface Finding {
  id: string; check_id: string; title: string; category: string; category_title?: string; severity: string;
  evidence_status: string; confidence: string; confidence_reasons: string[];
  status: string; retest_state: string | null; detail: string; what: string; why: string;
  fix: string; references: string[]; evidence_refs: string[];
  locations: {route: string; parameter: string | null; header: string | null; detail: string}[];
}
export interface CategoryTile {
  category: string; title: string; in_profile: boolean; state: string; score: number | null;
  coverage_percent: number; reason: string; caps_applied: string[];
}
export interface Evidence {
  id: string; origin: string; producer: string; trusted: boolean; content_hash: string;
  content_bytes: number; summary: string; captured_at: string; redaction_state: string;
}
export interface BrowserView {
  context_id: string | null; status: string; actions: number; states: number;
  gaps: Record<string, unknown>[]; evidence_refs: string[]; limitations: string[];
}
export interface ScannerResult {
  tool: string; state: string; version: string; errors: string[];
  not_in_profile_controls?: { check_id: string; state: string; reason: string }[];
  observations: {rule_id: string; title: string; severity?: string; reported_severity?: string | null; evidence: string; locations?: string[]; mapped_control?: string | null}[];
}
export interface ProgressEvent {
  cursor: number; at: string | null; type: string; action: string; outcome: string;
  route?: string; reason?: string; method?: string; allowed?: boolean; status?: string; task_state?: string; logical_id?: string;
  coverage_percent?: number; verdict?: string;
}
export const dashboardApi = {
  summary: (id: string) => request<Summary>(`/api/scans/${id}/summary`),
  scope: (id: string) => request<ScopeView>(`/api/scopes/${id}`),
  findings: (id: string) => request<Finding[]>(`/api/scans/${id}/findings`),
  categories: (id: string) => request<CategoryTile[]>(`/api/scans/${id}/categories`),
  evidence: (id: string) => request<Evidence[]>(`/api/scans/${id}/evidence`),
  browser: (id: string) => request<BrowserView>(`/api/scans/${id}/browser`),
  scanners: (id: string) => request<ScannerResult[]>(`/api/scans/${id}/scanners`),
  hostPriorities: (id: string) => request<HostPriorityPlan>(`/api/scans/${id}/host-priorities`),
  hosts: (id: string) => request<HostInventoryEntry[]>(`/api/scans/${id}/hosts`),
  cancel: (id: string) => request<ScanView>(`/api/scans/${id}/cancel`, {method: 'POST'}),
  retest: (id: string) => request<{scan_id: string}>(`/api/findings/${id}/retest`, {method: 'POST'}),
  register: (body: Record<string, unknown>) => request<ScopeView>('/api/scopes', {method: 'POST', body: JSON.stringify(body)}),
};
export const eventTypes = ['scan.create', 'scan.cancel', 'scan.reconcile', 'task.admit', 'task.settle', 'broker.admit', 'outbox.dispatch', 'evidence.record', 'score.ready', 'retest.request', 'retest.complete', 'browser.open', 'browser.admit', 'browser.complete', 'browser.close', 'model.complete', 'adaptive.plan', 'adaptive.complete'];

// Development-only session bootstrap. Credentials never enter the browser bundle.
let localSession: Promise<void> | null = null;
export function connectLocalWorkspace(): Promise<void> {
  if (!import.meta.env.DEV) return Promise.resolve();
  if (!localSession) localSession = (async () => {
    try { await api.me(); return; } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 401) throw error;
    }
    const response = await fetch('/__local/session', { method: 'POST', credentials: 'same-origin', headers: { 'x-scopelens-local': '1' } });
    if (!response.ok) throw new ApiError(response.status, 'Local workspace session could not be established.');
  })().finally(() => { localSession = null; });
  return localSession;
}

export interface HostPriority {
  host: string;
  owned_domain_match: boolean;
  priority: 'focus' | 'standard' | 'inventory_only';
  rank_points: number;
  evidence_level: 'observed' | 'name_hint_only' | 'unassessed';
  latest_scan_id: string | null;
  latest_scan_status: string | null;
  signals: { code: string; explanation: string; scan_id: string | null }[];
  next_steps: { code: string; description: string; readiness: 'ready_to_plan' | 'needs_review' | 'needs_test_accounts' }[];
}
export interface HostPriorityPlan {
  version: string; revision: string; owned_domains: string[];
  hosts: HostPriority[]; ordering: string; limitation: string; discovery?: HostDiscoveryCoverage;
}
