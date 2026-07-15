import { genRequestId, logger } from "./logger";

export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const CSRF_COOKIE = "rt_csrf";
const REQUEST_ID_HEADER = "X-Request-ID";

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.split("=")[1]) : null;
}

export function getCsrfToken(): string | null {
  return readCookie(CSRF_COOKIE);
}

export class ApiError extends Error {
  constructor(public status: number, message: string, public requestId?: string) {
    super(message);
  }
}

async function parseError(res: Response): Promise<ApiError> {
  let detail = res.statusText;
  try {
    const body = await res.json();
    if (typeof body.detail === "string") {
      detail = body.detail;
    } else if (Array.isArray(body.detail)) {
      detail = body.detail
        .map((e: { loc?: unknown[]; msg?: string }) => {
          const field = Array.isArray(e.loc) ? e.loc.slice(1).join(".") : "";
          return field ? `${field}: ${e.msg}` : e.msg;
        })
        .join("; ");
    }
  } catch {}
  const requestId = res.headers.get(REQUEST_ID_HEADER) ?? undefined;
  return new ApiError(res.status, detail, requestId);
}

async function doFetch(
  path: string,
  init: RequestInit & { _retry?: boolean } = {},
): Promise<Response> {
  const { headers, _retry: _ignored, ...rest } = init;
  const h = new Headers(headers);
  if (!h.has("Content-Type") && init.body) h.set("Content-Type", "application/json");
  if (!h.has(REQUEST_ID_HEADER)) h.set(REQUEST_ID_HEADER, genRequestId());
  const method = (init.method || "GET").toUpperCase();
  if (!SAFE_METHODS.has(method)) {
    const csrf = getCsrfToken();
    if (csrf) h.set("X-CSRF-Token", csrf);
  }
  return fetch(`${API_URL}${path}`, {
    ...rest,
    headers: h,
    credentials: "include",
  });
}

let refreshInFlight: Promise<boolean> | null = null;

async function tryRefresh(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = (async () => {
    try {
      const res = await doFetch("/auth/refresh", { method: "POST" });
      return res.ok;
    } catch {
      return false;
    } finally {
      // allow next failure to attempt refresh again
      setTimeout(() => {
        refreshInFlight = null;
      }, 0);
    }
  })();
  return refreshInFlight;
}

export async function api<T>(
  path: string,
  init: RequestInit & { auth?: boolean; skipRefresh?: boolean } = {},
): Promise<T> {
  const { auth: _auth, skipRefresh, ...rest } = init;
  let res = await doFetch(path, rest);

  if (res.status === 401 && !skipRefresh && path !== "/auth/refresh" && path !== "/auth/login") {
    const refreshed = await tryRefresh();
    if (refreshed) {
      res = await doFetch(path, rest);
    } else if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login") && !window.location.pathname.startsWith("/accept-invite")) {
      window.location.assign("/login");
    }
  }

  if (!res.ok) {
    const err = await parseError(res);
    logger.error("api request failed", {
      path,
      status: err.status,
      request_id: err.requestId,
    });
    throw err;
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const sseUrl = (path: string): string => {
  // Cookies travel with EventSource natively (same-origin or CORS w/ credentials);
  // no token query param needed under the new cookie-based auth.
  return `${API_URL}${path}`;
};

// ----- /auth/me + login/logout typed helpers (used by auth-context) -----

export type Me = {
  id: string;
  email: string;
  role: "admin" | "analyst";
  org_id: string;
  features: string[];
};

export type LoginResponse = { csrf_token: string; user: Me };

export async function login(email: string, password: string): Promise<LoginResponse> {
  return api<LoginResponse>("/auth/login", {
    method: "POST",
    skipRefresh: true,
    body: JSON.stringify({ email, password }),
  });
}

export async function logout(): Promise<void> {
  await api<void>("/auth/logout", { method: "POST" });
}

export async function fetchMe(): Promise<Me> {
  return api<Me>("/auth/me", { skipRefresh: false });
}

export async function acceptInvite(token: string, password: string): Promise<LoginResponse> {
  return api<LoginResponse>("/auth/invite/accept", {
    method: "POST",
    skipRefresh: true,
    body: JSON.stringify({ token, password }),
  });
}

export type Scan = {
  id: string;
  domain: string;
  profile: string;
  status: "queued" | "created" | "running" | "completed" | "failed" | "stopped";
  progress_pct: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
};

export type ScanStage = {
  id: string;
  stage_name: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
};

export type ScanDetail = Scan & { stages: ScanStage[] };

export type Asset = {
  id: string;
  type: string;
  canonical_key: string;
  attributes: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
};

export type SubdomainRow = {
  asset_id: string;
  subdomain: string;
  http_status: number | null;
  title: string | null;
  redirect: boolean;
  final_url: string | null;
  location: string | null;
  ip_tag: string | null;
  primary_ip: string | null;
  all_ips: string[];
  cdn: boolean;
  cdn_name: string | null;
  cname: string | null;
  cnames: string[];
  waf: string | null;
  waf_conf: "NONE" | "LOW" | "MED" | "HIGH" | null;
  asn: string | null;
  org: string | null;
  country: string | null;
  country_name: string | null;
  city: string | null;
  server: string | null;
  tech: string[];
  url: string | null;
  open_ports: string[];
  sources: string[];
  screenshot_url: string | null;
  first_seen: string;
  last_seen: string;
};

export type SubdomainsPage = {
  rows: SubdomainRow[];
  total: number;
  page: number;
  limit: number;
};

export type IpRow = {
  asset_id: string;
  ip: string;
  subdomain_count: number;
  asn: string | null;
  org: string | null;
  country: string | null;
  city: string | null;
  resolves: string[];
};

export type CountBucket = { label: string; count: number };

export type TechBucket = { label: string; count: number; subdomains: string[] };

export type ScanOverview = {
  subdomain_count: number;
  ip_count: number;
  cdn_count: number;
  waf_count: number;
  tech_count: number;
  http_status_buckets: CountBucket[];
  top_tech: CountBucket[];
  top_asn: CountBucket[];
  top_cdn: CountBucket[];
};

export type CdnWafSummary = {
  behind_cdn_pct: number;
  behind_waf_pct: number;
  cdn_breakdown: CountBucket[];
  waf_breakdown: CountBucket[];
  unprotected_origins: string[];
};

export type PortRow = {
  asset_id: string;
  host: string;
  port: number;
  proto: string;
  state: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
};

export type PortsPage = {
  rows: PortRow[];
  total: number;
  page: number;
  limit: number;
};

export type FindingRow = {
  finding_id: string;
  asset_id: string;
  fqdn: string;
  severity: "HIGH" | "MED" | "LOW" | "INFO";
  priority_rank: number;
  risk_score: number;
  rationale: string;
  signals: string[];
  recommended_action: string;
  source: string;
};

export type FindingsPage = {
  total: number;
  items: FindingRow[];
  severity_counts: Record<string, number>;
};

export async function startScan(scanId: string): Promise<Scan> {
  return api<Scan>(`/scans/${scanId}/start`, { method: "POST" });
}

export async function stopScan(scanId: string): Promise<Scan> {
  return api<Scan>(`/scans/${scanId}/stop`, { method: "POST" });
}

export async function patchScan(scanId: string, profile: string): Promise<Scan> {
  return api<Scan>(`/scans/${scanId}`, {
    method: "PATCH",
    body: JSON.stringify({ profile }),
  });
}

export async function deleteScan(scanId: string): Promise<void> {
  await api<void>(`/scans/${scanId}`, { method: "DELETE" });
}

export async function deleteWorkspace(workspaceId: string): Promise<void> {
  await api<void>(`/target-workspaces/${workspaceId}`, { method: "DELETE" });
}

export async function deleteInvestigationTask(
  workspaceId: string,
  taskId: string,
): Promise<void> {
  await api<void>(
    `/target-workspaces/${workspaceId}/tasks/${taskId}`,
    { method: "DELETE" },
  );
}

// Inactive states where a record can be deleted safely.
export const DELETABLE_SCAN_STATUSES = new Set([
  "queued", "completed", "failed", "stopped", "cancelled",
]);

export function canDeleteScan(status: string): boolean {
  return DELETABLE_SCAN_STATUSES.has(status);
}

// Target Workspace
export type WorkspaceOut = {
  id: string;
  label: string;
  target_id: string;
  target_domain: string;
  parent_scan_id: string | null;
  status: string;
  created_at: string;
};

export type WorkspaceListRow = {
  id: string;
  label: string;
  target_id: string;
  target_domain: string;
  parent_scan_id: string | null;
  asset_count: number;
  task_count: number;
  status: string;
  created_at: string;
};

export type WorkspaceOverview = {
  total_subdomains: number;
  alive_hosts: number;
  ports_identified: number;
  running_tasks: number;
  findings_count: number;
  hvt_count: number;
  hvt_signal_summary: Record<string, number>;
};

export type WorkspaceScanEntry = {
  task_id: string;
  tool: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_s: number | null;
};

export type WorkspaceSubdomainIpRow = {
  asset_id: string;
  ip: string;
  scans: WorkspaceScanEntry[];
};

export type WorkspaceSubdomainRow = {
  asset_id: string;
  fqdn: string;
  alive: boolean;
  ports: number[];
  technologies: string[];
  has_http: boolean;
  has_https: boolean;
  available_tools: string[];
  tools_run: string[];
  hvt_signals: string[];
  ips: WorkspaceSubdomainIpRow[];
  scans: WorkspaceScanEntry[];
};

export type WorkspaceSubdomainsResponse = {
  rows: WorkspaceSubdomainRow[];
};

export type InvestigationTaskOut = {
  id: string;
  workspace_id: string;
  asset_id: string;
  asset_label: string;
  tool: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  progress_pct: number;
  duration_s: number | null;
  raw_output_present: boolean;
  exit_code: number | null;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
};

export type InvestigationTasksResponse = {
  rows: InvestigationTaskOut[];
};

export type InvestigationFindingOut = {
  id: string;
  task_id: string;
  asset_id: string;
  kind: string;
  severity: string;
  title: string;
  description: string | null;
  evidence: Record<string, unknown>;
  created_at: string;
};

export type InvestigationTaskDetailOut = {
  task: InvestigationTaskOut;
  findings: InvestigationFindingOut[];
  raw_output: string | null;
  stderr: string | null;
  stdout_url: string | null;
  stderr_url: string | null;
};

export const TOOL_LABELS: Record<string, string> = {
  nmap_deep: "Nmap Deep Scan",
  ffuf: "FFUF",
  dirsearch: "Dirsearch",
  testssl: "TestSSL",
};

export type ScanProfileSpec = {
  id: string;
  label: string;
  args: string[];
  description: string;
};

export type ToolProfileBundle = {
  binary: string;
  default: string;
  profiles: ScanProfileSpec[];
};

export type ScanProfilesCatalog = Record<string, ToolProfileBundle>;

export async function getScanProfiles(): Promise<ScanProfilesCatalog> {
  return api<ScanProfilesCatalog>("/target-workspaces/scan-profiles");
}

export async function createWorkspace(parent_scan_id: string): Promise<WorkspaceOut> {
  return api<WorkspaceOut>("/target-workspaces", {
    method: "POST",
    body: JSON.stringify({ parent_scan_id }),
  });
}

export async function listWorkspaces(): Promise<WorkspaceListRow[]> {
  return api<WorkspaceListRow[]>("/target-workspaces");
}

export async function getWorkspace(id: string): Promise<WorkspaceOut> {
  return api<WorkspaceOut>(`/target-workspaces/${id}`);
}

export async function getWorkspaceOverview(id: string): Promise<WorkspaceOverview> {
  return api<WorkspaceOverview>(`/target-workspaces/${id}/overview`);
}

export async function getWorkspaceSubdomains(
  id: string,
): Promise<WorkspaceSubdomainsResponse> {
  return api<WorkspaceSubdomainsResponse>(`/target-workspaces/${id}/subdomains`);
}

export async function listWorkspaceTasks(
  id: string,
): Promise<InvestigationTasksResponse> {
  return api<InvestigationTasksResponse>(`/target-workspaces/${id}/tasks`);
}

export async function createInvestigationTask(
  workspace_id: string,
  body: { asset_id: string; tool: string; params?: Record<string, unknown> },
): Promise<InvestigationTaskOut> {
  return api<InvestigationTaskOut>(`/target-workspaces/${workspace_id}/tasks`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function getInvestigationTask(
  workspace_id: string,
  task_id: string,
): Promise<InvestigationTaskDetailOut> {
  return api<InvestigationTaskDetailOut>(
    `/target-workspaces/${workspace_id}/tasks/${task_id}`,
  );
}

// --- Operations Console (standalone manual ops) ------------------------------

export type OperationStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export type Operation = {
  id: string;
  target: string;
  target_type: string;
  tool: string;
  profile: string | null;
  protocol: string | null;
  custom_args: string | null;
  generated_command: string | null;
  status: OperationStatus;
  progress_pct: number;
  duration_s: number | null;
  raw_output_present: boolean;
  exit_code: number | null;
  error: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
};

export type OperationsResponse = { rows: Operation[] };

export type OperationFinding = {
  id: string;
  operation_id: string;
  kind: string;
  severity: string;
  title: string;
  description: string | null;
  evidence: Record<string, unknown>;
  created_at: string;
};

export type OperationDetail = {
  operation: Operation;
  findings: OperationFinding[];
  raw_output: string | null;
  stderr: string | null;
  stdout_url: string | null;
  stderr_url: string | null;
};

export type OperationRequest = {
  target_type: "domain" | "ipv4";
  target: string;
  tool: string;
  profile?: string | null;
  protocol?: "http" | "https" | null;
  custom_args?: string | null;
};

export async function previewOperation(
  body: OperationRequest,
): Promise<{ generated_command: string }> {
  return api<{ generated_command: string }>("/operations/preview", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function createOperation(body: OperationRequest): Promise<Operation> {
  return api<Operation>("/operations", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function listOperations(): Promise<OperationsResponse> {
  return api<OperationsResponse>("/operations");
}

export async function getOperation(operation_id: string): Promise<OperationDetail> {
  return api<OperationDetail>(`/operations/${operation_id}`);
}

export async function cancelOperation(operation_id: string): Promise<Operation> {
  return api<Operation>(`/operations/${operation_id}/cancel`, { method: "POST" });
}

export async function retryOperation(operation_id: string): Promise<Operation> {
  return api<Operation>(`/operations/${operation_id}/retry`, { method: "POST" });
}

// --- Dashboard ----------------------------------------------------------------

export type ScanActivityDay = { day: string; completed: number };

export type RecentScanRow = {
  id: string;
  domain: string;
  profile: string;
  status: string;
  progress_pct: number;
  created_at: string;
};

export type TopFindingRow = {
  scan_id: string;
  fqdn: string;
  severity: string;
  risk_score: number;
  rationale: string;
};

export type DashboardSummary = {
  active_scans: number;
  assets_tracked: number;
  open_findings: number;
  workspaces: number;
  severity_counts: Record<string, number>;
  scan_activity: ScanActivityDay[];
  recent_scans: RecentScanRow[];
  top_findings: TopFindingRow[];
};

export async function getDashboardSummary(): Promise<DashboardSummary> {
  return api<DashboardSummary>("/dashboard/summary");
}

// --- Admin: OpenRouter settings ----------------------------------------------

export type OpenRouterSettings = {
  api_key_set: boolean;
  api_key_hint: string | null;
  default_model: string;
};

export type OpenRouterTestResult = {
  status: "connected" | "invalid_key" | "connection_failed";
  detail: string | null;
};

export const OPENROUTER_PRESET_MODELS = [
  "deepseek/deepseek-v4-flash",
  "openai/gpt-4o",
  "anthropic/claude-3.7-sonnet",
  "google/gemini-2.5-pro",
];

export async function getOpenRouterSettings(): Promise<OpenRouterSettings> {
  return api<OpenRouterSettings>("/admin/settings/openrouter");
}

export async function updateOpenRouterSettings(body: {
  api_key?: string | null;
  default_model?: string | null;
}): Promise<OpenRouterSettings> {
  return api<OpenRouterSettings>("/admin/settings/openrouter", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function testOpenRouterConnection(body: {
  api_key?: string | null;
  default_model?: string | null;
}): Promise<OpenRouterTestResult> {
  return api<OpenRouterTestResult>("/admin/settings/openrouter/test", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

// --- Admin: tool execution logs (Phase 5 — Postgres-only, tenant-scoped) -----

export type ToolExecutionOut = {
  id: string;
  source: "operation" | "investigation_task" | "scan_stage";
  tool: string;
  target: string | null;
  status: string;
  exit_code: number | null;
  error: string | null;
  stderr_preview: string | null;
  stdout_url: string | null;
  stderr_url: string | null;
  org_id: string;
  created_at: string;
};

export async function listToolExecutions(params: {
  tool?: string;
  status?: string;
  from?: string;
  to?: string;
}): Promise<ToolExecutionOut[]> {
  const qs = new URLSearchParams();
  if (params.tool) qs.set("tool", params.tool);
  if (params.status) qs.set("status", params.status);
  if (params.from) qs.set("from", params.from);
  if (params.to) qs.set("to", params.to);
  const query = qs.toString();
  return api<ToolExecutionOut[]>(`/admin/logs/tool-executions${query ? `?${query}` : ""}`);
}
