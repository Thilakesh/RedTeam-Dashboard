const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const TOKEN_KEY = "recon_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T>(
  path: string,
  init: RequestInit & { auth?: boolean } = {},
): Promise<T> {
  const { auth = true, headers, ...rest } = init;
  const h = new Headers(headers);
  h.set("Content-Type", "application/json");
  if (auth) {
    const token = getToken();
    if (token) h.set("Authorization", `Bearer ${token}`);
  }

  const res = await fetch(`${API_URL}${path}`, { ...rest, headers: h });
  if (!res.ok) {
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
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const sseUrl = (path: string): string => {
  const token = getToken();
  const sep = path.includes("?") ? "&" : "?";
  return `${API_URL}${path}${sep}token=${token ?? ""}`;
};

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
  target_authz_verified: boolean;
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

export type VulnScanOut = {
  id: string;
  target_domain: string;
  parent_scan_id: string | null;
  profile: string;
  status: string;
  progress_pct: number;
  intrusive: boolean;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
};

export type VulnScanDetail = VulnScanOut & {
  stages: Array<{
    id: string;
    stage_name: string;
    status: string;
    started_at: string | null;
    finished_at: string | null;
    error: string | null;
  }>;
};

export type VulnOverview = {
  total: number;
  critical: number;
  high: number;
  med: number;
  low: number;
  info: number;
  kev_count: number;
  cve_count: number;
};

export type VulnOut = {
  id: string;
  canonical_key: string;
  title: string;
  severity: string;
  cvss_v3: number | null;
  cve_ids: string[];
  cwe_ids: string[];
  status: string;
  asset_id: string;
  asset_label: string;
  template_id: string | null;
  kev: boolean;
  first_seen: string;
  last_seen: string;
};

export type VulnsPage = {
  total: number;
  items: VulnOut[];
};

export type VulnDiff = {
  counts: { new: number; seen: number; fixed: number };
  new: VulnOut[];
  seen: VulnOut[];
  fixed: VulnOut[];
  has_prior: boolean;
};
