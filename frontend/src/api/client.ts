// API client. Reads bearer token from localStorage; if absent, requests are
// unauthenticated (server may allow this when LIGHTHOUSE_AUTH_DISABLED=true).

const TOKEN_KEY = "lighthouse_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  // Always trim — tokens copied from terminal logs often carry a trailing
  // newline or whitespace, which silently breaks the Bearer comparison.
  localStorage.setItem(TOKEN_KEY, token.trim());
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

// Re-arm the auth prompt after the user saves a token on Settings.
export function resetAuthPrompt(): void {
  authPromptConsumed = false;
  authPromptPromise = null;
}

// Shared 401 gate: concurrent failing queries wait on one prompt, then all
// retry (or all fail) together. After cancel/wrong-token, further prompts are
// suppressed until resetAuthPrompt() so we don't loop.
let authPromptPromise: Promise<boolean> | null = null;
let authPromptConsumed = false;

function promptForToken(): Promise<boolean> {
  if (authPromptConsumed && !authPromptPromise) {
    return Promise.resolve(false);
  }
  if (!authPromptPromise) {
    authPromptPromise = Promise.resolve().then(() => {
      const entered = window.prompt(
        "Enter Lighthouse auth token.\n\n" +
          "If you didn't set LIGHTHOUSE_AUTH_TOKEN, the backend printed an " +
          "auto-generated one in its terminal output — look for a line like:\n" +
          "  WARNING ... Using auto-generated auth token ...: auto-XXXX\n\n" +
          "You can also change it later on the Settings page.",
      );
      if (entered) {
        setToken(entered);
        return true;
      }
      return false;
    }).finally(() => {
      authPromptConsumed = true;
      // Let in-flight waiters finish on the same promise, then clear.
      queueMicrotask(() => {
        authPromptPromise = null;
      });
    });
  }
  return authPromptPromise;
}

function formatErrorDetail(detail: unknown, fallback: string): string {
  if (detail == null) return fallback;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object" && "msg" in item) {
          return String((item as { msg: unknown }).msg);
        }
        return JSON.stringify(item);
      })
      .join("; ");
  }
  if (typeof detail === "object") return JSON.stringify(detail);
  return String(detail);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers || {});
  if (!headers.has("Content-Type") && init.body) {
    headers.set("Content-Type", "application/json");
  }
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) {
    const ok = await promptForToken();
    if (ok) {
      return request<T>(path, init);
    }
    throw new Error(
      "Unauthorized. Open the Settings page and paste the correct auth token " +
        "(printed in the backend terminal output on startup).",
    );
  }
  if (!res.ok) {
    let detail: unknown = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? body;
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status}: ${formatErrorDetail(detail, res.statusText)}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export interface Scan {
  id: number;
  started_at: string;
  finished_at: string | null;
  target_cidr: string;
  scan_type: string;
  port_range: string | null;
  status: string;
  error: string | null;
  device_count: number;
  alert_count: number;
}

export interface ScanDetail extends Scan {
  nmap_xml_path: string | null;
  nmap_stdout: string | null;
  progress_log: string;
}

export interface Device {
  id: number;
  ip: string;
  mac: string | null;
  hostname: string | null;
  vendor: string | null;
  os_guess: string | null;
  first_seen: string;
  last_seen: string;
  open_port_count: number;
}

export interface Port {
  id: number;
  port: number;
  protocol: string;
  state: string;
  service: string | null;
  version: string | null;
  first_seen: string;
  last_seen: string;
  scan_id: number | null;
}

export interface DeviceDetail extends Device {
  ports: Port[];
  scan_id: number | null;
}

export interface PortAggregate {
  port: number;
  protocol: string;
  service: string | null;
  version: string | null;
  device_id: number;
  ip: string;
  hostname: string | null;
  last_seen: string;
}

export interface Alert {
  id: number;
  scan_id: number | null;
  device_id: number | null;
  kind: string;
  severity: string;
  detail: Record<string, unknown>;
  acknowledged: boolean;
  created_at: string;
}

export interface Stats {
  device_count: number;
  open_port_count: number;
  unack_alert_count: number;
  last_scan_at: string | null;
  last_scan_status: string | null;
}

export interface Settings {
  default_cidr: string;
  schedule_cron: string;
  port_range: string;
  scan_type: string;
}

export const api = {
  health: () => request<{ status: string }>("/api/health"),
  stats: () => request<Stats>("/api/stats"),
  listScans: () => request<Scan[]>("/api/scans"),
  getScan: (id: number) => request<ScanDetail>(`/api/scans/${id}`),
  createScan: (body: { target: string; scan_type: string; port_range?: string | null }) =>
    request<Scan>("/api/scans", { method: "POST", body: JSON.stringify(body) }),
  listDevices: () => request<Device[]>("/api/devices"),
  getDevice: (id: number) => request<DeviceDetail>(`/api/devices/${id}`),
  listPorts: () => request<PortAggregate[]>("/api/ports"),
  listAlerts: (params: { acknowledged?: boolean; kind?: string } = {}) => {
    const q = new URLSearchParams();
    if (params.acknowledged !== undefined) q.set("acknowledged", String(params.acknowledged));
    if (params.kind) q.set("kind", params.kind);
    const qs = q.toString();
    return request<Alert[]>(`/api/alerts${qs ? `?${qs}` : ""}`);
  },
  acknowledgeAlert: (id: number) => request<Alert>(`/api/alerts/${id}`, { method: "PATCH" }),
  getSettings: () => request<Settings>("/api/settings"),
  updateSettings: (body: Partial<Settings>) =>
    request<Settings>("/api/settings", { method: "PUT", body: JSON.stringify(body) }),
};
