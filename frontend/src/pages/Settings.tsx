import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Settings, getToken, setToken, resetAuthPrompt } from "../api/client";

export default function SettingsPage() {
  const qc = useQueryClient();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["settings"],
    queryFn: api.getSettings,
  });
  const [form, setForm] = useState<Settings | null>(null);
  const [tokenInput, setTokenInput] = useState(getToken() || "");
  const [tokenMsg, setTokenMsg] = useState("");
  const [cronHelp, setCronHelp] = useState("");
  const [saveMsg, setSaveMsg] = useState("");

  useEffect(() => {
    if (data) setForm(data);
  }, [data]);

  useEffect(() => {
    // Keep the input in sync if another flow (401 prompt) wrote localStorage.
    setTokenInput(getToken() || "");
  }, [data]);

  useEffect(() => {
    if (!tokenMsg) return;
    const t = window.setTimeout(() => setTokenMsg(""), 4000);
    return () => window.clearTimeout(t);
  }, [tokenMsg]);

  useEffect(() => {
    if (!saveMsg) return;
    const t = window.setTimeout(() => setSaveMsg(""), 4000);
    return () => window.clearTimeout(t);
  }, [saveMsg]);

  const save = useMutation({
    mutationFn: (body: Partial<Settings>) => api.updateSettings(body),
    onSuccess: () => {
      setSaveMsg("Saved.");
      qc.invalidateQueries({ queryKey: ["settings"] });
    },
  });

  const setCronPreset = (preset: string) => {
    if (!form) return;
    setForm({ ...form, schedule_cron: preset });
    setSaveMsg("");
    setCronHelp(
      preset === ""
        ? "Additional schedule off — automatic host discovery still runs every 5 minutes."
        : preset === "*/5 * * * *"
          ? "Additional deeper scan every 5 minutes (uses scan type below)."
          : preset === "0 * * * *"
            ? "Additional deeper scan every hour."
            : preset === "0 3 * * *"
              ? "Additional deeper scan daily at 3:00 AM."
              : preset === "*/30 * * * *"
                ? "Additional deeper scan every 30 minutes."
                : "",
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="text-sm text-slate-600">
          Defaults for scans. Host discovery runs automatically on launch and every 5 minutes.
        </p>
      </div>

      <div className="card p-5">
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-500">
          Auth token
        </h2>
        <p className="mb-3 text-sm text-slate-600">
          Stored in your browser's localStorage and sent as a Bearer token. Set{" "}
          <code className="rounded bg-slate-100 px-1">LIGHTHOUSE_AUTH_TOKEN</code> in the backend{" "}
          <code className="rounded bg-slate-100 px-1">.env</code>.
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <input
            className="input"
            value={tokenInput}
            onChange={(e) => {
              setTokenInput(e.target.value);
              setTokenMsg("");
            }}
            placeholder="paste token"
          />
          <button
            className="btn-primary"
            disabled={!tokenInput.trim()}
            onClick={async () => {
              const trimmed = tokenInput.trim();
              if (!trimmed) return;
              setToken(trimmed);
              resetAuthPrompt();
              setTokenMsg("Token saved — refreshing…");
              try {
                await qc.invalidateQueries();
                await api.getSettings();
                setTokenMsg("Token saved.");
              } catch (e) {
                setTokenMsg("");
                // Leave query errors visible below; re-arm so user can retry prompt.
                resetAuthPrompt();
              }
            }}
          >
            Save token
          </button>
          {tokenMsg && <span className="text-sm text-emerald-600">{tokenMsg}</span>}
        </div>
      </div>

      {isError && (
        <div className="card p-4 text-sm text-rose-700 bg-rose-50">
          <p>{(error as Error).message}</p>
          <p className="mt-2">
            Paste your token in the Auth token section above and click Save token to retry.
          </p>
        </div>
      )}

      {isLoading && !data && !isError && (
        <div className="card p-6 text-sm text-slate-500">Loading…</div>
      )}

      {form && (
        <div className="card p-5 space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-600">Default CIDR</label>
              <input
                className="input"
                value={form.default_cidr}
                onChange={(e) => {
                  setForm({ ...form, default_cidr: e.target.value });
                  setSaveMsg("");
                }}
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-600">Port range</label>
              <input
                className="input"
                value={form.port_range}
                onChange={(e) => {
                  setForm({ ...form, port_range: e.target.value });
                  setSaveMsg("");
                }}
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-600">Scan type</label>
              <select
                className="input"
                value={form.scan_type}
                onChange={(e) => {
                  setForm({ ...form, scan_type: e.target.value });
                  setSaveMsg("");
                }}
              >
                <option value="fast">fast (host discovery)</option>
                <option value="connect">connect (TCP, no root)</option>
                <option value="syn">syn (needs root)</option>
                <option value="intense">intense (version+OS, root)</option>
              </select>
              <p className="mt-1 text-xs text-slate-500">
                Devices thorough Scan / Scan all use this type when it is connect, syn, or intense;
                otherwise they default to intense.
              </p>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-600">
                Additional schedule (cron, empty = off)
              </label>
              <input
                className="input"
                value={form.schedule_cron}
                onChange={(e) => {
                  setForm({ ...form, schedule_cron: e.target.value });
                  setSaveMsg("");
                }}
                placeholder="0 3 * * *"
              />
              <p className="mt-1 text-xs text-slate-500">
                Optional deeper scans using the CIDR, scan type, and port range above. Automatic
                host discovery is always on.
              </p>
              <div className="mt-1 flex flex-wrap gap-1 text-xs">
                <button type="button" className="btn-ghost px-2 py-1" onClick={() => setCronPreset("")}>
                  off
                </button>
                <button
                  type="button"
                  className="btn-ghost px-2 py-1"
                  onClick={() => setCronPreset("*/5 * * * *")}
                >
                  every 5m
                </button>
                <button
                  type="button"
                  className="btn-ghost px-2 py-1"
                  onClick={() => setCronPreset("*/30 * * * *")}
                >
                  every 30m
                </button>
                <button
                  type="button"
                  className="btn-ghost px-2 py-1"
                  onClick={() => setCronPreset("0 * * * *")}
                >
                  hourly
                </button>
                <button
                  type="button"
                  className="btn-ghost px-2 py-1"
                  onClick={() => setCronPreset("0 3 * * *")}
                >
                  daily 3am
                </button>
              </div>
              {cronHelp && <div className="mt-1 text-xs text-slate-500">{cronHelp}</div>}
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              className="btn-primary"
              onClick={() => {
                setSaveMsg("");
                save.mutate(form);
              }}
              disabled={save.isPending}
            >
              {save.isPending ? "Saving…" : "Save settings"}
            </button>
            {save.isError && <span className="text-sm text-rose-600">{(save.error as Error).message}</span>}
            {saveMsg && <span className="text-sm text-emerald-600">{saveMsg}</span>}
          </div>
        </div>
      )}
    </div>
  );
}
