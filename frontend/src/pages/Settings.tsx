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
  const [saveMsg, setSaveMsg] = useState("");
  const [wipeConfirm, setWipeConfirm] = useState("");
  const [wipeMsg, setWipeMsg] = useState("");

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

  useEffect(() => {
    if (!wipeMsg) return;
    const t = window.setTimeout(() => setWipeMsg(""), 6000);
    return () => window.clearTimeout(t);
  }, [wipeMsg]);

  const save = useMutation({
    mutationFn: (body: Partial<Settings>) => api.updateSettings(body),
    onSuccess: () => {
      setSaveMsg("Saved.");
      qc.invalidateQueries({ queryKey: ["settings"] });
    },
  });

  const wipe = useMutation({
    mutationFn: () => api.wipeDatabase(),
    onSuccess: (result) => {
      const total = Object.values(result.deleted).reduce((a, b) => a + b, 0);
      setWipeMsg(`Database wiped (${total} rows removed). Settings restored to defaults.`);
      setWipeConfirm("");
      qc.invalidateQueries();
    },
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="text-sm text-slate-600">
          Host discovery runs automatically on launch and every 5 minutes.
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
        <div className="card space-y-4 p-5">
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">
              Host discovery
            </h2>
            <p className="mt-1 text-sm text-slate-600">
              Fast discovery scans this network on launch and every 5 minutes. Discovery itself does
              not open ports — it only finds live hosts.
            </p>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-slate-600">Network CIDR</label>
            <input
              className="input max-w-md"
              value={form.default_cidr}
              onChange={(e) => {
                setForm({ ...form, default_cidr: e.target.value });
                setSaveMsg("");
              }}
              placeholder="192.168.1.0/24"
            />
          </div>

          <label className="flex cursor-pointer items-start gap-3">
            <input
              type="checkbox"
              className="mt-1 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
              checked={form.deep_scan_on_new_device}
              onChange={(e) => {
                setForm({ ...form, deep_scan_on_new_device: e.target.checked });
                setSaveMsg("");
              }}
            />
            <span>
              <span className="block text-sm font-medium text-slate-800">
                Perform deep scan on new device discovery
              </span>
              <span className="mt-0.5 block text-xs text-slate-500">
                When discovery finds a host for the first time, automatically queue a thorough port
                scan using the type and port range below.
              </span>
            </span>
          </label>

          <div className="grid gap-4 border-t border-slate-100 pt-4 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium text-slate-600">
                Deep / thorough scan type
              </label>
              <select
                className="input"
                value={form.scan_type}
                onChange={(e) => {
                  setForm({ ...form, scan_type: e.target.value });
                  setSaveMsg("");
                }}
              >
                <option value="connect">connect (TCP, no root)</option>
                <option value="syn">syn (needs root)</option>
                <option value="intense">intense (version+OS, root)</option>
              </select>
              <p className="mt-1 text-xs text-slate-500">
                Used for Devices Scan / Scan all and for automatic deep scans on new hosts.
              </p>
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
                placeholder="1-1024"
              />
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
            {save.isError && (
              <span className="text-sm text-rose-600">{(save.error as Error).message}</span>
            )}
            {saveMsg && <span className="text-sm text-emerald-600">{saveMsg}</span>}
          </div>
        </div>
      )}

      <div className="card space-y-4 border-rose-200 p-5">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wide text-rose-600">Danger zone</h2>
          <p className="mt-1 text-sm text-slate-600">
            Permanently delete all scans, devices, ports, and alerts. Settings are reset to defaults.
            This cannot be undone.
          </p>
        </div>

        <div className="max-w-md">
          <label className="mb-1 block text-xs font-medium text-slate-600">Are you sure?</label>
          <select
            className="input"
            value={wipeConfirm}
            onChange={(e) => {
              setWipeConfirm(e.target.value);
              setWipeMsg("");
            }}
          >
            <option value="">Select to confirm…</option>
            <option value="no">No, keep my data</option>
            <option value="yes">Yes, permanently wipe the database</option>
          </select>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            className="btn-danger"
            disabled={wipeConfirm !== "yes" || wipe.isPending}
            onClick={() => {
              setWipeMsg("");
              wipe.mutate();
            }}
          >
            {wipe.isPending ? "Wiping…" : "Wipe database"}
          </button>
          {wipe.isError && (
            <span className="text-sm text-rose-600">{(wipe.error as Error).message}</span>
          )}
          {wipeMsg && <span className="text-sm text-emerald-600">{wipeMsg}</span>}
        </div>
      </div>
    </div>
  );
}
