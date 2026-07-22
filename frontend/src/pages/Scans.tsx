import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Scan } from "../api/client";
import ScanForm from "../components/ScanForm";
import { formatDateTime } from "../lib/time";

const STATUS_BADGE: Record<string, string> = {
  pending: "bg-slate-100 text-slate-700",
  running: "bg-blue-100 text-blue-800",
  done: "bg-emerald-100 text-emerald-800",
  error: "bg-rose-100 text-rose-800",
};

export default function Scans() {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState<number | null>(null);
  const settings = useQuery({ queryKey: ["settings"], queryFn: api.getSettings });
  const list = useQuery({
    queryKey: ["scans"],
    queryFn: api.listScans,
    refetchInterval: 5_000,
  });
  const detail = useQuery({
    queryKey: ["scan", expanded],
    queryFn: () => api.getScan(expanded!),
    enabled: expanded != null,
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Scans</h1>
        <p className="text-sm text-slate-600">
          Trigger a new scan or inspect past results.{" "}
          <span className="text-slate-400">Times shown in America/New_York.</span>
        </p>
      </div>

      <div className="card p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">
          New scan
        </h2>
        <ScanForm
          defaultTarget={settings.data?.default_cidr || ""}
          defaultPortRange={settings.data?.port_range || "1-1024"}
          defaultScanType={settings.data?.scan_type || "fast"}
        />
      </div>

      <div className="card overflow-hidden">
        <div className="border-b border-slate-100 px-4 py-3 text-sm font-semibold">Scan history</div>
        {list.isLoading && <div className="p-4 text-sm text-slate-500">Loading…</div>}
        {list.data && list.data.length === 0 && (
          <div className="p-4 text-sm text-slate-500">No scans yet.</div>
        )}
        <table className="w-full text-sm">
          <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-2">ID</th>
              <th className="px-4 py-2">Target</th>
              <th className="px-4 py-2">Type</th>
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2 text-right">Devices</th>
              <th className="px-4 py-2 text-right">Alerts</th>
              <th className="px-4 py-2">Started</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {list.data?.map((s: Scan) => (
              <>
                <tr
                  key={s.id}
                  className="cursor-pointer hover:bg-slate-50"
                  onClick={() => setExpanded(expanded === s.id ? null : s.id)}
                >
                  <td className="px-4 py-2 font-mono">#{s.id}</td>
                  <td className="px-4 py-2 font-mono">{s.target_cidr}</td>
                  <td className="px-4 py-2">{s.scan_type}</td>
                  <td className="px-4 py-2">
                    <span className={`badge ${STATUS_BADGE[s.status] || STATUS_BADGE.pending}`}>
                      {s.status}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-right">{s.device_count}</td>
                  <td className="px-4 py-2 text-right">{s.alert_count}</td>
                  <td className="px-4 py-2 text-xs text-slate-500">
                    {formatDateTime(s.started_at)}
                  </td>
                </tr>
                {expanded === s.id && (
                  <tr key={`${s.id}-detail`}>
                    <td colSpan={7} className="bg-slate-50 px-4 py-3">
                      {detail.isLoading && <div className="text-sm text-slate-500">Loading…</div>}
                      {detail.data?.error && (
                        <div className="mb-2 text-sm text-rose-600">Error: {detail.data.error}</div>
                      )}
                      {detail.data?.nmap_stdout && (
                        <pre className="max-h-80 overflow-auto rounded bg-slate-900 p-3 text-xs text-slate-100">
                          {detail.data.nmap_stdout}
                        </pre>
                      )}
                      {!detail.data?.nmap_stdout && detail.data && (
                        <div className="text-sm text-slate-500">
                          Scan {detail.data.status}. No raw nmap output captured.
                        </div>
                      )}
                      <button
                        className="btn-ghost mt-3 text-xs"
                        onClick={() => qc.invalidateQueries({ queryKey: ["scans"] })}
                      >
                        Refresh list
                      </button>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
