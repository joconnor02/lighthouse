import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import { api } from "../api/client";
import PortBadge from "../components/PortBadge";
import { formatDateTime } from "../lib/time";

export default function DeviceDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const deviceId = Number(id);

  const { data, isLoading, error } = useQuery({
    queryKey: ["device", deviceId],
    queryFn: () => api.getDevice(deviceId),
    enabled: !Number.isNaN(deviceId),
  });

  if (isLoading) return <div className="card p-6 text-sm text-slate-500">Loading…</div>;
  if (error) return <div className="card p-6 text-sm text-rose-600">{(error as Error).message}</div>;
  if (!data) return null;

  // Group ports by scan_id to build a per-scan bar chart of open port counts.
  const byScan = new Map<number, number>();
  for (const p of data.ports) {
    if (p.state !== "open") continue;
    const key = p.scan_id ?? 0;
    byScan.set(key, (byScan.get(key) ?? 0) + 1);
  }
  const chartData = Array.from(byScan.entries())
    .map(([scanId, count]) => ({ scan: `#${scanId}`, count }))
    .sort((a, b) => a.scan.localeCompare(b.scan, undefined, { numeric: true }));

  return (
    <div className="space-y-4">
      <button className="btn-ghost text-sm" onClick={() => navigate("/devices")}>
        ← Back to devices
      </button>
      <div className="card p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <div>
            <div className="font-mono text-xl font-semibold">{data.ip}</div>
            <div className="text-sm text-slate-600">
              {data.hostname || "no hostname"} · {data.mac || "no MAC"} · {data.vendor || "unknown vendor"}
            </div>
          </div>
          <div className="text-sm text-slate-500">
            first seen {formatDateTime(data.first_seen)} · last seen{" "}
            {formatDateTime(data.last_seen)}
          </div>
        </div>
      </div>

      <div className="card p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">
          Open ports per scan
        </h2>
        {chartData.length === 0 ? (
          <div className="text-sm text-slate-500">No open ports recorded.</div>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="scan" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="count" fill="#2f6fed" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="card overflow-hidden">
        <div className="border-b border-slate-100 px-4 py-3 text-sm font-semibold">
          Port history ({data.ports.length})
        </div>
        {data.ports.length === 0 ? (
          <div className="p-4 text-sm text-slate-500">No ports recorded.</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-2">Port</th>
                <th className="px-4 py-2">State</th>
                <th className="px-4 py-2">Service</th>
                <th className="px-4 py-2">Version</th>
                <th className="px-4 py-2">Scan</th>
                <th className="px-4 py-2">Last seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {data.ports.map((p) => (
                <tr key={p.id}>
                  <td className="px-4 py-2">
                    <PortBadge port={p.port} protocol={p.protocol} state={p.state} service={p.service} />
                  </td>
                  <td className="px-4 py-2 text-slate-600">{p.state}</td>
                  <td className="px-4 py-2 text-slate-600">{p.service || "—"}</td>
                  <td className="px-4 py-2 text-slate-600">{p.version || "—"}</td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-500">#{p.scan_id ?? "—"}</td>
                  <td className="px-4 py-2 text-xs text-slate-500">
                    {formatDateTime(p.last_seen)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
