import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import StatCard from "../components/StatCard";
import AlertRow from "../components/AlertRow";
import ScanForm from "../components/ScanForm";
import { formatDateTime } from "../lib/time";

export default function Dashboard() {
  const stats = useQuery({ queryKey: ["stats"], queryFn: api.stats, refetchInterval: 5_000 });
  const alerts = useQuery({
    queryKey: ["alerts", { acknowledged: false }],
    queryFn: () => api.listAlerts({ acknowledged: false }),
    refetchInterval: 10_000,
  });
  const settings = useQuery({ queryKey: ["settings"], queryFn: api.getSettings });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="text-sm text-slate-600">
          Quick view of your network. Run a scan to populate data.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Devices" value={stats.data?.device_count ?? null} />
        <StatCard label="Open ports" value={stats.data?.open_port_count ?? null} />
        <StatCard
          label="Unacked alerts"
          value={stats.data?.unack_alert_count ?? null}
          accent={stats.data?.unack_alert_count ? "warn" : "default"}
        />
        <StatCard
          label="Last scan"
          value={formatDateTime(stats.data?.last_scan_at)}
          hint={stats.data?.last_scan_status ? `status: ${stats.data.last_scan_status}` : undefined}
        />
      </div>

      <div className="card p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">
          Run a scan
        </h2>
        <ScanForm
          defaultTarget={settings.data?.default_cidr || ""}
          defaultPortRange={settings.data?.port_range || "1-1024"}
          defaultScanType={settings.data?.scan_type || "fast"}
        />
      </div>

      <div className="card">
        <div className="border-b border-slate-100 px-4 py-3 text-sm font-semibold">Recent alerts</div>
        {alerts.isLoading && <div className="p-4 text-sm text-slate-500">Loading…</div>}
        {alerts.data && alerts.data.length === 0 && (
          <div className="p-4 text-sm text-slate-500">No unacknowledged alerts.</div>
        )}
        {alerts.data?.map((a) => <AlertRow key={a.id} alert={a} />)}
      </div>
    </div>
  );
}
