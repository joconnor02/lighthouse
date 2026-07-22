import type { Device } from "../api/client";
import { formatDateTime } from "../lib/time";
import ProgressBar from "./ProgressBar";

interface DeviceTableProps {
  devices: Device[];
  onSelect?: (device: Device) => void;
  onScan?: (device: Device) => void;
  scanBusyByIp?: Record<string, number>;
  scanningIp?: string | null;
  thoroughLabel?: string;
}

export default function DeviceTable({
  devices,
  onSelect,
  onScan,
  scanBusyByIp = {},
  scanningIp = null,
  thoroughLabel = "Scan",
}: DeviceTableProps) {
  if (devices.length === 0) {
    return <div className="card p-6 text-sm text-slate-500">No devices discovered yet.</div>;
  }
  return (
    <div className="card overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-4 py-3">IP</th>
            <th className="px-4 py-3">Hostname</th>
            <th className="px-4 py-3">MAC</th>
            <th className="px-4 py-3">Vendor</th>
            <th className="px-4 py-3">OS guess</th>
            <th className="px-4 py-3 text-right">Open ports</th>
            <th className="px-4 py-3">Last seen</th>
            <th className="px-4 py-3">Scan</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {devices.map((d) => {
            const pct = scanBusyByIp[d.ip];
            const rowBusy = pct !== undefined;
            const thisScanning = scanningIp === d.ip;
            return (
              <tr
                key={d.id}
                className={onSelect ? "cursor-pointer hover:bg-slate-50" : ""}
                onClick={() => onSelect?.(d)}
              >
                <td className="px-4 py-3 font-mono">{d.ip}</td>
                <td className="px-4 py-3">{d.hostname || "—"}</td>
                <td className="px-4 py-3 font-mono text-xs text-slate-600">{d.mac || "—"}</td>
                <td className="px-4 py-3 text-slate-600">{d.vendor || "—"}</td>
                <td className="px-4 py-3 text-slate-600">{d.os_guess || "—"}</td>
                <td className="px-4 py-3 text-right font-semibold">{d.open_port_count}</td>
                <td className="px-4 py-3 text-xs text-slate-500">
                  {formatDateTime(d.last_seen)}
                </td>
                <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                  <div className="flex min-w-[7.5rem] flex-col gap-1">
                    <button
                      type="button"
                      className="btn-ghost px-2 py-1 text-xs"
                      disabled={!onScan || thisScanning || rowBusy}
                      onClick={() => onScan?.(d)}
                    >
                      {thisScanning ? "Starting…" : thoroughLabel}
                    </button>
                    {rowBusy && <ProgressBar value={pct} compact />}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
