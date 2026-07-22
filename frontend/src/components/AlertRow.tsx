import type { Alert } from "../api/client";

interface AlertRowProps {
  alert: Alert;
  onAcknowledge?: (alert: Alert) => void;
}

const SEVERITY: Record<string, string> = {
  info: "bg-slate-100 text-slate-700",
  warn: "bg-amber-100 text-amber-800",
  critical: "bg-rose-100 text-rose-800",
};

const KIND_LABEL: Record<string, string> = {
  new_device: "New device",
  new_port: "New open port",
  port_closed: "Port closed",
};

export default function AlertRow({ alert, onAcknowledge }: AlertRowProps) {
  const d = alert.detail as Record<string, unknown>;
  const summary =
    alert.kind === "new_device"
      ? `${d.ip}${d.hostname ? ` (${d.hostname})` : ""}${d.vendor ? ` — ${d.vendor}` : ""}`
      : alert.kind === "new_port"
        ? `${d.ip}:${d.port}/${d.protocol}${d.service ? ` (${d.service})` : ""}`
        : alert.kind === "port_closed"
          ? `${d.ip}:${d.port}/${d.protocol} closed`
          : JSON.stringify(d);

  return (
    <div className="flex items-start justify-between gap-3 border-b border-slate-100 px-4 py-3 last:border-0">
      <div className="flex items-start gap-3">
        <span className={`badge mt-0.5 ${SEVERITY[alert.severity] || SEVERITY.info}`}>
          {KIND_LABEL[alert.kind] || alert.kind}
        </span>
        <div>
          <div className="text-sm font-mono">{summary}</div>
          <div className="text-xs text-slate-500">{new Date(alert.created_at).toLocaleString()}</div>
        </div>
      </div>
      {onAcknowledge && !alert.acknowledged && (
        <button className="btn-ghost text-xs" onClick={() => onAcknowledge(alert)}>
          Acknowledge
        </button>
      )}
      {alert.acknowledged && <span className="badge bg-slate-100 text-slate-500">ack</span>}
    </div>
  );
}
