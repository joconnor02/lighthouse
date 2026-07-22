import { useState, useEffect, useRef } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";

interface ScanFormProps {
  defaultTarget?: string;
  defaultPortRange?: string;
  defaultScanType?: string;
  compact?: boolean;
}

export default function ScanForm({
  defaultTarget = "",
  defaultPortRange = "1-1024",
  defaultScanType = "fast",
  compact = false,
}: ScanFormProps) {
  const [target, setTarget] = useState(defaultTarget);
  const [scanType, setScanType] = useState(defaultScanType);
  const [portRange, setPortRange] = useState(defaultPortRange);
  const [err, setErr] = useState("");
  const targetDirty = useRef(false);
  const scanTypeDirty = useRef(false);
  const portRangeDirty = useRef(false);
  const qc = useQueryClient();

  useEffect(() => {
    if (!targetDirty.current) setTarget(defaultTarget);
    if (!scanTypeDirty.current) setScanType(defaultScanType);
    if (!portRangeDirty.current) setPortRange(defaultPortRange);
  }, [defaultTarget, defaultScanType, defaultPortRange]);

  const mutation = useMutation({
    mutationFn: () =>
      api.createScan({
        target,
        scan_type: scanType,
        port_range: portRange || null,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["stats"] });
    },
  });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) {
      setErr("Enter a target CIDR or IP");
      return;
    }
    setErr("");
    mutation.mutate();
  };

  return (
    <form onSubmit={submit} className={compact ? "flex flex-wrap items-end gap-2" : "grid gap-3 sm:grid-cols-4"}>
      <div className={compact ? "" : "sm:col-span-2"}>
        <label className="mb-1 block text-xs font-medium text-slate-600">Target (CIDR or IP)</label>
        <input
          className="input"
          value={target}
          onChange={(e) => {
            targetDirty.current = true;
            setTarget(e.target.value);
            setErr("");
          }}
          placeholder="192.168.1.0/24"
        />
      </div>
      <div>
        <label className="mb-1 block text-xs font-medium text-slate-600">Scan type</label>
        <select
          className="input"
          value={scanType}
          onChange={(e) => {
            scanTypeDirty.current = true;
            setScanType(e.target.value);
          }}
        >
          <option value="fast">fast (host discovery)</option>
          <option value="connect">connect (TCP, no root)</option>
          <option value="syn">syn (needs root)</option>
          <option value="intense">intense (version+OS, root)</option>
        </select>
      </div>
      <div>
        <label className="mb-1 block text-xs font-medium text-slate-600">Port range</label>
        <input
          className="input"
          value={portRange}
          onChange={(e) => {
            portRangeDirty.current = true;
            setPortRange(e.target.value);
          }}
          placeholder="1-1024"
        />
      </div>
      <div className={compact ? "" : "sm:col-span-4"}>
        <button type="submit" className="btn-primary" disabled={mutation.isPending}>
          {mutation.isPending ? "Starting…" : "Run scan"}
        </button>
        {err && <span className="ml-3 text-sm text-rose-600">{err}</span>}
        {mutation.isError && (
          <span className="ml-3 text-sm text-rose-600">{(mutation.error as Error).message}</span>
        )}
        {mutation.isSuccess && (
          <span className="ml-3 text-sm text-emerald-600">Scan queued.</span>
        )}
      </div>
    </form>
  );
}
