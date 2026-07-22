import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Device, type Scan } from "../api/client";
import DeviceTable from "../components/DeviceTable";
import ProgressBar from "../components/ProgressBar";
import QueryError from "../components/QueryError";

function resolveThoroughScanType(settingsType: string | undefined): string {
  if (settingsType === "connect" || settingsType === "syn" || settingsType === "intense") {
    return settingsType;
  }
  return "intense";
}

function scanProgressValue(scan: Scan): number {
  if (scan.status === "done") return 100;
  if (scan.status === "error") return scan.progress_pct ?? 0;
  if (scan.status === "pending") return 0;
  return Math.min(99, scan.progress_pct ?? 0);
}

export default function Devices() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [batchIds, setBatchIds] = useState<number[]>([]);
  const [scanningIp, setScanningIp] = useState<string | null>(null);

  const devicesQuery = useQuery({
    queryKey: ["devices"],
    queryFn: api.listDevices,
    refetchInterval: 15_000,
  });

  const settingsQuery = useQuery({
    queryKey: ["settings"],
    queryFn: api.getSettings,
  });

  const thoroughType = resolveThoroughScanType(settingsQuery.data?.scan_type);
  const portRange = settingsQuery.data?.port_range || "1-1024";

  const scansQuery = useQuery({
    queryKey: ["scans"],
    queryFn: api.listScans,
    refetchInterval: (query) => {
      const rows = query.state.data as Scan[] | undefined;
      const watching = new Set(batchIds);
      const active =
        rows?.some(
          (s) =>
            (s.status === "pending" || s.status === "running") &&
            (watching.size === 0 || watching.has(s.id) || s.scan_type !== "fast"),
        ) ?? false;
      return active || batchIds.length > 0 ? 1_500 : 5_000;
    },
  });

  const scanByIp = useMemo(() => {
    const map: Record<string, number> = {};
    const scans = scansQuery.data || [];
    const batch = new Set(batchIds);

    for (const scan of scans) {
      const inBatch = batch.has(scan.id);
      const active = scan.status === "pending" || scan.status === "running";
      // Show progress for in-flight scans and for the current scan-all batch.
      if (!active && !inBatch) continue;
      if (scan.scan_type === "fast") continue;
      const ip = scan.target_cidr;
      if (!ip || ip.includes("/")) continue;
      const next = scanProgressValue(scan);
      // Prefer the newest matching scan (list is newest-first).
      if (map[ip] === undefined) {
        map[ip] = next;
      }
    }
    return map;
  }, [scansQuery.data, batchIds]);

  const batchProgress = useMemo(() => {
    if (batchIds.length === 0) return null;
    const byId = new Map((scansQuery.data || []).map((s) => [s.id, s]));
    let sum = 0;
    let known = 0;
    let allTerminal = true;
    for (const id of batchIds) {
      const scan = byId.get(id);
      if (!scan) {
        allTerminal = false;
        continue;
      }
      known += 1;
      sum += scanProgressValue(scan);
      if (scan.status === "pending" || scan.status === "running") {
        allTerminal = false;
      }
    }
    if (known === 0) return { pct: 0, done: false };
    return { pct: sum / batchIds.length, done: allTerminal && known === batchIds.length };
  }, [batchIds, scansQuery.data]);

  useEffect(() => {
    if (batchProgress?.done && batchIds.length > 0) {
      setBatchIds([]);
      qc.invalidateQueries({ queryKey: ["devices"] });
      qc.invalidateQueries({ queryKey: ["scans"] });
    }
  }, [batchProgress?.done, batchIds.length, qc]);

  const scanOne = useMutation({
    mutationFn: (device: Device) =>
      api.createScan({
        target: device.ip,
        scan_type: thoroughType,
        port_range: portRange,
      }),
    onMutate: (device) => setScanningIp(device.ip),
    onSuccess: (scan) => {
      setBatchIds((prev) => (prev.includes(scan.id) ? prev : [...prev, scan.id]));
      qc.invalidateQueries({ queryKey: ["scans"] });
    },
    onSettled: () => setScanningIp(null),
  });

  const scanAll = useMutation({
    mutationFn: () =>
      api.scanAllDevices({
        scan_type: thoroughType,
        port_range: portRange,
      }),
    onSuccess: (result) => {
      setBatchIds(result.scans.map((s) => s.id));
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["devices"] });
    },
  });

  const deviceCount = devicesQuery.data?.length ?? 0;
  const scanAllBusy = scanAll.isPending || (batchProgress != null && !batchProgress.done);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Devices</h1>
          <p className="text-sm text-slate-600">
            Host discovery runs on launch and every 5 minutes. Thorough scans use{" "}
            <span className="font-medium">{thoroughType}</span>.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button className="btn-ghost" onClick={() => devicesQuery.refetch()}>
            Refresh
          </button>
          <button
            className="btn-primary"
            disabled={scanAllBusy || deviceCount === 0}
            onClick={() => scanAll.mutate()}
          >
            {scanAll.isPending ? "Starting…" : `Scan all (${thoroughType})`}
          </button>
        </div>
      </div>

      {batchProgress != null && (
        <div className="card space-y-2 p-4">
          <div className="flex items-center justify-between text-sm text-slate-600">
            <span>Scan all progress</span>
            <span className="tabular-nums">{Math.round(batchProgress.pct)}%</span>
          </div>
          <ProgressBar value={batchProgress.pct} />
        </div>
      )}

      {scanAll.isError && (
        <div className="text-sm text-rose-600">{(scanAll.error as Error).message}</div>
      )}
      {scanOne.isError && (
        <div className="text-sm text-rose-600">{(scanOne.error as Error).message}</div>
      )}

      {devicesQuery.isLoading && <div className="card p-6 text-sm text-slate-500">Loading…</div>}
      {devicesQuery.isError && (
        <QueryError error={devicesQuery.error} onRetry={() => devicesQuery.refetch()} />
      )}
      {devicesQuery.data && (
        <DeviceTable
          devices={devicesQuery.data}
          onSelect={(d) => navigate(`/devices/${d.id}`)}
          onScan={(d) => scanOne.mutate(d)}
          scanBusyByIp={scanByIp}
          scanningIp={scanningIp}
          thoroughLabel={`Scan (${thoroughType})`}
        />
      )}
    </div>
  );
}
