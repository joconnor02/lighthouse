import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import AlertRow from "../components/AlertRow";
import QueryError from "../components/QueryError";

type Filter = "all" | "unacked";

export default function Alerts() {
  const qc = useQueryClient();
  const [filter, setFilter] = useState<Filter>("unacked");
  const [kind, setKind] = useState<string>("");

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["alerts", { filter, kind }],
    queryFn: () =>
      api.listAlerts({
        acknowledged: filter === "unacked" ? false : undefined,
        kind: kind || undefined,
      }),
    refetchInterval: 10_000,
  });

  const ack = useMutation({
    mutationFn: (id: number) => api.acknowledgeAlert(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alerts"] });
      qc.invalidateQueries({ queryKey: ["stats"] });
    },
  });

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Alerts</h1>
        <p className="text-sm text-slate-600">
          New devices, new open ports, and closed ports detected between scans.
        </p>
      </div>

      <div className="card flex flex-wrap items-center gap-3 p-3">
        <div className="flex gap-1">
          {(["unacked", "all"] as Filter[]).map((f) => (
            <button
              key={f}
              className={`btn ${filter === f ? "bg-brand-600 text-white" : "bg-white text-slate-700 ring-1 ring-slate-200"}`}
              onClick={() => setFilter(f)}
            >
              {f === "unacked" ? "Unacknowledged" : "All"}
            </button>
          ))}
        </div>
        <select className="input max-w-xs" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">All kinds</option>
          <option value="new_device">New device</option>
          <option value="new_port">New port</option>
          <option value="port_closed">Port closed</option>
        </select>
      </div>

      {ack.isError && (
        <QueryError error={ack.error} onRetry={() => ack.reset()} />
      )}

      <div className="card">
        {isLoading && <div className="p-4 text-sm text-slate-500">Loading…</div>}
        {isError && (
          <div className="p-4">
            <QueryError error={error} onRetry={() => refetch()} />
          </div>
        )}
        {data && data.length === 0 && (
          <div className="p-4 text-sm text-slate-500">No alerts match this filter.</div>
        )}
        {data?.map((a) => (
          <AlertRow
            key={a.id}
            alert={a}
            onAcknowledge={(al) => ack.mutate(al.id)}
            acknowledging={ack.isPending && ack.variables === a.id}
          />
        ))}
      </div>
    </div>
  );
}
