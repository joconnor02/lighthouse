import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import DeviceTable from "../components/DeviceTable";

export default function Devices() {
  const navigate = useNavigate();
  const { data, isLoading, refetch } = useQuery({
    queryKey: ["devices"],
    queryFn: api.listDevices,
    refetchInterval: 15_000,
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Devices</h1>
          <p className="text-sm text-slate-600">All hosts ever seen by Lighthouse.</p>
        </div>
        <button className="btn-ghost" onClick={() => refetch()}>
          Refresh
        </button>
      </div>
      {isLoading && <div className="card p-6 text-sm text-slate-500">Loading…</div>}
      {data && (
        <DeviceTable
          devices={data}
          onSelect={(d) => navigate(`/devices/${d.id}`)}
        />
      )}
    </div>
  );
}
