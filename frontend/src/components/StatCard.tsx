interface StatCardProps {
  label: string;
  value: number | string | null;
  hint?: string;
  accent?: "default" | "warn" | "critical";
}

export default function StatCard({ label, value, hint, accent = "default" }: StatCardProps) {
  const accentClass =
    accent === "warn"
      ? "text-amber-600"
      : accent === "critical"
        ? "text-rose-600"
        : "text-brand-600";
  return (
    <div className="card p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`mt-2 text-3xl font-semibold ${accentClass}`}>{value ?? "—"}</div>
      {hint && <div className="mt-1 text-xs text-slate-500">{hint}</div>}
    </div>
  );
}
