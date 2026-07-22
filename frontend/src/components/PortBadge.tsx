interface PortBadgeProps {
  port: number;
  protocol?: string;
  state?: string;
  service?: string | null;
}

export default function PortBadge({ port, protocol = "tcp", state = "open", service }: PortBadgeProps) {
  const stateClass =
    state === "open"
      ? "bg-emerald-100 text-emerald-800"
      : state === "closed"
        ? "bg-slate-100 text-slate-600"
        : "bg-amber-100 text-amber-800";
  return (
    <span className={`badge ${stateClass}`} title={service || undefined}>
      {port}/{protocol}
      {service ? <span className="ml-1 opacity-70">· {service}</span> : null}
    </span>
  );
}
