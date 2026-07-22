interface ProgressBarProps {
  value: number;
  label?: string;
  className?: string;
  compact?: boolean;
}

/** Simple percent bar; value expected in 0–100. */
export default function ProgressBar({
  value,
  label,
  className = "",
  compact = false,
}: ProgressBarProps) {
  const pct = Math.max(0, Math.min(100, Number.isFinite(value) ? value : 0));
  const rounded = Math.round(pct);
  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <div
        className={`min-w-0 flex-1 overflow-hidden rounded bg-slate-100 ${
          compact ? "h-1.5" : "h-2.5"
        }`}
        role="progressbar"
        aria-valuenow={rounded}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div
          className="h-full rounded bg-brand-600 transition-[width] duration-300 ease-out"
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className={`shrink-0 tabular-nums text-slate-600 ${compact ? "text-xs" : "text-sm"}`}>
        {label ?? `${rounded}%`}
      </span>
    </div>
  );
}
