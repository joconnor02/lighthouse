// Shared time-formatting helpers. The backend stores and serializes all
// timestamps as UTC ISO 8601 strings; the UI renders them in a fixed
// display timezone (America/New_York) so every viewer sees the same
// clock regardless of their browser's local timezone.

export const DISPLAY_TIMEZONE = "America/New_York";

const dateTimeFormatter = new Intl.DateTimeFormat("en-US", {
  timeZone: DISPLAY_TIMEZONE,
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

const dateFormatter = new Intl.DateTimeFormat("en-US", {
  timeZone: DISPLAY_TIMEZONE,
  year: "numeric",
  month: "short",
  day: "numeric",
});

const timeFormatter = new Intl.DateTimeFormat("en-US", {
  timeZone: DISPLAY_TIMEZONE,
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

const FALLBACK = "—";

function toDate(iso: string | null | undefined): Date | null {
  if (iso == null || iso === "") return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Format an ISO timestamp as e.g. `Jul 22, 2026, 02:24:13` in NYC time. */
export function formatDateTime(iso: string | null | undefined): string {
  const d = toDate(iso);
  return d ? dateTimeFormatter.format(d) : FALLBACK;
}

/** Format just the date portion of an ISO timestamp in NYC time. */
export function formatDate(iso: string | null | undefined): string {
  const d = toDate(iso);
  return d ? dateFormatter.format(d) : FALLBACK;
}

/** Format just the time portion of an ISO timestamp in NYC time (24-hour). */
export function formatTime(iso: string | null | undefined): string {
  const d = toDate(iso);
  return d ? timeFormatter.format(d) : FALLBACK;
}
