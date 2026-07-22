interface QueryErrorProps {
  error: unknown;
  onRetry?: () => void;
}

export default function QueryError({ error, onRetry }: QueryErrorProps) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className="card p-4 text-sm text-rose-700 bg-rose-50">
      <p>{message}</p>
      {message.toLowerCase().includes("unauthorized") && (
        <p className="mt-2">
          Open <span className="font-medium">Settings</span> and paste the auth token from the
          backend logs, then try again.
        </p>
      )}
      {onRetry && (
        <button className="btn-ghost mt-2 text-xs" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}
