"use client";

interface ErrorStateProps {
  title?: string;
  description?: string;
  onRetry?: () => void;
}

/** Displays an operation failure without exposing implementation details. */
export function ErrorState({ title = "Something went wrong", description, onRetry }: ErrorStateProps) {
  return (
    <section className="rounded-xl border border-red-200 bg-red-50 p-6" role="alert">
      <h2 className="text-lg font-semibold text-slate-950">{title}</h2>
      {description ? <p className="mt-2 text-sm leading-6 text-slate-800">{description}</p> : null}
      {onRetry ? (
        <button
          type="button"
          onClick={onRetry}
          className="mt-5 rounded-lg border border-red-300 bg-white px-4 py-2 text-sm font-semibold text-slate-900 hover:bg-red-100 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2"
        >
          Try again
        </button>
      ) : null}
    </section>
  );
}
