interface LoadingStateProps {
  title?: string;
  description?: string;
}

/** Accessible, data-free feedback for a real asynchronous operation. */
export function LoadingState({ title = "Loading", description }: LoadingStateProps) {
  return (
    <section className="rounded-xl border border-slate-200 bg-white p-6 text-center shadow-sm" role="status">
      <span
        aria-hidden="true"
        className="mx-auto block h-6 w-6 animate-spin rounded-full border-2 border-slate-200 border-t-cyan-600"
      />
      <h2 className="mt-4 text-lg font-semibold text-slate-950">{title}</h2>
      {description ? <p className="mt-2 text-sm leading-6 text-slate-700">{description}</p> : null}
    </section>
  );
}
