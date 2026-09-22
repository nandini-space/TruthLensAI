interface ExplanationCardProps {
  explanation: string;
}

export function ExplanationCard({ explanation }: ExplanationCardProps) {
  return (
    <section aria-labelledby="explanation-heading" className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h3 id="explanation-heading" className="text-base font-semibold text-slate-950">
        Explanation
      </h3>
      <p className="mt-3 whitespace-pre-wrap break-words text-sm leading-6 text-slate-700">{explanation}</p>
    </section>
  );
}
