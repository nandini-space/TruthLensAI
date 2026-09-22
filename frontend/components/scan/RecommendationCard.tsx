interface RecommendationCardProps {
  recommendation: string;
}

export function RecommendationCard({ recommendation }: RecommendationCardProps) {
  return (
    <section aria-labelledby="recommendation-heading" className="rounded-xl border border-cyan-100 bg-cyan-50 p-5">
      <h3 id="recommendation-heading" className="text-base font-semibold text-slate-950">
        Recommendation
      </h3>
      <p className="mt-3 whitespace-pre-wrap break-words text-sm leading-6 text-slate-800">
        {recommendation}
      </p>
    </section>
  );
}
