import type { Indicator } from "../../lib/module2-types";

const percent = (value: number | null | undefined) => value == null ? undefined : `${Math.round(value * 100)}%`;

export function IndicatorList({ indicators }: { indicators: unknown }) {
  if (!Array.isArray(indicators)) return <p className="empty">Indicator data is unavailable for this investigation.</p>;
  if (!indicators.length) return <p className="empty">No indicators were extracted for this investigation.</p>;
  return <ul className="indicator-list">{indicators.map((candidate, index) => {
    const indicator = candidate as Partial<Indicator>;
    if (!indicator || typeof indicator.value !== "string" || typeof indicator.type !== "string") return <li className="malformed" key={index}>An indicator record could not be displayed safely.</li>;
    return <li key={typeof indicator.indicator_id === "string" ? indicator.indicator_id : `${indicator.type}-${indicator.value}-${index}`}><span className="badge indicator-type">{indicator.type}</span><code title="Selectable indicator value">{indicator.value}</code><span className="indicator-source">Source: {typeof indicator.source === "string" ? indicator.source : "Unavailable"}{percent(indicator.confidence) ? ` · Confidence: ${percent(indicator.confidence)}` : ""}</span></li>;
  })}</ul>;
}
