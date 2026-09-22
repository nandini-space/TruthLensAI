import type { ThreatIntelResult } from "../../lib/module2-types";

const confidence = (value: number | null | undefined) => value == null ? "" : `${Math.round(value * 100)}%`;

export function ThreatIntelligencePanel({ intelligence }: { intelligence: unknown }) {
  if (!Array.isArray(intelligence) || !intelligence.length) return <section className="panel"><h2>Threat intelligence</h2><p className="empty">Threat-intelligence enrichment is unavailable for this investigation.</p></section>;
  return <section className="panel"><h2>Threat intelligence</h2><div className="intel-list">{intelligence.map((candidate, index) => {
    const item = candidate as Partial<ThreatIntelResult>;
    if (!item || typeof item.source !== "string" || !item.indicator || typeof item.indicator.value !== "string" || typeof item.reputation !== "string" || typeof item.status !== "string" || !Array.isArray(item.findings)) return <article className="intel-card malformed" key={index}>An intelligence record could not be displayed safely.</article>;
    return <article className="intel-card" key={`${item.source}-${item.indicator.value}-${index}`}><header><span className={`badge reputation-${item.reputation}`}>{item.reputation}</span><span className="badge status">{item.status}</span><code>{item.indicator.value}</code></header><p><strong>{item.indicator.type}</strong> · Source: {item.source}{confidence(item.confidence) && ` · Confidence: ${confidence(item.confidence)}`}</p>{item.provider_reference && <p className="muted">Reference: {item.provider_reference}</p>}{item.findings.length ? <ul>{item.findings.map((finding, findingIndex) => <li key={`${finding.source}-${finding.category}-${findingIndex}`}><strong>{finding.category}</strong>: {finding.description}{confidence(finding.confidence) && ` (${confidence(finding.confidence)})`}</li>)}</ul> : <p className="muted">No findings were returned by this source.</p>}</article>;
  })}</div></section>;
}
