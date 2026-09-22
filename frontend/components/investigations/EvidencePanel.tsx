import type { EvidencePack, JsonValue } from "../../lib/module2-types";

const readable = (value: string) => new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
const json = (value: Record<string, JsonValue>) => Object.keys(value).length ? JSON.stringify(value) : undefined;

export function EvidencePanel({ evidence }: { evidence: unknown }) {
  if (!evidence) return <section className="panel"><h2>Evidence</h2><p className="empty">No evidence available for this investigation.</p></section>;
  const item = evidence as Partial<EvidencePack>;
  if (typeof item.evidence_id !== "string" || typeof item.scan_id !== "string" || typeof item.collected_at !== "string" || !item.scan_result || !item.enriched_threat_result) return <section className="panel"><h2>Evidence</h2><p className="empty">Evidence data is malformed and could not be displayed.</p></section>;
  const enrichment = item.enriched_threat_result;
  const reference = item.scan_result.input_reference?.reference_uri ?? item.scan_result.input_reference?.original_content;
  const provenance = item.scan_result.provenance;
  return <section className="panel"><h2>Evidence</h2><dl className="detail-list"><div><dt>Evidence ID</dt><dd className="mono">{item.evidence_id}</dd></div><div><dt>Collected</dt><dd>{readable(item.collected_at)}</dd></div><div><dt>Scan ID</dt><dd className="mono">{item.scan_id}</dd></div><div><dt>Enrichment status</dt><dd><span className="badge status">{enrichment.status}</span></dd></div>{reference && <div><dt>Input reference</dt><dd className="mono">{reference}</dd></div>}{item.scan_result.input_reference?.content_hash && <div><dt>Content hash</dt><dd className="mono">{item.scan_result.input_reference.content_hash}</dd></div>}{provenance && <div><dt>Detection source</dt><dd>{provenance.source} · {provenance.detector_id}</dd></div>}{provenance && json(provenance.metadata) && <div><dt>Provenance metadata</dt><dd className="mono">{json(provenance.metadata)}</dd></div>}</dl></section>;
}
