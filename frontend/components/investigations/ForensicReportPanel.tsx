import type { ForensicReport } from "../../lib/module2-types";
import { IndicatorList } from "./IndicatorList";

const date = (value: string) => new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));

export function ForensicReportPanel({ report }: { report: unknown }) {
  if (!report) return <section className="panel"><h2>Forensic report</h2><p className="empty">No forensic report is available for this investigation.</p></section>;
  const item = report as Partial<ForensicReport>;
  if (typeof item.report_id !== "string" || typeof item.incident_id !== "string" || typeof item.scan_id !== "string" || typeof item.analysis !== "string" || typeof item.recommended_action !== "string" || typeof item.generated_at !== "string" || !Array.isArray(item.indicators) || !Array.isArray(item.detected_signals) || !item.evidence_pack) return <section className="panel"><h2>Forensic report</h2><p className="empty">Forensic report data is malformed and could not be displayed.</p></section>;
  const input = item.original_input?.reference_uri ?? item.original_input?.original_content;
  return <section className="panel"><h2>Forensic report</h2><dl className="detail-list"><div><dt>Report ID</dt><dd className="mono">{item.report_id}</dd></div><div><dt>Generated</dt><dd>{date(item.generated_at)}</dd></div><div><dt>Incident ID</dt><dd className="mono">{item.incident_id}</dd></div><div><dt>Scan ID</dt><dd className="mono">{item.scan_id}</dd></div><div><dt>Evidence ID</dt><dd className="mono">{item.evidence_pack.evidence_id}</dd></div>{input && <div><dt>Original input reference</dt><dd className="mono">{input}</dd></div>}</dl><h3>Analysis</h3><p className="report-copy">{item.analysis}</p><h3>Recommended action</h3><p className="recommendation">{item.recommended_action}</p><details className="report-details"><summary>Report findings and technical references</summary><div><h4>Indicators</h4><IndicatorList indicators={item.indicators} /><h4>Detected signals</h4>{item.detected_signals.length ? <ul className="report-signals">{item.detected_signals.map((signal, index) => <li key={`${signal.name}-${index}`}><strong>{signal.name}</strong>: {signal.value} <span>({signal.source})</span></li>)}</ul> : <p className="empty">No detected signals were included in this report.</p>}</div></details></section>;
}
