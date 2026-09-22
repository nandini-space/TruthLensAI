import type { ActionRecord, Module2Result } from "../../lib/module2-types";

type TimelineEvent = { timestamp: string; title: string; detail: string; kind: "incident" | "evidence" | "enrichment" | "response" | "report" };

const isTimestamp = (value: unknown): value is string => typeof value === "string" && !Number.isNaN(Date.parse(value));
const displayTime = (value: string) => new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));

function actionEvent(record: unknown): TimelineEvent | undefined {
  const item = record as Partial<ActionRecord>;
  if (!item || !isTimestamp(item.timestamp) || typeof item.action !== "string" || typeof item.status !== "string") return undefined;
  return { timestamp: item.timestamp, title: "Dry-run response action recorded", detail: `${item.action} · ${item.status}${item.executed === false ? " · not executed" : ""}`, kind: "response" };
}

export function InvestigationTimeline({ result }: { result: Module2Result }) {
  const events: TimelineEvent[] = [];
  const { incident, evidence_pack: evidence, forensic_report: report, action_records } = result;
  if (isTimestamp(incident.created_at)) events.push({ timestamp: incident.created_at, title: "Incident record created", detail: `Lifecycle status: ${incident.status}`, kind: "incident" });
  if (isTimestamp(incident.updated_at) && incident.updated_at !== incident.created_at) events.push({ timestamp: incident.updated_at, title: "Incident record updated", detail: `Lifecycle status: ${incident.status}`, kind: "incident" });
  if (isTimestamp(evidence.collected_at)) events.push({ timestamp: evidence.collected_at, title: "Evidence collected", detail: `Evidence ID: ${evidence.evidence_id}`, kind: "evidence" });
  if (isTimestamp(evidence.enriched_threat_result.enriched_at)) events.push({ timestamp: evidence.enriched_threat_result.enriched_at, title: "Threat-intelligence enrichment recorded", detail: `Enrichment status: ${evidence.enriched_threat_result.status}`, kind: "enrichment" });
  if (isTimestamp(report.generated_at)) events.push({ timestamp: report.generated_at, title: "Forensic report generated", detail: `Report ID: ${report.report_id}`, kind: "report" });
  if (Array.isArray(action_records)) events.push(...action_records.map(actionEvent).filter((event): event is TimelineEvent => Boolean(event)));
  events.sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp));
  return <section className="panel"><h2>Investigation timeline</h2>{events.length ? <ol className="timeline">{events.map((event, index) => <li key={`${event.kind}-${event.timestamp}-${index}`}><time dateTime={event.timestamp}>{displayTime(event.timestamp)}</time><div><strong>{event.title}</strong><p>{event.detail}</p></div></li>)}</ol> : <p className="empty">No timeline events are available for this investigation.</p>}</section>;
}
