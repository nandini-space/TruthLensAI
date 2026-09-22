import type { ActionRecord, ResponseDecision } from "../../lib/module2-types";

const displayTime = (value: string) => new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
const isTimestamp = (value: unknown): value is string => typeof value === "string" && !Number.isNaN(Date.parse(value));
const mode = (value: string) => value === "dry_run" ? "Dry Run" : value;

function Decision({ decision }: { decision: unknown }) {
  const item = decision as Partial<ResponseDecision>;
  if (!item || typeof item.action !== "string" || typeof item.reason !== "string" || typeof item.indicator_value !== "string" || typeof item.indicator_type !== "string" || typeof item.mode !== "string") return <li className="malformed">A response decision record could not be displayed safely.</li>;
  return <li><header><span className={`badge response-${item.action}`}>{item.action}</span><span className="badge status">{mode(item.mode)}</span></header><code>{item.indicator_value}</code><p>{item.indicator_type}{item.reputation ? ` · Intelligence reputation: ${item.reputation}` : ""}</p><p className="muted">{item.reason}</p></li>;
}

function Action({ record }: { record: unknown }) {
  const item = record as Partial<ActionRecord>;
  if (!item || typeof item.action_id !== "string" || typeof item.action !== "string" || typeof item.status !== "string" || typeof item.reason !== "string" || typeof item.mode !== "string" || !item.indicator || typeof item.indicator.value !== "string") return <li className="malformed">A response action record could not be displayed safely.</li>;
  return <li><header><span className={`badge response-${item.action}`}>{item.action}</span><span className="badge status">{item.status}</span><span className="badge status">{mode(item.mode)}</span></header><code>{item.indicator.value}</code><p>{isTimestamp(item.timestamp) ? `Recorded: ${displayTime(item.timestamp)} · ` : ""}Would execute: {String(item.would_execute === true)} · Executed: {String(item.executed === true)}</p><p className="muted">{item.reason}</p></li>;
}

export function ResponseActionsPanel({ decisions, records }: { decisions: unknown; records: unknown }) {
  const validDecisions = Array.isArray(decisions) ? decisions : undefined;
  const validRecords = Array.isArray(records) ? records : undefined;
  return <section className="panel"><h2>Response decisions and actions</h2>{!validDecisions && !validRecords ? <p className="empty">Response information is unavailable for this investigation.</p> : <div className="response-grid"><div><h3>Policy decisions</h3>{validDecisions?.length ? <ul className="response-list">{validDecisions.map((item, index) => <Decision decision={item} key={index} />)}</ul> : <p className="empty">No response decisions were recorded.</p>}</div><div><h3>Audit action records</h3>{validRecords?.length ? <ul className="response-list">{validRecords.map((item, index) => <Action record={item} key={index} />)}</ul> : <p className="empty">No response actions were recorded.</p>}</div></div>}</section>;
}
