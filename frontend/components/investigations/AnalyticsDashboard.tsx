"use client";

import { useEffect, useMemo, useState } from "react";
import { listInvestigations, Module2ApiError } from "../../lib/module2-client";
import type { Module2Result } from "../../lib/module2-types";

const PAGE_SIZE = 100;
const MAX_RECORDS = 1000;
type Counts = Record<string, number>;
type Loaded = { items: Module2Result[]; partial: boolean; malformed: number };

const increment = (counts: Counts, key: string) => { counts[key] = (counts[key] ?? 0) + 1; };
const labels = (counts: Counts) => Object.entries(counts).sort(([a], [b]) => a.localeCompare(b));

function aggregate(items: Module2Result[]) {
  const statuses: Counts = {}; const threats: Counts = {}; const severities: Counts = {}; const risk: Counts = {}; const enrichment: Counts = {}; const indicators: Counts = {}; const decisions: Counts = {}; const execution: Counts = {};
  for (const result of items) {
    increment(statuses, result.incident.status); increment(threats, result.incident.threat_type); increment(severities, result.incident.severity);
    const score = result.incident.risk_score;
    if (Number.isFinite(score)) increment(risk, score < 25 ? "0–24" : score < 50 ? "25–49" : score < 75 ? "50–74" : "75–100");
    increment(enrichment, result.evidence_pack.enriched_threat_result.status);
    result.indicators.forEach((indicator) => increment(indicators, indicator.type));
    result.response_decisions.forEach((decision) => increment(decisions, decision.action));
    result.action_records.forEach((record) => increment(execution, record.executed ? "executed" : record.mode === "dry_run" ? "dry_run_not_executed" : "not_executed"));
  }
  return { statuses, threats, severities, risk, enrichment, indicators, decisions, execution };
}

function Bars({ title, counts, empty }: { title: string; counts: Counts; empty: string }) {
  const rows = labels(counts); const maximum = Math.max(...rows.map(([, value]) => value), 1);
  return <section className="panel analytics-panel"><h2>{title}</h2>{rows.length ? <ul className="metric-bars">{rows.map(([label, value]) => <li key={label}><div><span>{label}</span><strong>{value}</strong></div><div className="bar-track" aria-label={`${label}: ${value}`}><span style={{ width: `${value / maximum * 100}%` }} /></div></li>)}</ul> : <p className="empty">{empty}</p>}</section>;
}

function isAnalyticsRecord(value: Module2Result): boolean {
  const result = value as Partial<Module2Result>;
  return Boolean(result.incident && typeof result.incident.status === "string" && typeof result.incident.threat_type === "string" && typeof result.incident.severity === "string" && typeof result.incident.risk_score === "number" && result.evidence_pack && result.evidence_pack.enriched_threat_result && typeof result.evidence_pack.enriched_threat_result.status === "string" && Array.isArray(result.indicators) && Array.isArray(result.response_decisions) && Array.isArray(result.action_records));
}

async function loadAll(): Promise<Loaded> {
  const items: Module2Result[] = []; let offset = 0; let malformed = 0; let fetched = 0;
  while (fetched < MAX_RECORDS) {
    const page = await listInvestigations({ limit: PAGE_SIZE, offset });
    for (const item of page.items) { if (isAnalyticsRecord(item)) items.push(item); else malformed += 1; }
    fetched += page.items.length;
    if (page.items.length < PAGE_SIZE) return { items, partial: false, malformed };
    offset += page.items.length;
  }
  return { items, partial: true, malformed };
}

export function AnalyticsDashboard() {
  const [loaded, setLoaded] = useState<Loaded>(); const [error, setError] = useState<string>(); const [loading, setLoading] = useState(true);
  const load = async () => { setLoading(true); setError(undefined); try { setLoaded(await loadAll()); } catch (reason) { setError(reason instanceof Module2ApiError ? reason.message : "Unable to load investigation analytics."); } finally { setLoading(false); } };
  useEffect(() => { void load(); }, []);
  const data = useMemo(() => loaded ? aggregate(loaded.items) : undefined, [loaded]);
  const total = loaded?.items.length ?? 0;
  return <main className="workspace"><header className="hero"><p className="eyebrow">Module 3B · Loaded investigation data</p><h1>Investigation Analytics</h1><p>Aggregated from persisted Module 2 investigation snapshots. No new analytics API or backend processing is used.</p></header>{loading && <p className="loading" role="status">Loading investigation pages for analytics…</p>}{error && <section className="error" role="alert"><strong>Analytics unavailable.</strong><p>{error}</p><button type="button" onClick={() => void load()}>Retry</button></section>}{loaded && data && !loading && !error && <><section className="analytics-note panel"><p><strong>Loaded set: {total} investigation{total === 1 ? "" : "s"}.</strong> {loaded.partial ? "The 1,000-record client safety cap was reached; metrics may be partial." : "All pages available at the time of this request were loaded."}{loaded.malformed ? ` ${loaded.malformed} malformed record${loaded.malformed === 1 ? " was" : "s were"} excluded.` : ""}</p></section>{total ? <><section className="overview-cards" aria-label="Investigation status summary"><article><span>Total investigations</span><strong>{total}</strong></article><article><span>Open</span><strong>{data.statuses.open ?? 0}</strong></article><article><span>Investigating</span><strong>{data.statuses.investigating ?? 0}</strong></article><article><span>Resolved</span><strong>{data.statuses.resolved ?? 0}</strong></article></section><div className="analytics-grid"><Bars title="Threat type distribution" counts={data.threats} empty="Threat type data is unavailable." /><Bars title="Severity distribution" counts={data.severities} empty="Severity data is unavailable." /><Bars title="Risk score distribution" counts={data.risk} empty="No valid risk scores were returned." /><Bars title="Intelligence enrichment status" counts={data.enrichment} empty="Enrichment status is unavailable." /><Bars title="Indicator type distribution" counts={data.indicators} empty="No indicators were returned." /><Bars title="Response decision summary" counts={data.decisions} empty="No response decisions were recorded." /><Bars title="Response execution summary" counts={data.execution} empty="No response action records were recorded." /></div></> : <section className="panel empty-state"><h2>No persisted investigations</h2><p>There is no loaded investigation data to aggregate.</p></section>}</>}</main>;
}
