"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { listInvestigations, Module2ApiError } from "../../lib/module2-client";
import type { Module2InvestigationPage } from "../../lib/module2-types";

const date = (value: string) => new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
const score = (value: number) => new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(value);

export function InvestigationCenter() {
  const [page, setPage] = useState<Module2InvestigationPage>();
  const [error, setError] = useState<string>();
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const load = async () => {
    setLoading(true); setError(undefined);
    try { setPage(await listInvestigations()); }
    catch (reason) { setError(reason instanceof Module2ApiError ? reason.message : "Unable to load persisted investigations."); }
    finally { setLoading(false); }
  };
  useEffect(() => { void load(); }, []);
  const items = useMemo(() => page?.items.filter(({ incident, scan_result }) => {
    const value = query.trim().toLowerCase();
    return !value || [incident.incident_id, scan_result.scan_id, incident.threat_type, incident.severity, incident.status]
      .some((field) => field.toLowerCase().includes(value));
  }) ?? [], [page, query]);
  return <main className="workspace">
    <header className="hero"><p className="eyebrow">Module 3B · Persisted investigations</p><h1>Investigation Center</h1><p>Review completed Module 2 investigation snapshots from the configured persistence store.</p></header>
    <section className="toolbar panel" aria-label="Investigation controls">
      <div><strong>{page ? `${page.count} investigation${page.count === 1 ? "" : "s"} loaded` : "Investigation history"}</strong><p>Newest collected evidence first.</p></div>
      <label className="search"><span>Search loaded investigations</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="ID, threat, severity, or status" /></label>
    </section>
    {loading && <p className="loading" role="status">Loading persisted investigations…</p>}
    {error && <section className="error" role="alert"><strong>Investigation history unavailable.</strong><p>{error}</p><button type="button" onClick={() => void load()}>Retry</button></section>}
    {page && !loading && !error && (items.length ? <section className="panel table-wrap"><table className="investigation-table"><caption className="sr-only">Persisted investigations</caption><thead><tr><th>Incident</th><th>Threat</th><th>Severity</th><th>Risk</th><th>Status</th><th>Collected</th><th><span className="sr-only">Open detail</span></th></tr></thead><tbody>{items.map((result) => <tr key={result.scan_result.scan_id}><td><span className="mono">{result.incident.incident_id}</span><br /><small>Scan: {result.scan_result.scan_id}</small></td><td>{result.incident.threat_type}</td><td><span className={`badge severity-${result.incident.severity}`}>{result.incident.severity}</span></td><td><div className="risk"><span style={{ width: `${result.incident.risk_score}%` }} /><b>{score(result.incident.risk_score)} / 100</b></div></td><td><span className="badge status">{result.incident.status}</span></td><td>{date(result.evidence_pack.collected_at)}</td><td><Link className="detail-link" href={`/investigations/${result.scan_result.scan_id}`}>View<span className="sr-only"> {result.incident.incident_id}</span></Link></td></tr>)}</tbody></table></section> : <section className="panel empty-state"><h2>{query ? "No matching investigations" : "No persisted investigations"}</h2><p>{query ? "Try a different loaded ID, threat classification, severity, or status." : "The Module 2 persistence store did not return any investigation snapshots."}</p></section>)}
  </main>;
}
