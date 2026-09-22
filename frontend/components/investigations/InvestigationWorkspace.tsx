"use client";

import { useState } from "react";
import { investigate, Module2ApiError } from "../../lib/module2-client";
import type { Module2Result } from "../../lib/module2-types";
import { demoScanResult } from "./demo-scan";

const format = (value: number) => new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(value);

function EmptyState({ children }: { children: React.ReactNode }) { return <p className="empty">{children}</p>; }
function Section({ title, children }: { title: string; children: React.ReactNode }) { return <section className="panel"><h2>{title}</h2>{children}</section>; }

export function InvestigationResults({ result }: { result: Module2Result }) {
  const { incident, evidence_pack: evidence, threat_intelligence: intelligence, forensic_report: report } = result;
  return <div className="results">
    <Section title="Investigation summary">
      <dl className="summary-grid">
        <div><dt>Incident ID</dt><dd className="mono">{incident.incident_id}</dd></div>
        <div><dt>Threat classification</dt><dd>{incident.threat_type}</dd></div>
        <div><dt>Severity</dt><dd><span className={`badge severity-${incident.severity}`}>{incident.severity}</span></dd></div>
        <div><dt>Risk score</dt><dd>{format(incident.risk_score)} / 100</dd></div>
        <div><dt>Confidence</dt><dd>{format(incident.confidence * 100)}%</dd></div>
        <div><dt>Incident status</dt><dd><span className="badge status">{incident.status}</span></dd></div>
      </dl>
      <p>{result.scan_result.explanation}</p>
    </Section>
    <Section title="Evidence">
      {evidence ? <dl className="detail-list"><div><dt>Evidence ID</dt><dd className="mono">{evidence.evidence_id}</dd></div><div><dt>Collected</dt><dd>{evidence.collected_at}</dd></div><div><dt>Input reference</dt><dd className="mono">{evidence.scan_result.input_reference.reference_uri ?? evidence.scan_result.input_reference.original_content ?? "No input reference returned."}</dd></div><div><dt>Signals</dt><dd>{evidence.scan_result.signals.length ? evidence.scan_result.signals.map((signal) => `${signal.name}: ${signal.value}`).join("; ") : "No detection signals returned."}</dd></div></dl> : <EmptyState>No evidence pack was returned.</EmptyState>}
    </Section>
    <Section title="Threat intelligence">
      {!intelligence.length ? <EmptyState>No intelligence results were returned. This may mean no eligible indicators were found or providers were unavailable.</EmptyState> : <div className="table-wrap"><table><thead><tr><th>Indicator</th><th>Reputation</th><th>Status</th><th>Source</th><th>Findings</th></tr></thead><tbody>{intelligence.map((item) => <tr key={`${item.indicator.indicator_id}-${item.source}`}><td className="mono">{item.indicator.value}</td><td><span className={`badge reputation-${item.reputation}`}>{item.reputation}</span></td><td>{item.status}</td><td>{item.source}</td><td>{item.findings.length ? item.findings.map((finding) => finding.description).join(" ") : "No findings returned."}</td></tr>)}</tbody></table></div>}
    </Section>
    <Section title="Response actions">
      {!result.response_decisions.length && !result.action_records.length ? <EmptyState>No response decisions or action records were returned.</EmptyState> : <ul className="records">{result.response_decisions.map((decision, index) => <li key={`${decision.indicator_value}-${index}`}><strong>{decision.action}</strong> · {decision.indicator_type}: <span className="mono">{decision.indicator_value}</span><br /><span>{decision.reason} ({decision.mode})</span></li>)}{result.action_records.map((record) => <li key={record.action_id}><strong>{record.status}</strong> · {record.action} for <span className="mono">{record.indicator.value}</span><br /><span>Dry run: {record.mode}; executed: {String(record.executed)}.</span></li>)}</ul>}
    </Section>
    <Section title="Forensic report">
      {report ? <><dl className="detail-list"><div><dt>Report ID</dt><dd className="mono">{report.report_id}</dd></div><div><dt>Generated</dt><dd>{report.generated_at}</dd></div><div><dt>Recommended action</dt><dd>{report.recommended_action}</dd></div></dl><p>{report.analysis}</p></> : <EmptyState>No forensic report was returned.</EmptyState>}
    </Section>
    <Section title="STIX 2.1 bundle">
      {result.stix_bundle ? <p className="success">A STIX bundle was returned with this in-memory investigation. No download endpoint is currently available.</p> : <EmptyState>No STIX bundle was returned.</EmptyState>}
    </Section>
  </div>;
}

export function InvestigationWorkspace() {
  const [result, setResult] = useState<Module2Result>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(false);
  async function runInvestigation() {
    setLoading(true); setError(undefined);
    try { setResult(await investigate(demoScanResult)); }
    catch (reason) { setError(reason instanceof Module2ApiError ? reason.message : "Unable to start the investigation."); }
    finally { setLoading(false); }
  }
  return <main className="workspace"><header className="hero"><p className="eyebrow">Module 3B · Investigation workspace</p><h1>Investigation Center</h1><p>Review evidence, intelligence, response recommendations, and forensic snapshots returned by Module 2.</p></header>
    <section className="panel demo"><div><h2>Development sample</h2><p>This is clearly labeled demo data and does not represent a real incident. It uses the canonical Module 1 scan-result contract.</p></div><button type="button" onClick={runInvestigation} disabled={loading}>{loading ? "Investigating…" : "Investigate demo scan"}</button></section>
    {error && <section className="error" role="alert"><strong>Investigation unavailable.</strong><p>{error}</p><button type="button" onClick={runInvestigation} disabled={loading}>Retry</button></section>}
    {loading && <p className="loading" role="status">Requesting the Module 2 investigation snapshot…</p>}
    {result && !loading && <InvestigationResults result={result} />}
  </main>;
}
