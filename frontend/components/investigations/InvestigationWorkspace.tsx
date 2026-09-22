"use client";

import { useState } from "react";
import { investigate, Module2ApiError } from "../../lib/module2-client";
import type { Module2Result } from "../../lib/module2-types";
import { demoScanResult } from "./demo-scan";
import { EvidencePanel } from "./EvidencePanel";
import { ForensicReportPanel } from "./ForensicReportPanel";
import { IndicatorList } from "./IndicatorList";
import { InvestigationTimeline } from "./InvestigationTimeline";
import { ResponseActionsPanel } from "./ResponseActionsPanel";
import { StixPanel } from "./StixPanel";
import { ThreatIntelligencePanel } from "./ThreatIntelligencePanel";

const format = (value: number) => new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(value);
function Section({ title, children }: { title: string; children: React.ReactNode }) { return <section className="panel"><h2>{title}</h2>{children}</section>; }

export function InvestigationResults({ result }: { result: Module2Result }) {
  const { incident, evidence_pack: evidence } = result;
  return <div className="results">
    <Section title="Investigation summary"><dl className="summary-grid"><div><dt>Incident ID</dt><dd className="mono">{incident.incident_id}</dd></div><div><dt>Threat classification</dt><dd>{incident.threat_type}</dd></div><div><dt>Severity</dt><dd><span className={`badge severity-${incident.severity}`}>{incident.severity}</span></dd></div><div><dt>Risk score</dt><dd>{format(incident.risk_score)} / 100</dd></div><div><dt>Confidence</dt><dd>{format(incident.confidence * 100)}%</dd></div><div><dt>Incident status</dt><dd><span className="badge status">{incident.status}</span></dd></div></dl><p>{result.scan_result.explanation}</p></Section>
    <InvestigationTimeline result={result} />
    <EvidencePanel evidence={evidence} />
    <ThreatIntelligencePanel intelligence={result.threat_intelligence} />
    <Section title="Indicators"><IndicatorList indicators={result.indicators} /></Section>
    <ResponseActionsPanel decisions={result.response_decisions} records={result.action_records} />
    <ForensicReportPanel report={result.forensic_report} />
    <StixPanel bundle={result.stix_bundle} />
  </div>;
}

export function InvestigationWorkspace() {
  const [result, setResult] = useState<Module2Result>(); const [error, setError] = useState<string>(); const [loading, setLoading] = useState(false);
  async function runInvestigation() { setLoading(true); setError(undefined); try { setResult(await investigate(demoScanResult)); } catch (reason) { setError(reason instanceof Module2ApiError ? reason.message : "Unable to start the investigation."); } finally { setLoading(false); } }
  return <main className="workspace"><header className="hero"><p className="eyebrow">Module 3B · Investigation workspace</p><h1>Investigation Center</h1><p>Review evidence, intelligence, response recommendations, and forensic snapshots returned by Module 2.</p></header><section className="panel demo"><div><h2>Development sample</h2><p>This is clearly labeled demo data and does not represent a real incident. It uses the canonical Module 1 scan-result contract.</p></div><button type="button" onClick={runInvestigation} disabled={loading}>{loading ? "Investigating…" : "Investigate demo scan"}</button></section>{error && <section className="error" role="alert"><strong>Investigation unavailable.</strong><p>{error}</p><button type="button" onClick={runInvestigation} disabled={loading}>Retry</button></section>}{loading && <p className="loading" role="status">Requesting the Module 2 investigation snapshot…</p>}{result && !loading && <InvestigationResults result={result} />}</main>;
}
