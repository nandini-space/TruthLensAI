"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { getInvestigation, Module2ApiError } from "../../../lib/module2-client";
import type { Module2Result } from "../../../lib/module2-types";
import { InvestigationResults } from "../../../components/investigations/InvestigationWorkspace";

export default function InvestigationDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const [result, setResult] = useState<Module2Result>(); const [error, setError] = useState<string>(); const [loading, setLoading] = useState(true);
  useEffect(() => { void (async () => { try { const { id } = await params; setResult(await getInvestigation(id)); } catch (reason) { setError(reason instanceof Module2ApiError ? reason.message : "Unable to load this investigation."); } finally { setLoading(false); } })(); }, [params]);
  return <main className="workspace"><nav className="breadcrumbs" aria-label="Breadcrumb"><Link href="/investigations">Investigation Center</Link><span aria-hidden="true">›</span><span>Investigation detail</span></nav><Link className="back-link" href="/investigations">← Back to Investigations</Link>{loading && <p className="loading" role="status">Loading persisted investigation…</p>}{error && <section className="error" role="alert"><strong>{error === "Module 2 investigation was not found." ? "Investigation not found." : "Investigation unavailable."}</strong><p>{error}</p><Link className="detail-link" href="/investigations">Return to Investigation Center</Link></section>}{result && !loading && <><header className="hero compact-hero"><p className="eyebrow">Persisted Module 2 snapshot</p><h1>Investigation detail</h1><p>Scan ID: <span className="mono">{result.scan_result.scan_id}</span></p></header><InvestigationResults result={result} /></>}</main>;
}
