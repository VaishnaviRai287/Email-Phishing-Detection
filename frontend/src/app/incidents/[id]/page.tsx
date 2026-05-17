"use client";

import React, { useEffect, useState, use } from "react";
import Link from "next/link";

interface LinkRead {
  id: number;
  url: string;
  domain: string;
  is_shortened: boolean;
  is_suspicious_redirect: boolean;
  vt_malicious_count: number;
  vt_harmless_count: number;
  vt_suspicious_count: number;
  vt_undetected_count: number;
  vt_scan_date: string | null;
  vt_reputation_score: number;
  vt_verdict: string;
}

interface AttachmentRead {
  id: number;
  filename: string;
  content_type: string | null;
  file_size: number | null;
  file_hash_sha256: string | null;
  is_suspicious: boolean;
  risk_reason: string | null;
}

interface CaseHistoryRead {
  id: number;
  timestamp: string;
  action: string;
  details: string | null;
  analyst: string | null;
}

interface IncidentRead {
  id: number;
  message_id: string | null;
  sender: string;
  sender_name: string | null;
  subject: string | null;
  received_at: string | null;
  ingested_at: string;
  body_text: string | null;
  body_html: string | null;
  reply_to: string | null;
  reply_to_mismatch: boolean;
  spf_result: string | null;
  dkim_result: string | null;
  dmarc_result: string | null;
  headers_json: string | null;
  risk_score: number;
  severity: string;
  summary_ai: string | null;
  investigation_notes_ai: string | null;
  remediation_steps_ai: string | null;
  status: string;
  assigned_analyst: string | null;
  analyst_notes: string | null;
  resolved_at: string | null;
  resolution_reason: string | null;
  
  links: LinkRead[];
  attachments: AttachmentRead[];
  history: CaseHistoryRead[];
}

export default function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const resolvedParams = use(params);
  const incidentId = resolvedParams.id;

  const [incident, setIncident] = useState<IncidentRead | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Active UI tab
  const [activeTab, setActiveTab] = useState<"ai" | "email" | "intel" | "audit">("ai");

  // Workflow states
  const [analystName, setAnalystName] = useState("");
  const [assigning, setAssigning] = useState(false);
  
  const [noteContent, setNoteContent] = useState("");
  const [addingNote, setAddingNote] = useState(false);

  const [resolutionReason, setResolutionReason] = useState("True Positive Phishing");
  const [resolutionNotes, setResolutionNotes] = useState("");
  const [resolving, setResolving] = useState(false);
  const [showResolveModal, setShowResolveModal] = useState(false);

  const fetchIncidentDetail = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch(`http://localhost:8000/api/incidents/${incidentId}`);
      if (!res.ok) {
        throw new Error("Failed to load incident detail.");
      }
      const data = await res.json();
      setIncident(data);
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Failed to contact SOC server.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidentDetail();
  }, [incidentId]);

  // ASSIGN OWNER ACTION
  const handleAssign = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!analystName.trim()) return;
    try {
      setAssigning(true);
      const res = await fetch(`http://localhost:8000/api/incidents/${incidentId}/assign`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ analyst: analystName }),
      });
      if (res.ok) {
        setAnalystName("");
        await fetchIncidentDetail();
      } else {
        alert("Failed to assign incident.");
      }
    } catch (err) {
      alert("Error contacting API.");
    } finally {
      setAssigning(false);
    }
  };

  // ADD NOTES ACTION
  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!noteContent.trim()) return;
    try {
      setAddingNote(true);
      const res = await fetch(`http://localhost:8000/api/incidents/${incidentId}/notes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ note: noteContent }),
      });
      if (res.ok) {
        setNoteContent("");
        await fetchIncidentDetail();
      } else {
        alert("Failed to save note.");
      }
    } catch (err) {
      alert("Error contacting API.");
    } finally {
      setAddingNote(false);
    }
  };

  // RESOLVE CASE ACTION
  const handleResolve = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setResolving(true);
      const res = await fetch(`http://localhost:8000/api/incidents/${incidentId}/resolve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          resolution_reason: resolutionReason,
          analyst_notes: resolutionNotes 
        }),
      });
      if (res.ok) {
        setResolutionNotes("");
        setShowResolveModal(false);
        await fetchIncidentDetail();
      } else {
        alert("Failed to resolve case.");
      }
    } catch (err) {
      alert("Error contacting API.");
    } finally {
      setResolving(false);
    }
  };

  if (loading && !incident) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
        <span className="w-10 h-10 rounded-full border-4 border-indigo-600/30 border-t-indigo-500 animate-spin" />
        <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Loading Incident Forensic Logs...</span>
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="text-center py-20 max-w-md mx-auto space-y-4">
        <div className="text-rose-500 text-sm font-bold uppercase tracking-wider"> forensice triage failed</div>
        <p className="text-slate-400 text-xs">{error || "Case file not found."}</p>
        <Link href="/incidents" className="inline-block px-5 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-xs font-semibold uppercase">Return to incidents</Link>
      </div>
    );
  }

  // Pre-calculate visual states
  const spfPass = incident.spf_result?.toLowerCase() === "pass";
  const dkimPass = incident.dkim_result?.toLowerCase() === "pass";
  const dmarcPass = incident.dmarc_result?.toLowerCase() === "pass";

  return (
    <div className="space-y-8 relative">
      {/* Top Navigation Back bar */}
      <div className="flex items-center gap-2">
        <Link href="/incidents" className="text-xs text-indigo-400 hover:text-indigo-300 font-bold uppercase tracking-wider flex items-center gap-1 transition-colors">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M15 19l-7-7 7-7" />
          </svg>
          Back to Triage Desk
        </Link>
      </div>

      {/* Flagship Header Panel: Summary & Scoring */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
        {/* Left 8 cols: Incident Summary Metadata */}
        <div className="xl:col-span-8 glass-panel p-6 rounded-xl border-slate-800 space-y-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="space-y-1">
              <span className={`px-2.5 py-0.5 rounded text-[10px] font-black tracking-wider uppercase ${
                incident.severity === "CRITICAL" ? "badge-critical" :
                incident.severity === "HIGH" ? "badge-high" :
                incident.severity === "MEDIUM" ? "badge-medium" : "badge-low"
              }`}>
                {incident.severity} SEVERITY
              </span>
              <h2 className="text-lg font-black text-white mt-2 leading-snug">{incident.subject || "(No Subject)"}</h2>
            </div>
            
            <div className="shrink-0 flex items-center gap-2">
              <span className="text-slate-500 text-xs font-mono">Status:</span>
              <span className={`px-3 py-1 rounded-md text-[10px] font-black uppercase tracking-widest ${
                incident.status === "RESOLVED" ? "badge-resolved" :
                incident.status === "INVESTIGATING" ? "badge-medium" : "badge-low"
              }`}>
                {incident.status}
              </span>
            </div>
          </div>

          <div className="h-px bg-slate-800/50" />

          {/* Key Metrics: Sender details, Mismatch flags */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs leading-relaxed">
            <div className="space-y-3">
              <div>
                <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">From Sender:</span>
                <div className="text-slate-200 mt-0.5 font-medium">
                  {incident.sender_name && <span className="font-bold text-slate-100">{incident.sender_name} </span>}
                  <span className="font-mono text-slate-400">&lt;{incident.sender}&gt;</span>
                </div>
              </div>
              
              {incident.reply_to && (
                <div>
                  <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Reply-To Header:</span>
                  <div className="text-slate-200 mt-0.5 font-mono">{incident.reply_to}</div>
                </div>
              )}
            </div>

            <div className="space-y-3">
              <div>
                <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Triage Timestamp:</span>
                <div className="text-slate-300 mt-0.5 font-mono">
                  {incident.received_at ? new Date(incident.received_at).toLocaleString() : new Date(incident.ingested_at).toLocaleString()}
                </div>
              </div>

              <div>
                <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Message Hash:</span>
                <div className="text-slate-400 mt-0.5 font-mono text-[10px] truncate max-w-[280px]">
                  {incident.message_id || "N/A (Offline Direct Ingest)"}
                </div>
              </div>
            </div>
          </div>

          {/* Mismatch Alert Box */}
          {incident.reply_to_mismatch && (
            <div className="p-3.5 rounded-lg bg-rose-950/20 border border-rose-900/30 flex items-center gap-3 text-rose-300 text-xs">
              <svg className="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <div>
                <span className="font-bold">SENDER ALIAS MISMATCH DETECTED:</span> Reply-To header points to a completely different email address than the From address. Highly indicative of spoofing.
              </div>
            </div>
          )}

          {/* Email Authentication Badges */}
          <div className="space-y-1.5">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Authentication Seals (SPF / DKIM / DMARC):</span>
            <div className="flex items-center gap-3">
              {/* SPF Badge */}
              <div className={`px-3 py-1.5 rounded border text-[10px] font-mono font-bold uppercase tracking-widest flex items-center gap-2 ${
                spfPass ? "bg-emerald-950/25 border-emerald-900/50 text-emerald-400" : "bg-rose-950/25 border-rose-900/50 text-rose-400"
              }`}>
                <span>SPF:</span>
                <span className="font-black">{incident.spf_result || "NONE"}</span>
              </div>

              {/* DKIM Badge */}
              <div className={`px-3 py-1.5 rounded border text-[10px] font-mono font-bold uppercase tracking-widest flex items-center gap-2 ${
                dkimPass ? "bg-emerald-950/25 border-emerald-900/50 text-emerald-400" : "bg-rose-950/25 border-rose-900/50 text-rose-400"
              }`}>
                <span>DKIM:</span>
                <span className="font-black">{incident.dkim_result || "NONE"}</span>
              </div>

              {/* DMARC Badge */}
              <div className={`px-3 py-1.5 rounded border text-[10px] font-mono font-bold uppercase tracking-widest flex items-center gap-2 ${
                dmarcPass ? "bg-emerald-950/25 border-emerald-900/50 text-emerald-400" : "bg-rose-950/25 border-rose-900/50 text-rose-400"
              }`}>
                <span>DMARC:</span>
                <span className="font-black">{incident.dmarc_result || "NONE"}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right 4 cols: Threat Score Meter */}
        <div className="xl:col-span-4 glass-panel p-6 rounded-xl border-slate-800 flex flex-col justify-between">
          <div className="text-center py-4">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest block mb-2">Calculated Phishing Index</span>
            <div className="relative inline-flex items-center justify-center">
              <div className="text-6xl font-black font-mono text-white tracking-tighter">
                {incident.risk_score.toFixed(0)}
              </div>
              <span className="text-xs text-slate-500 font-bold ml-1">/100</span>
            </div>
            
            {/* Simple colored score slider */}
            <div className="w-full bg-slate-900 h-1.5 rounded-full mt-5 overflow-hidden">
              <div 
                className={`h-full rounded-full transition-all duration-500 ${
                  incident.risk_score >= 85 ? "bg-rose-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]" :
                  incident.risk_score >= 60 ? "bg-orange-500" :
                  incident.risk_score >= 30 ? "bg-yellow-500" : "bg-blue-500"
                }`}
                style={{ width: `${incident.risk_score}%` }}
              />
            </div>
          </div>

          <div className="h-px bg-slate-800/40 my-3" />

          {/* Mini scorecard findings summary */}
          <div className="space-y-3.5 flex-1 mt-2 text-xs">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block">Computed Threat Indicators:</span>
            
            <div className="space-y-2 max-h-[160px] overflow-y-auto pr-1">
              {incident.reply_to_mismatch && (
                <div className="flex items-center gap-2 text-rose-400">
                  <span className="font-black shrink-0">CRIT</span>
                  <span className="text-slate-300">Reply-to mismatch flag</span>
                </div>
              )}
              {incident.links.some(l => l.vt_verdict === "MALICIOUS") && (
                <div className="flex items-center gap-2 text-rose-400">
                  <span className="font-black shrink-0">CRIT</span>
                  <span className="text-slate-300">VirusTotal blacklisted URL</span>
                </div>
              )}
              {incident.attachments.some(a => a.is_suspicious) && (
                <div className="flex items-center gap-2 text-orange-400">
                  <span className="font-black shrink-0">WARN</span>
                  <span className="text-slate-300">Macro/executable attachments</span>
                </div>
              )}
              {incident.links.some(l => l.is_shortened) && (
                <div className="flex items-center gap-2 text-yellow-400">
                  <span className="font-black shrink-0">SUSP</span>
                  <span className="text-slate-300">URL Shortener redirection</span>
                </div>
              )}
              {(!spfPass || !dkimPass) && (
                <div className="flex items-center gap-2 text-yellow-400">
                  <span className="font-black shrink-0">SUSP</span>
                  <span className="text-slate-300">Auth Signature failures</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Double Column Triage Work Area */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        
        {/* Left Column: Forensic Tabs Content (9 cols) */}
        <div className="lg:col-span-9 space-y-6">
          {/* Tab Selection Row */}
          <div className="border-b border-slate-800 flex items-center gap-6">
            <button
              onClick={() => setActiveTab("ai")}
              className={`py-3.5 text-xs font-bold uppercase tracking-wider border-b-2 px-1 transition-all cursor-pointer ${
                activeTab === "ai"
                  ? "border-indigo-500 text-indigo-400 font-extrabold"
                  : "border-transparent text-slate-500 hover:text-slate-300"
              }`}
            >
              AI Analyst Notes
            </button>
            <button
              onClick={() => setActiveTab("email")}
              className={`py-3.5 text-xs font-bold uppercase tracking-wider border-b-2 px-1 transition-all cursor-pointer ${
                activeTab === "email"
                  ? "border-indigo-500 text-indigo-400 font-extrabold"
                  : "border-transparent text-slate-500 hover:text-slate-300"
              }`}
            >
              Email Content View
            </button>
            <button
              onClick={() => setActiveTab("intel")}
              className={`py-3.5 text-xs font-bold uppercase tracking-wider border-b-2 px-1 transition-all cursor-pointer ${
                activeTab === "intel"
                  ? "border-indigo-500 text-indigo-400 font-extrabold"
                  : "border-transparent text-slate-500 hover:text-slate-300"
              }`}
            >
              IOC Threat Intel ({incident.links.length + incident.attachments.length})
            </button>
            <button
              onClick={() => setActiveTab("audit")}
              className={`py-3.5 text-xs font-bold uppercase tracking-wider border-b-2 px-1 transition-all cursor-pointer ${
                activeTab === "audit"
                  ? "border-indigo-500 text-indigo-400 font-extrabold"
                  : "border-transparent text-slate-500 hover:text-slate-300"
              }`}
            >
              Triage Audit History ({incident.history.length})
            </button>
          </div>

          {/* TAB 1: AI ANALYST NOTE */}
          {activeTab === "ai" && (
            <div className="space-y-6">
              {/* Summary */}
              <div className="glass-panel p-5 rounded-xl border-slate-800 space-y-3">
                <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">AI Incident Summary</h3>
                <div className="text-slate-300 text-xs leading-relaxed italic">
                  {renderMarkdown(incident.summary_ai) || "AI summary currently unavailable. Configure your GEMINI_API_KEY in backend .env to populate."}
                </div>
              </div>

              {/* Technical Analysis & Remediation side by side */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Tech notes */}
                <div className="glass-panel p-5 rounded-xl border-slate-800 space-y-4">
                  <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">Forensic Investigation Notes</h3>
                  <div className="text-slate-300 text-xs leading-relaxed max-h-[380px] overflow-y-auto space-y-1 pr-1 font-sans">
                    {renderMarkdown(incident.investigation_notes_ai) || <span className="text-slate-500 italic">No technical logs generated.</span>}
                  </div>
                </div>

                {/* Containment recommendations */}
                <div className="glass-panel p-5 rounded-xl border-slate-800 space-y-4">
                  <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 font-mono text-indigo-300">Remediation & Containment Guide</h3>
                  <div className="text-slate-300 text-xs leading-relaxed max-h-[380px] overflow-y-auto space-y-1 pr-1 font-sans">
                    {renderMarkdown(incident.remediation_steps_ai) || <span className="text-slate-500 italic">Remediation guidance unavailable.</span>}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: EMAIL VIEWER */}
          {activeTab === "email" && (
            <div className="space-y-6">
              {/* Sanitized HTML Sandbox Iframe */}
              {incident.body_html ? (
                <div className="glass-panel rounded-xl border-slate-800 overflow-hidden">
                  <div className="bg-[#0c121e]/80 px-4 py-2 border-b border-slate-800 text-[10px] text-slate-500 font-bold uppercase tracking-wider flex items-center justify-between">
                    <span>Sandboxed Email HTML Preview (Active Scripts Disabled)</span>
                    <span className="text-[9px] text-indigo-400 border border-indigo-900 px-2 py-0.5 rounded font-mono">SECURE PREVIEW</span>
                  </div>
                  
                  {/* Iframe with complete security sandbox block */}
                  <iframe
                    srcDoc={`
                      <html>
                        <head>
                          <style>
                            body { font-family: sans-serif; font-size: 13px; color: #334155; padding: 20px; line-height: 1.5; background: #f8fafc; }
                            a { color: #2563eb; text-decoration: underline; }
                          </style>
                        </head>
                        <body>
                          ${incident.body_html}
                        </body>
                      </html>
                    `}
                    sandbox="allow-popups"
                    className="w-full h-[400px] bg-white border-0"
                  />
                </div>
              ) : (
                // Text body fallback
                <div className="glass-panel p-6 rounded-xl border-slate-800 bg-slate-950/30">
                  <div className="text-[10px] text-slate-500 font-bold uppercase tracking-wider mb-3">Email Plain-text Body</div>
                  <pre className="text-xs text-slate-300 font-mono whitespace-pre-wrap leading-relaxed max-h-[400px] overflow-y-auto">
                    {incident.body_text || "(Empty email body text)"}
                  </pre>
                </div>
              )}

              {/* Technical Headers block */}
              {incident.headers_json && (
                <div className="glass-panel rounded-xl border-slate-800 overflow-hidden">
                  <details className="group">
                    <summary className="bg-[#0c121e]/80 px-5 py-3 text-xs font-bold uppercase tracking-widest text-slate-400 cursor-pointer flex items-center justify-between hover:text-slate-200">
                      <span>Forensic Email Header Inspector (Raw Data)</span>
                      <span className="text-slate-500 group-open:rotate-180 transition-transform">▼</span>
                    </summary>
                    <div className="p-5 bg-slate-950/45 border-t border-slate-850 font-mono text-[10px] text-slate-400 overflow-x-auto max-h-[300px] overflow-y-auto leading-relaxed">
                      <pre>{JSON.stringify(JSON.parse(incident.headers_json), null, 2)}</pre>
                    </div>
                  </details>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: IOC THREAT INTEL */}
          {activeTab === "intel" && (
            <div className="space-y-8">
              {/* Link reputation check VirusTotal */}
              <div className="space-y-4">
                <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">Extracted Links & VirusTotal Reputation</h3>
                
                {incident.links.length === 0 ? (
                  <div className="text-xs text-slate-500 italic py-6 glass-panel text-center rounded-xl border-slate-800">No hyperlinks extracted from email body.</div>
                ) : (
                  <div className="space-y-4">
                    {incident.links.map((link) => {
                      const vtMalicious = link.vt_malicious_count > 0;
                      return (
                        <div key={link.id} className="glass-panel p-5 rounded-xl border-slate-800 space-y-4">
                          <div className="flex flex-wrap items-start justify-between gap-4">
                            <div className="min-w-0 flex-1">
                              <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block">Hyperlink Destination:</span>
                              <div className="font-mono text-xs text-slate-200 break-all select-all mt-1">{link.url}</div>
                            </div>
                            
                            <div className="shrink-0">
                              <span className={`px-2.5 py-0.5 rounded text-[10px] font-black uppercase tracking-widest border ${
                                link.vt_verdict === "MALICIOUS" ? "bg-rose-950/20 border-rose-900/40 text-rose-400" :
                                link.vt_verdict === "SUSPICIOUS" ? "bg-amber-950/20 border-amber-900/40 text-amber-400" :
                                "bg-emerald-950/20 border-emerald-900/40 text-emerald-400"
                              }`}>
                                VT verdict: {link.vt_verdict}
                              </span>
                            </div>
                          </div>

                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-slate-950/30 p-3 rounded-lg border border-slate-900/60 font-mono text-[11px] text-slate-400 leading-normal">
                            <div>
                              <span className="text-[9px] text-slate-500 uppercase font-sans font-bold">Malicious flags:</span>
                              <div className={`mt-0.5 font-bold ${vtMalicious ? "text-rose-400" : "text-slate-400"}`}>{link.vt_malicious_count}</div>
                            </div>
                            <div>
                              <span className="text-[9px] text-slate-500 uppercase font-sans font-bold">Harmless:</span>
                              <div className="mt-0.5">{link.vt_harmless_count}</div>
                            </div>
                            <div>
                              <span className="text-[9px] text-slate-500 uppercase font-sans font-bold">Shortened URL:</span>
                              <div className="mt-0.5 font-bold text-slate-300">{link.is_shortened ? "TRUE" : "FALSE"}</div>
                            </div>
                            <div>
                              <span className="text-[9px] text-slate-500 uppercase font-sans font-bold">Domain:</span>
                              <div className="mt-0.5 text-indigo-400 truncate max-w-[120px]" title={link.domain}>{link.domain}</div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Suspicious attachment checker */}
              <div className="space-y-4">
                <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">Suspicious Attachments Metadata</h3>
                
                {incident.attachments.length === 0 ? (
                  <div className="text-xs text-slate-500 italic py-6 glass-panel text-center rounded-xl border-slate-800">No attachments included in incident mail envelope.</div>
                ) : (
                  <div className="space-y-4">
                    {incident.attachments.map((attach) => (
                      <div key={attach.id} className="glass-panel p-5 rounded-xl border-slate-800 space-y-3.5">
                        <div className="flex flex-wrap items-center justify-between gap-4">
                          <div className="flex items-center gap-3 min-w-0">
                            {/* File icon */}
                            <div className="w-10 h-10 rounded bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-400 shrink-0">
                              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                              </svg>
                            </div>
                            <div className="min-w-0">
                              <h4 className="text-sm font-bold text-white truncate max-w-sm" title={attach.filename}>{attach.filename}</h4>
                              <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                                {attach.content_type || "Unknown MIME"} | {( (attach.file_size || 0) / 1024 ).toFixed(1)} KB
                              </div>
                            </div>
                          </div>

                          <div className="shrink-0">
                            <span className={`px-2.5 py-0.5 rounded text-[10px] font-black uppercase tracking-wider border ${
                              attach.is_suspicious ? "bg-rose-950/20 border-rose-900/40 text-rose-400" : "bg-slate-900 border-slate-850 text-slate-500"
                            }`}>
                              {attach.is_suspicious ? "SUSPICIOUS VECTOR" : "SAFE / EXCLUDED"}
                            </span>
                          </div>
                        </div>

                        {attach.is_suspicious && (
                          <div className="p-3 bg-rose-950/15 border border-rose-900/20 rounded-lg text-xs text-rose-300">
                            <span className="font-bold">Threat Indicator:</span> {attach.risk_reason || "Potentially high-risk file extension trigger."}
                          </div>
                        )}

                        <div className="text-[10px] font-mono text-slate-500 select-all border border-slate-900/80 bg-slate-950/20 p-2.5 rounded-lg">
                          <span className="font-sans font-bold text-[9px] text-slate-600 block mb-1">SHA256 File Fingerprint (Reputation Check):</span>
                          {attach.file_hash_sha256 || "Hash calculation bypassed"}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 4: AUDIT HISTORY TIMELINE */}
          {activeTab === "audit" && (
            <div className="glass-panel p-6 rounded-xl border-slate-800 space-y-6">
              <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">Incident Triage Audit History</h3>
              
              <div className="relative border-l-2 border-slate-800 pl-6 ml-2.5 space-y-6">
                {incident.history.map((log) => (
                  <div key={log.id} className="relative group">
                    {/* Timestamp bullet */}
                    <span className="absolute -left-[31px] top-1.5 w-3 h-3 rounded-full bg-indigo-500 border border-slate-950 group-hover:scale-125 transition-transform" />
                    
                    <div className="space-y-1">
                      <div className="flex items-center gap-3 text-xs">
                        <span className="font-mono text-indigo-400 font-bold bg-indigo-950/40 px-2 py-0.5 rounded border border-indigo-900/50 uppercase tracking-widest">
                          {log.action}
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono">
                          {new Date(log.timestamp).toLocaleString()}
                        </span>
                      </div>
                      
                      <p className="text-slate-300 text-xs leading-relaxed mt-1.5">{log.details}</p>
                      
                      <div className="text-[10px] text-slate-500 font-semibold tracking-wider uppercase mt-1">
                        Analyst Actioned: <span className="text-slate-400">{log.analyst || "System Core"}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: SOC Actions Panel (3 cols) */}
        <div className="lg:col-span-3 space-y-6">
          
          {/* Action Card: Owner Assignment */}
          <div className="glass-panel p-5 rounded-xl border-slate-800 space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">Case Assignment</h3>
            
            {incident.assigned_analyst ? (
              <div className="space-y-1 bg-[#090f17]/45 p-3 rounded-lg border border-slate-850/60 text-xs leading-normal">
                <span className="text-[9px] text-slate-500 uppercase tracking-wider font-bold">Assigned Analyst:</span>
                <div className="text-slate-200 font-bold">{incident.assigned_analyst}</div>
              </div>
            ) : (
              <div className="p-3 bg-amber-950/10 border border-amber-900/20 text-amber-400 text-xs font-semibold rounded-lg">
                Case currently unassigned. Self-assign or delegate immediately.
              </div>
            )}

            <form onSubmit={handleAssign} className="space-y-2.5">
              <input
                type="text"
                placeholder="Analyst Name (e.g. SOC #94)"
                value={analystName}
                onChange={(e) => setAnalystName(e.target.value)}
                className="w-full px-3 py-1.5 bg-slate-950/75 border border-slate-850 focus:border-indigo-500 rounded-lg text-xs font-semibold text-slate-200 placeholder-slate-600 outline-none transition-all shadow-inner"
              />
              <button
                type="submit"
                disabled={assigning || !analystName.trim()}
                className="w-full py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-800 disabled:opacity-50 text-white font-bold text-xs uppercase tracking-wider transition-all cursor-pointer shadow-md"
              >
                {assigning ? "Assigning..." : "Update Owner"}
              </button>
            </form>
          </div>

          {/* Action Card: Case Status Resolve */}
          <div className="glass-panel p-5 rounded-xl border-slate-800 space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">Case Resolution</h3>
            
            {incident.status === "RESOLVED" ? (
              <div className="space-y-3">
                <div className="bg-emerald-950/15 p-3 rounded-lg border border-emerald-900/20 text-xs leading-normal">
                  <span className="text-[9px] text-slate-500 uppercase tracking-wider font-bold block mb-1">Resolution verdict:</span>
                  <span className="font-extrabold text-emerald-400">{incident.resolution_reason}</span>
                </div>
                <div className="text-[10px] text-slate-400 leading-normal font-mono select-all p-2 rounded-lg bg-slate-950/30 max-h-[140px] overflow-y-auto whitespace-pre-wrap">
                  {incident.analyst_notes || "No notes logged."}
                </div>
              </div>
            ) : (
              <button
                onClick={() => setShowResolveModal(true)}
                className="w-full py-2.5 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-black text-xs uppercase tracking-widest transition-all cursor-pointer shadow-md shadow-emerald-950/20"
              >
                Close & Resolve Case
              </button>
            )}
          </div>

          {/* Action Card: Manual Analyst Notes */}
          <div className="glass-panel p-5 rounded-xl border-slate-800 space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">Triage Journal</h3>
            
            {/* Show notes history */}
            {incident.analyst_notes && incident.status !== "RESOLVED" && (
              <div className="text-[10px] text-slate-400 leading-normal font-mono select-all p-2.5 rounded-lg border border-slate-850/60 bg-slate-950/35 max-h-[160px] overflow-y-auto whitespace-pre-wrap">
                {incident.analyst_notes}
              </div>
            )}

            <form onSubmit={handleAddNote} className="space-y-2.5">
              <textarea
                placeholder="Log observation notes, phishing indicators, user actions..."
                value={noteContent}
                rows={3}
                onChange={(e) => setNoteContent(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950/75 border border-slate-850 focus:border-indigo-500 rounded-lg text-xs font-semibold text-slate-200 placeholder-slate-600 outline-none transition-all shadow-inner resize-none leading-relaxed"
              />
              <button
                type="submit"
                disabled={addingNote || !noteContent.trim()}
                className="w-full py-2 rounded-lg bg-slate-850 hover:bg-slate-750 border border-slate-700/60 disabled:opacity-50 text-indigo-400 font-bold text-xs uppercase tracking-wider transition-all cursor-pointer"
              >
                {addingNote ? "Saving..." : "Append Journal Note"}
              </button>
            </form>
          </div>
        </div>

      </div>

      {/* CASE RESOLUTION MODAL OVERLAY */}
      {showResolveModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-md glass-panel rounded-2xl border-slate-800 overflow-hidden shadow-2xl p-6 space-y-5 animate-scale-up">
            <div>
              <h3 className="text-base font-bold text-white uppercase tracking-wider">Close Security Case</h3>
              <p className="text-slate-400 text-xs mt-1">Specify case resolution category and submit final investigative logs.</p>
            </div>

            <form onSubmit={handleResolve} className="space-y-4 text-xs font-semibold">
              {/* Verdict category selection */}
              <div className="space-y-1.5">
                <label className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block">Triage Verdict Resolution:</label>
                <select
                  value={resolutionReason}
                  onChange={(e) => setResolutionReason(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-850 focus:border-indigo-500 rounded-lg p-2.5 text-xs text-slate-300 outline-none transition-all cursor-pointer"
                >
                  <option value="True Positive Phishing">True Positive Phishing (Malicious link/attachment)</option>
                  <option value="BEC Impersonation Spam">BEC Impersonation Spam (Spoofed authority/scam)</option>
                  <option value="False Positive (Legitimate Email)">False Positive (Safe legitimate newsletter/message)</option>
                  <option value="Quarantined / Excluded Spam">Quarantined / Excluded Spam (Harmless commercial/marketing)</option>
                </select>
              </div>

              {/* Notes */}
              <div className="space-y-1.5">
                <label className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block">Final Investigation Summary (Logged to History):</label>
                <textarea
                  placeholder="Provide closing details: what indicators were validated, actions taken to protect user inbox, whether password reset was forced..."
                  value={resolutionNotes}
                  rows={4}
                  onChange={(e) => setResolutionNotes(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-850 focus:border-indigo-500 rounded-lg text-xs text-slate-200 placeholder-slate-600 outline-none transition-all shadow-inner resize-none leading-relaxed"
                />
              </div>

              <div className="flex items-center justify-end gap-3.5 pt-2">
                <button
                  type="button"
                  onClick={() => setShowResolveModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-850 hover:bg-slate-800 text-slate-400 font-bold uppercase tracking-wider transition-all cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={resolving}
                  className="px-5 py-2 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-extrabold uppercase tracking-widest transition-all cursor-pointer shadow-md"
                >
                  {resolving ? "Mitigating..." : "Confirm & Resolve"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
}

// --- LIGHTWEIGHT FORENSIC MARKDOWN RENDERING SYSTEM ---
const renderMarkdown = (text: string | null) => {
  if (!text) return null;
  
  const lines = text.split("\n");
  
  return lines.map((line, idx) => {
    // 1. Headers (### or ## or #)
    if (line.startsWith("### ")) {
      return (
        <h4 key={idx} className="text-xs font-bold text-slate-200 mt-4 mb-2 tracking-widest uppercase border-b border-slate-800/45 pb-1.5 font-mono text-indigo-400">
          {line.slice(4)}
        </h4>
      );
    }
    if (line.startsWith("## ")) {
      return (
        <h3 key={idx} className="text-sm font-bold text-white mt-5 mb-3 tracking-wider uppercase border-b border-slate-800 pb-1.5">
          {line.slice(3)}
        </h3>
      );
    }
    if (line.startsWith("# ")) {
      return (
        <h2 key={idx} className="text-base font-extrabold text-white mt-6 mb-3.5 tracking-wide uppercase border-b-2 border-slate-800 pb-2">
          {line.slice(2)}
        </h2>
      );
    }

    // 2. Bullet lists (e.g. - **Key**: value or - item)
    const listMatch = line.match(/^(\s*)-\s+(.*)$/);
    if (listMatch) {
      const bulletContent = listMatch[2];
      return (
        <div key={idx} className="flex items-start gap-2 ml-4 my-1 text-slate-300 leading-relaxed">
          <span className="text-indigo-500 mt-1 select-none font-bold">•</span>
          <span className="flex-1 text-slate-300">{parseInlineStyles(bulletContent)}</span>
        </div>
      );
    }

    // 3. Numbered lists (e.g. 1. **Key** or 1. item)
    const numMatch = line.match(/^(\s*)\d+\.\s+(.*)$/);
    if (numMatch) {
      const numContent = numMatch[2];
      const numberStr = line.match(/^\d+/)?.[0] || "1";
      return (
        <div key={idx} className="flex items-start gap-2 ml-2 my-1.5 text-slate-300 leading-relaxed">
          <span className="text-indigo-400 font-mono font-black">{numberStr}.</span>
          <span className="flex-1 text-slate-300">{parseInlineStyles(numContent)}</span>
        </div>
      );
    }

    // 4. Empty block
    if (!line.trim()) {
      return <div key={idx} className="h-2" />;
    }

    // 5. Standard line
    return (
      <p key={idx} className="my-1 text-slate-300 leading-relaxed font-sans">
        {parseInlineStyles(line)}
      </p>
    );
  });
};

const parseInlineStyles = (text: string) => {
  // Split line on **bold** or `code` marks
  const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);
  
  return parts.map((part, index) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return (
        <strong key={index} className="text-slate-100 font-extrabold text-[11px] bg-slate-950/20 px-1 py-0.5 rounded border border-slate-900/30">
          {part.slice(2, -2)}
        </strong>
      );
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code key={index} className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-850 text-indigo-400 font-mono text-[10px] font-bold">
          {part.slice(1, -1)}
        </code>
      );
    }
    return part;
  });
};
