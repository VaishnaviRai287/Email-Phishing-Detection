"use client";

import React, { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";

interface StatusCounts {
  open: number;
  investigating: number;
  resolved: number;
}

interface SeverityCounts {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

interface DashboardStats {
  total_incidents: number;
  severity_distribution: SeverityCounts;
  status_distribution: StatusCounts;
  avg_phishing_score: number;
}

export default function ReportsPage() {
  const router = useRouter();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  // Connection mode toggle: "env" or "custom"
  const [connectionMode, setConnectionMode] = useState<"env" | "custom">("env");
  
  // Custom IMAP Config states
  const [imapServer, setImapServer] = useState("");
  const [imapPort, setImapPort] = useState(993);
  const [imapEmail, setImapEmail] = useState("");
  const [imapPassword, setImapPassword] = useState("");
  const [imapLimit, setImapLimit] = useState(5);
  
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);

  // EML Uploader states
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<string | null>(null);
  const [uploadedIncidentId, setUploadedIncidentId] = useState<number | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const res = await fetch("http://localhost:8000/api/dashboard/stats");
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.error("Failed to load statistics: ", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  // IMAP SYNC TRIGGER
  const handleIMAPSync = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSyncing(true);
      setSyncMessage(null);
      setSyncError(null);

      let url = `http://localhost:8000/api/ingest/imap?limit=${imapLimit}`;
      let options: RequestInit = { method: "POST" };

      if (connectionMode === "custom") {
        if (!imapServer.trim() || !imapEmail.trim() || !imapPassword.trim()) {
          setSyncError("All connection fields are required for custom IMAP mode.");
          setSyncing(false);
          return;
        }
        options = {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            server: imapServer,
            port: imapPort,
            email_addr: imapEmail,
            password: imapPassword,
            limit: imapLimit
          })
        };
      }

      const res = await fetch(url, options);
      const data = await res.json();
      
      if (res.ok) {
        setSyncMessage(data.message || "IMAP Ingestion process completed successfully.");
        await fetchStats(); // Reload statistics
      } else {
        setSyncError(data.detail || "IMAP server connection failed. Verify your server values.");
      }
    } catch (err: any) {
      setSyncError("Error establishing connection to FastAPI local server.");
    } finally {
      setSyncing(false);
    }
  };

  // EML FILE UPLOAD LOGIC
  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processEmlFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processEmlFile(e.target.files[0]);
    }
  };

  const processEmlFile = async (file: File) => {
    if (!file.name.endsWith(".eml")) {
      setUploadError("Invalid file type. Please upload a raw suspicious email ending in .eml");
      return;
    }

    try {
      setUploading(true);
      setUploadError(null);
      setUploadedIncidentId(null);
      
      setUploadProgress("Parsing email structure & authentication headers...");
      await new Promise((r) => setTimeout(r, 800)); // Visual micro-delay

      setUploadProgress("Running threat score metrics & VirusTotal link lookups...");
      await new Promise((r) => setTimeout(r, 800));

      setUploadProgress("Prompting Gemini AI Level-3 triage assistant report...");
      
      const formData = new FormData();
      formData.append("file", file);

      const res = await fetch("http://localhost:8000/api/ingest/upload", {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      if (res.ok) {
        setUploadedIncidentId(data.id);
        setUploadProgress("Ingestion complete!");
        await fetchStats(); // Refresh dashboard stats
      } else {
        setUploadError(data.detail || "Failed to process and analyze the email file.");
      }
    } catch (err) {
      setUploadError("Could not connect to FastAPI server. Ensure uvicorn is running.");
    } finally {
      setUploading(false);
    }
  };

  const handleCSVDownload = () => {
    window.open("http://localhost:8000/api/reports/csv", "_blank");
  };

  return (
    <div className="space-y-8">
      {/* Title */}
      <div>
        <h2 className="text-xl font-bold text-white uppercase tracking-wider">Triage Reporting Center</h2>
        <p className="text-slate-400 text-xs mt-1">Ingest custom threat files, sync direct mailbox queues, and export database tables.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        
        {/* Left Column (7 cols): Ingestion Forms */}
        <div className="lg:col-span-7 space-y-6">
          
          {/* EML FILE DROPZONE UPLOADER */}
          <div className="glass-panel p-6 rounded-xl border-slate-800 space-y-5">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Secure Raw EML Uploader</h3>
              <p className="text-slate-400 text-xs mt-1 leading-relaxed">
                Analyze single suspicious email envelopes. Drag and drop any raw <code className="text-slate-300 font-mono">.eml</code> packet file below to trigger immediate parsing, authentication verification, VirusTotal scans, and Gemini summary drafts.
              </p>
            </div>

            {/* Dropzone visual container */}
            <div
              onDragEnter={handleDrag}
              onDragOver={handleDrag}
              onDragLeave={handleDrag}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all duration-300 ${
                dragActive
                  ? "border-indigo-500 bg-indigo-950/20 shadow-[0_0_15px_rgba(99,102,241,0.15)]"
                  : "border-slate-800 hover:border-slate-700 bg-slate-950/20"
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml"
                onChange={handleFileChange}
                className="hidden"
              />

              {uploading ? (
                <div className="space-y-4 py-3">
                  <span className="w-9 h-9 mx-auto rounded-full border-3 border-indigo-600/30 border-t-indigo-500 animate-spin block" />
                  <div className="text-xs text-indigo-400 font-bold uppercase tracking-wider animate-pulse">{uploadProgress}</div>
                </div>
              ) : uploadedIncidentId ? (
                <div className="space-y-4 py-2">
                  <div className="w-10 h-10 mx-auto rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                    <svg className="w-5 h-5 animate-bounce" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                  <div>
                    <div className="text-xs font-bold text-slate-200 uppercase tracking-wide">Threat Ingested Successfully!</div>
                    <p className="text-[11px] text-slate-400 mt-1">Incident registered under case ticket #{uploadedIncidentId}</p>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      router.push(`/incidents/${uploadedIncidentId}`);
                    }}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold uppercase tracking-wider transition-all shadow-md cursor-pointer"
                  >
                    Open Forensic Investigation
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M9 5l7 7-7 7" />
                    </svg>
                  </button>
                </div>
              ) : (
                <div className="space-y-3 py-4">
                  <div className="w-12 h-12 mx-auto rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-400">
                    <svg className="w-5.5 h-5.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                  </div>
                  <div>
                    <span className="text-xs font-bold text-slate-300 block">Drag & drop raw email packet here</span>
                    <span className="text-[10px] text-slate-500 mt-1 block">or click to browse local workstation files (.eml)</span>
                  </div>
                </div>
              )}
            </div>

            {uploadError && (
              <div className="p-3 bg-rose-950/15 border border-rose-900/25 rounded-lg text-rose-400 text-xs font-medium">
                <span className="font-bold">Parsing Error:</span> {uploadError}
              </div>
            )}
          </div>

          {/* DYNAMIC IMAP sync console */}
          <div className="glass-panel p-6 rounded-xl border-slate-800 space-y-5">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">IMAP Mailbox Connection</h3>
                <p className="text-slate-400 text-xs mt-1 leading-relaxed">Connect to active email servers to pull down real-time alerts.</p>
              </div>

              {/* Mode switch pills */}
              <div className="bg-slate-950 p-1 rounded-lg border border-slate-850 flex items-center gap-1 font-sans text-[10px] font-bold uppercase tracking-wider shrink-0">
                <button
                  type="button"
                  onClick={() => setConnectionMode("env")}
                  className={`px-3 py-1.5 rounded-md cursor-pointer transition-all ${
                    connectionMode === "env" ? "bg-indigo-600/20 text-indigo-300" : "text-slate-500 hover:text-slate-300"
                  }`}
                >
                  Local .env Keys
                </button>
                <button
                  type="button"
                  onClick={() => setConnectionMode("custom")}
                  className={`px-3 py-1.5 rounded-md cursor-pointer transition-all ${
                    connectionMode === "custom" ? "bg-indigo-600/20 text-indigo-300" : "text-slate-500 hover:text-slate-300"
                  }`}
                >
                  Custom UI Config
                </button>
              </div>
            </div>

            <form onSubmit={handleIMAPSync} className="space-y-4 text-xs font-semibold">
              {/* Conditional custom connection form */}
              {connectionMode === "custom" && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 animate-fade-in">
                  <div className="space-y-1.5">
                    <label className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">IMAP Host Server:</label>
                    <input
                      type="text"
                      placeholder="e.g. imap.gmail.com"
                      value={imapServer}
                      onChange={(e) => setImapServer(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-950/70 border border-slate-850 focus:border-indigo-500 rounded-lg text-slate-200 outline-none transition-all shadow-inner"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">SSL Security Port:</label>
                    <input
                      type="number"
                      placeholder="993"
                      value={imapPort}
                      onChange={(e) => setImapPort(Number(e.target.value))}
                      className="w-full px-3 py-2 bg-slate-950/70 border border-slate-850 focus:border-indigo-500 rounded-lg text-slate-200 outline-none transition-all shadow-inner"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Email Address:</label>
                    <input
                      type="email"
                      placeholder="analyst-mailbox@corp.com"
                      value={imapEmail}
                      onChange={(e) => setImapEmail(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-950/70 border border-slate-850 focus:border-indigo-500 rounded-lg text-slate-200 outline-none transition-all shadow-inner"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">MFA Security App Password:</label>
                    <input
                      type="password"
                      placeholder="16-character secure code"
                      value={imapPassword}
                      onChange={(e) => setImapPassword(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-950/70 border border-slate-850 focus:border-indigo-500 rounded-lg text-slate-200 outline-none transition-all shadow-inner"
                    />
                  </div>
                </div>
              )}

              {connectionMode === "env" && (
                <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-850 text-slate-400 text-[11px] leading-relaxed">
                  System will connect using environment credentials defined in backend <code className="text-slate-300 font-mono">.env</code>:
                  <div className="font-mono mt-1 text-slate-500">
                    Host: server-side | SSL Port: 993 | Auth: env_credentials
                  </div>
                </div>
              )}

              {/* Sync limit and Trigger button */}
              <div className="flex flex-wrap items-center justify-between gap-4 pt-2">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Sync limit:</span>
                  <select
                    value={imapLimit}
                    onChange={(e) => setImapLimit(Number(e.target.value))}
                    className="bg-slate-950 border border-slate-850 rounded-lg px-3 py-1.5 text-xs text-slate-300 outline-none cursor-pointer"
                  >
                    <option value={1}>1 latest email</option>
                    <option value={5}>5 latest emails</option>
                    <option value={10}>10 latest emails</option>
                    <option value={20}>20 latest emails</option>
                  </select>
                </div>

                <button
                  type="submit"
                  disabled={syncing}
                  className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-850 disabled:opacity-50 text-white font-bold text-xs uppercase tracking-wider transition-all cursor-pointer shadow-md"
                >
                  {syncing ? (
                    <>
                      <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      FETCHING INBOX...
                    </>
                  ) : (
                    <>
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 6.571M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      Execute Mail Sync
                    </>
                  )}
                </button>
              </div>
            </form>

            {/* Results feedback */}
            {syncMessage && (
              <div className="p-3 bg-emerald-950/20 border border-emerald-900/35 rounded-lg text-emerald-400 text-xs">
                <span className="font-bold">Sync Completed:</span> {syncMessage}
              </div>
            )}
            
            {syncError && (
              <div className="p-4 bg-rose-950/15 border border-rose-900/25 rounded-lg space-y-2 text-xs">
                <div className="text-rose-400 font-bold">IMAP Sync Failed:</div>
                <p className="text-slate-400 leading-relaxed text-[11px]">{syncError}</p>
                <div className="pt-2 text-[10px] text-slate-500 leading-normal border-t border-rose-950/40">
                  <span className="font-bold uppercase tracking-wider text-slate-400 block mb-1">Configuration Guidelines:</span>
                  - Enable <span className="font-bold">IMAP Access</span> inside Gmail settings.<br />
                  - Set host server to <code className="text-slate-400 font-mono">imap.gmail.com</code> (or Microsoft equivalent).<br />
                  - Ensure Gmail account has <span className="font-bold">2-Step Verification</span> active.<br />
                  - Generate a 16-character <span className="font-bold">App Password</span> as your password credentials.
                </div>
              </div>
            )}
          </div>

        </div>

        {/* Right Column (5 cols): Exports and Ratios */}
        <div className="lg:col-span-5 space-y-6">
          
          {/* Database CSV Download */}
          <div className="glass-panel p-6 rounded-xl border-slate-800 space-y-5">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Triage Database Exports</h3>
              <p className="text-slate-400 text-xs mt-1 leading-relaxed">Download a comprehensive CSV workbook of all processed security incidents. This workbook contains sender addresses, validation signatures, heuristic scores, incident owners, and mitigation verdicts for audits.</p>
            </div>

            <button
              onClick={handleCSVDownload}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-slate-850 hover:bg-slate-750 text-indigo-400 font-bold text-xs uppercase tracking-wider border border-slate-700/60 shadow-md cursor-pointer transition-all w-full justify-center"
            >
              <svg className="w-4.5 h-4.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Download Database Workbook (CSV)
            </button>
          </div>

          {/* Metrics Summary Table */}
          <div className="glass-panel p-6 rounded-xl border-slate-800 space-y-5">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Threat Scope Ratios</h3>
              <p className="text-slate-500 text-[11px] mt-0.5">Statistical distributions of triaged incidents.</p>
            </div>

            {loading ? (
              <div className="text-xs text-slate-500 text-center py-6">Calculating ratios...</div>
            ) : !stats || stats.total_incidents === 0 ? (
              <div className="text-xs text-slate-500 italic text-center py-6">No incident cases processed yet.</div>
            ) : (
              <div className="space-y-5 text-xs font-semibold leading-relaxed">
                {/* Severity Breakdown */}
                <div className="space-y-2">
                  <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block">Severity distribution:</span>
                  <div className="space-y-1.5 font-mono text-[11px] text-slate-400">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-300">Critical:</span>
                      <span className="font-bold text-rose-400">{stats.severity_distribution.critical} ({((stats.severity_distribution.critical / stats.total_incidents) * 100).toFixed(0)}%)</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-300">High:</span>
                      <span className="font-bold text-orange-400">{stats.severity_distribution.high} ({((stats.severity_distribution.high / stats.total_incidents) * 100).toFixed(0)}%)</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-300">Medium:</span>
                      <span className="font-bold text-yellow-400">{stats.severity_distribution.medium} ({((stats.severity_distribution.medium / stats.total_incidents) * 100).toFixed(0)}%)</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-300">Low:</span>
                      <span className="font-bold text-blue-400">{stats.severity_distribution.low} ({((stats.severity_distribution.low / stats.total_incidents) * 100).toFixed(0)}%)</span>
                    </div>
                  </div>
                </div>

                <div className="h-px bg-slate-800/40" />

                {/* Status Breakdown */}
                <div className="space-y-2">
                  <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider block">Resolution Status split:</span>
                  <div className="space-y-1.5 font-mono text-[11px] text-slate-400">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-300">Open (New):</span>
                      <span className="font-bold text-slate-300">{stats.status_distribution.open}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-300">Investigating (Assigned):</span>
                      <span className="font-bold text-amber-400">{stats.status_distribution.investigating}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-300">Resolved (Mitigated):</span>
                      <span className="font-bold text-emerald-400">{stats.status_distribution.resolved}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
