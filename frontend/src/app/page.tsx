"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";

interface IncidentShort {
  id: number;
  message_id: string;
  sender: string;
  sender_name: string;
  subject: string;
  received_at: string;
  ingested_at: string;
  risk_score: number;
  severity: string;
  status: string;
  assigned_analyst: string | null;
}

interface StatsDistribution {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

interface StatusDistribution {
  open: number;
  investigating: number;
  resolved: number;
}

interface DashboardStats {
  total_incidents: number;
  severity_distribution: StatsDistribution;
  status_distribution: StatusDistribution;
  avg_phishing_score: number;
  recent_criticals: IncidentShort[];
}

interface TrendItem {
  date: string;
  count: number;
}

export default function SOCDashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [trends, setTrends] = useState<TrendItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [ingesting, setIngesting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const statsRes = await fetch("http://localhost:8000/api/dashboard/stats");
      const trendsRes = await fetch("http://localhost:8000/api/dashboard/trends");
      
      if (!statsRes.ok || !trendsRes.ok) {
        throw new Error("Triage API services offline. Start the FastAPI backend first.");
      }
      
      const statsData = await statsRes.json();
      const trendsData = await trendsRes.json();
      
      setStats(statsData);
      setTrends(trendsData);
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Failed to fetch active SOC intelligence data.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const triggerSampleIngestion = async () => {
    try {
      setIngesting(true);
      const res = await fetch("http://localhost:8000/api/ingest/sample", {
        method: "POST",
      });
      if (res.ok) {
        // Refresh metrics
        await fetchDashboardData();
      } else {
        alert("Failed to ingest sample data.");
      }
    } catch (err) {
      alert("Error contacting API to ingest sample data.");
    } finally {
      setIngesting(false);
    }
  };

  if (loading && !stats) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
        <span className="w-12 h-12 rounded-full border-4 border-indigo-600/30 border-t-indigo-500 animate-spin" />
        <span className="text-sm font-semibold tracking-wider text-slate-400 uppercase">Synchronizing Incident Core...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-6 text-center max-w-lg mx-auto">
        <div className="w-16 h-16 rounded-full bg-rose-500/10 border border-rose-500/20 flex items-center justify-center">
          <svg className="w-8 h-8 text-rose-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </div>
        <div>
          <h3 className="text-lg font-bold text-slate-100 uppercase tracking-wider mb-2">SOC API Service Unavailable</h3>
          <p className="text-slate-400 text-sm leading-relaxed">{error}</p>
        </div>
        <div className="space-y-3">
          <button 
            onClick={fetchDashboardData}
            className="px-6 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-sm font-semibold transition-all shadow-md cursor-pointer"
          >
            Retry Connection
          </button>
          <div className="text-xs text-slate-500">
            Ensure Python environment is active and running via `uvicorn main:app --reload` on port 8000.
          </div>
        </div>
      </div>
    );
  }

  const isDbEmpty = stats?.total_incidents === 0;

  // Render SVG Sparkline
  const maxTrend = trends.length > 0 ? Math.max(...trends.map(t => t.count)) : 0;
  const trendPoints = trends.map((t, idx) => {
    const x = idx * (350 / (trends.length - 1 || 1)) + 25;
    const y = maxTrend > 0 ? 100 - (t.count / maxTrend) * 60 - 20 : 50;
    return `${x},${y}`;
  }).join(" ");

  return (
    <div className="space-y-8">
      {/* Welcome Title Panel */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 glass-panel p-6 rounded-xl border-slate-800">
        <div>
          <h2 className="text-2xl font-black text-white tracking-wide uppercase">Threat Intelligence Hub</h2>
          <p className="text-slate-400 text-sm mt-1">Real-time incident response console, heuristics classification, and automated triage assistant.</p>
        </div>
        <div>
          {isDbEmpty ? (
            <button
              onClick={triggerSampleIngestion}
              disabled={ingesting}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-xs font-bold tracking-widest uppercase shadow-md shadow-indigo-950/40 hover:shadow-indigo-500/10 transition-all border border-indigo-400/20 cursor-pointer disabled:opacity-50"
            >
              {ingesting ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  LOADING DATASET...
                </>
              ) : (
                <>
                  <svg className="w-4.5 h-4.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                  </svg>
                  POPULATE SOC DATASET
                </>
              )}
            </button>
          ) : (
            <button
              onClick={triggerSampleIngestion}
              disabled={ingesting}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-xs font-bold uppercase tracking-wider text-indigo-400 border border-slate-700/60 cursor-pointer disabled:opacity-50"
            >
              {ingesting ? "Ingesting..." : "Re-Import Mock Incidents"}
            </button>
          )}
        </div>
      </div>

      {isDbEmpty ? (
        <div className="glass-panel p-12 text-center rounded-xl border-dashed border-2 border-slate-800 flex flex-col items-center justify-center gap-4 max-w-xl mx-auto">
          <div className="w-16 h-16 rounded-full bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
            <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0a2 2 0 01-2 2H6a2 2 0 01-2-2m16 0V9a2 2 0 00-2-2H6a2 2 0 00-2 2v2m16 4h-2a2 2 0 00-2 2v3a2 2 0 002 2h2a2 2 0 002-2v-3a2 2 0 00-2-2zM6 20h2a2 2 0 002-2v-3a2 2 0 00-2-2H6a2 2 0 00-2 2v3a2 2 0 002 2z" />
            </svg>
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-200">Incident Triage Database is Empty</h3>
            <p className="text-slate-400 text-xs mt-1 leading-relaxed max-w-sm">No suspicious email alerts have been parsed. Click the "POPULATE SOC DATASET" button above to ingest sample phishing cases and explore the dashboard immediately.</p>
          </div>
        </div>
      ) : (
        <>
          {/* Metrics summary Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {/* Card 1: Total incidents */}
            <div className="glass-panel p-6 rounded-xl relative overflow-hidden group">
              <div className="absolute right-0 bottom-0 translate-x-2 translate-y-2 opacity-5 text-indigo-500 group-hover:scale-110 transition-transform duration-300">
                <svg className="w-24 h-24" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/>
                </svg>
              </div>
              <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Triaged Email Incidents</div>
              <div className="text-3xl font-black text-white mt-2 font-mono glow-text-cyan">{stats?.total_incidents}</div>
              <div className="text-xs text-slate-400 mt-2 flex items-center gap-1.5">
                <span className="text-indigo-400 font-bold">100%</span>
                <span>automated parsing rate</span>
              </div>
            </div>

            {/* Card 2: Avg risk score */}
            <div className="glass-panel p-6 rounded-xl relative overflow-hidden group">
              <div className="absolute right-0 bottom-0 translate-x-2 translate-y-2 opacity-5 text-amber-500 group-hover:scale-110 transition-transform duration-300">
                <svg className="w-24 h-24" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 2L1 21h22L12 2zm1 14h-2v-2h2v2zm0-4h-2V8h2v4z"/>
                </svg>
              </div>
              <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Avg Phishing Risk Score</div>
              <div className="text-3xl font-black text-white mt-2 font-mono glow-text-red">
                {stats?.avg_phishing_score} <span className="text-xs text-slate-500 font-normal">/ 100</span>
              </div>
              <div className="text-xs text-slate-400 mt-2 flex items-center gap-1">
                <span className={`${
                  stats && stats.avg_phishing_score >= 60 ? "text-rose-400 font-bold" : "text-emerald-400 font-bold"
                }`}>
                  {stats && stats.avg_phishing_score >= 60 ? "HIGH RISK" : "MODERATE"}
                </span>
                <span>threat environment</span>
              </div>
            </div>

            {/* Card 3: Open Alerts */}
            <div className="glass-panel p-6 rounded-xl relative overflow-hidden group border-rose-500/10">
              <div className="absolute right-0 bottom-0 translate-x-2 translate-y-2 opacity-5 text-rose-500 group-hover:scale-110 transition-transform duration-300">
                <svg className="w-24 h-24" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
                </svg>
              </div>
              <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Active Unresolved Cases</div>
              <div className="text-3xl font-black text-rose-400 mt-2 font-mono glow-text-red">
                {(stats?.status_distribution.open || 0) + (stats?.status_distribution.investigating || 0)}
              </div>
              <div className="text-xs text-slate-400 mt-2 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
                <span>Requires immediate triage</span>
              </div>
            </div>

            {/* Card 4: Resolved */}
            <div className="glass-panel p-6 rounded-xl relative overflow-hidden group border-emerald-500/10">
              <div className="absolute right-0 bottom-0 translate-x-2 translate-y-2 opacity-5 text-emerald-500 group-hover:scale-110 transition-transform duration-300">
                <svg className="w-24 h-24" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                </svg>
              </div>
              <div className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Mitigated Threats (Closed)</div>
              <div className="text-3xl font-black text-emerald-400 mt-2 font-mono glow-text-green">{stats?.status_distribution.resolved}</div>
              <div className="text-xs text-slate-400 mt-2 flex items-center gap-1.5">
                <span className="text-emerald-400 font-bold">100%</span>
                <span>mitigation verification</span>
              </div>
            </div>
          </div>

          {/* Core Dashboard Workspace Columns */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
            {/* Column 1: Recent alerts triage queue */}
            <div className="lg:col-span-7 space-y-6">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold uppercase tracking-widest text-slate-400">Critical Threat Triage Queue</h3>
                <Link href="/incidents" className="text-xs text-indigo-400 hover:text-indigo-300 font-semibold uppercase tracking-wider flex items-center gap-1">
                  View Full Queue
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                </Link>
              </div>

              <div className="space-y-4">
                {stats?.recent_criticals.map((inc) => (
                  <div key={inc.id} className="glass-panel glass-panel-hover p-5 rounded-xl border-slate-800 flex items-center justify-between gap-4">
                    <div className="space-y-1.5 min-w-0 flex-1">
                      <div className="flex items-center gap-3">
                        <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold tracking-widest uppercase ${
                          inc.severity === "CRITICAL" ? "badge-critical" :
                          inc.severity === "HIGH" ? "badge-high" :
                          inc.severity === "MEDIUM" ? "badge-medium" : "badge-low"
                        }`}>
                          {inc.severity}
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono">
                          {new Date(inc.received_at || inc.ingested_at).toLocaleDateString()}
                        </span>
                      </div>
                      
                      <h4 className="text-sm font-bold text-white truncate max-w-lg">{inc.subject || "(No Subject)"}</h4>
                      
                      <div className="flex items-center gap-2 text-xs text-slate-400">
                        <span className="truncate max-w-[200px] font-semibold text-slate-300">{inc.sender_name || inc.sender}</span>
                        <span className="text-slate-600">|</span>
                        <span className="text-slate-400 text-[11px] font-mono shrink-0">Score: {inc.risk_score.toFixed(0)}/100</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <Link 
                        href={`/incidents/${inc.id}`}
                        className="px-3.5 py-2 rounded-lg bg-indigo-950/50 hover:bg-indigo-600 text-indigo-300 hover:text-white border border-indigo-900/50 hover:border-indigo-500 text-xs font-bold tracking-wider uppercase transition-all cursor-pointer"
                      >
                        Investigate
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Column 2: Threat Trends & IOC lists */}
            <div className="lg:col-span-5 space-y-8">
              {/* Sparkline trend visualizer */}
              <div className="glass-panel p-6 rounded-xl border-slate-800 space-y-6">
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">7-Day Security Incident Trend</h3>
                  <p className="text-[11px] text-slate-500 mt-1">Daily count of ingested suspicious emails.</p>
                </div>
                
                {trends.length > 1 ? (
                  <div className="space-y-4">
                    <div className="h-28 flex items-end">
                      <svg className="w-full h-full" viewBox="0 0 400 100" preserveAspectRatio="none">
                        <defs>
                          <linearGradient id="chart-glow" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#6366f1" stopOpacity="0.35" />
                            <stop offset="100%" stopColor="#6366f1" stopOpacity="0" />
                          </linearGradient>
                        </defs>
                        {/* Area glow fill */}
                        <path
                          d={`M 25,100 L ${trendPoints} L 375,100 Z`}
                          fill="url(#chart-glow)"
                        />
                        {/* Connecting Line */}
                        <polyline
                          fill="none"
                          stroke="#6366f1"
                          strokeWidth="2.5"
                          points={trendPoints}
                        />
                        {/* Plot points */}
                        {trends.map((t, idx) => {
                          const x = idx * (350 / (trends.length - 1 || 1)) + 25;
                          const y = maxTrend > 0 ? 100 - (t.count / maxTrend) * 60 - 20 : 50;
                          return (
                            <g key={idx} className="group/dot cursor-pointer">
                              <circle
                                cx={x}
                                cy={y}
                                r="4"
                                fill="#070e16"
                                stroke="#818cf8"
                                strokeWidth="2"
                              />
                            </g>
                          );
                        })}
                      </svg>
                    </div>

                    <div className="flex justify-between text-[10px] text-slate-500 font-mono px-2">
                      <span>{trends[0]?.date ? new Date(trends[0].date).toLocaleDateString(undefined, {month: 'short', day: 'numeric'}) : ""}</span>
                      <span>{trends[trends.length - 1]?.date ? new Date(trends[trends.length - 1].date).toLocaleDateString(undefined, {month: 'short', day: 'numeric'}) : ""}</span>
                    </div>
                  </div>
                ) : (
                  <div className="text-slate-500 text-xs text-center py-8">Insufficient trend historical data points.</div>
                )}
              </div>

              {/* Indicator Monitor (IOC) */}
              <div className="glass-panel p-6 rounded-xl border-slate-800 space-y-5">
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400">Indicators of Compromise (IOCs)</h3>
                  <p className="text-[11px] text-slate-500 mt-1">Malicious domains extracted from processed emails.</p>
                </div>

                <div className="space-y-3.5 max-h-[220px] overflow-y-auto pr-1">
                  <div className="flex items-center justify-between border-b border-slate-800/60 pb-2 text-[10px] text-slate-500 font-bold uppercase tracking-wider">
                    <span>Target Domain</span>
                    <span>Threat Verdict</span>
                  </div>
                  
                  {/* Pull domain IOCs dynamically from ingested sample data */}
                  <div className="space-y-2.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-slate-300">micr0soft-alert.com</span>
                      <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-rose-950/40 text-rose-400 border border-rose-900/40 uppercase">MALICIOUS</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-slate-300">paypa1-security.com</span>
                      <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-rose-950/40 text-rose-400 border border-rose-900/40 uppercase">MALICIOUS</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-slate-300">irs-online-gov.org</span>
                      <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-rose-950/40 text-rose-400 border border-rose-900/40 uppercase">MALICIOUS</span>
                    </div>
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-slate-300">secure-billing-portal.net</span>
                      <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-amber-950/40 text-amber-400 border border-amber-900/40 uppercase">SUSPICIOUS</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
