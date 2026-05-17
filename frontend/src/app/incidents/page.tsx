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

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<IncidentShort[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filter States
  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Build query params
      const params = new URLSearchParams();
      if (statusFilter) params.append("status", statusFilter);
      if (severityFilter) params.append("severity", severityFilter);
      if (searchQuery) params.append("search", searchQuery);

      const res = await fetch(`http://localhost:8000/api/incidents?${params.toString()}`);
      if (!res.ok) {
        throw new Error("Failed to load incidents desk database.");
      }
      
      const data = await res.json();
      setIncidents(data);
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Failed to contact SOC backend services.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Debounce search input changes slightly
    const delayDebounce = setTimeout(() => {
      fetchIncidents();
    }, 250);
    return () => clearTimeout(delayDebounce);
  }, [statusFilter, severityFilter, searchQuery]);

  return (
    <div className="space-y-6">
      {/* Title Header */}
      <div>
        <h2 className="text-xl font-bold text-white uppercase tracking-wider">Security Incident Desk</h2>
        <p className="text-slate-400 text-xs mt-1">Triaging and investigation queue for parsed email vectors.</p>
      </div>

      {/* Search and Filters panel */}
      <div className="glass-panel p-5 rounded-xl border-slate-800 flex flex-col md:flex-row gap-4 items-center justify-between">
        {/* Search */}
        <div className="relative w-full md:w-80">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <svg className="h-4 w-4 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          </span>
          <input
            type="text"
            placeholder="Search sender, subject..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-slate-950/65 border border-slate-850 hover:border-slate-750 focus:border-indigo-500 rounded-lg text-xs font-semibold text-slate-200 placeholder-slate-500 outline-none transition-all shadow-inner"
          />
        </div>

        {/* Dropdown Filters */}
        <div className="flex flex-wrap items-center gap-3.5 w-full md:w-auto">
          {/* Status filter */}
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950/65 border border-slate-850 focus:border-indigo-500 rounded-lg px-3 py-1.5 text-xs font-semibold text-slate-300 outline-none transition-all cursor-pointer"
            >
              <option value="">ALL STATUS</option>
              <option value="OPEN">OPEN</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
            </select>
          </div>

          {/* Severity filter */}
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950/65 border border-slate-850 focus:border-indigo-500 rounded-lg px-3 py-1.5 text-xs font-semibold text-slate-300 outline-none transition-all cursor-pointer"
            >
              <option value="">ALL SEVERITY</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main incidents table */}
      <div className="glass-panel rounded-xl border-slate-800 overflow-hidden shadow-xl">
        {loading && incidents.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3">
            <span className="w-8 h-8 rounded-full border-4 border-indigo-600/30 border-t-indigo-500 animate-spin" />
            <span className="text-xs text-slate-400 font-medium">Updating desk table...</span>
          </div>
        ) : error ? (
          <div className="text-center py-16 text-rose-400 font-semibold text-xs">{error}</div>
        ) : incidents.length === 0 ? (
          <div className="text-center py-20 text-slate-500 text-xs">No incidents match the search criteria.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-850 bg-[#090f17]/60 text-[10px] text-slate-500 font-bold uppercase tracking-wider">
                  <th className="py-4 px-6">Risk Score</th>
                  <th className="py-4 px-6">Subject</th>
                  <th className="py-4 px-6">Sender Address</th>
                  <th className="py-4 px-6">Ingested Date</th>
                  <th className="py-4 px-6">Case Status</th>
                  <th className="py-4 px-6">Owner</th>
                  <th className="py-4 px-6 text-center">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850/45 text-xs">
                {incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-slate-800/15 transition-all">
                    {/* Risk Score */}
                    <td className="py-4 px-6 font-mono">
                      <div className="flex items-center gap-2">
                        <span className={`w-2.5 h-2.5 rounded-full ${
                          inc.severity === "CRITICAL" ? "bg-rose-500 animate-pulse" :
                          inc.severity === "HIGH" ? "bg-orange-500" :
                          inc.severity === "MEDIUM" ? "bg-yellow-500" : "bg-blue-500"
                        }`} />
                        <span className="font-black text-slate-200">{inc.risk_score.toFixed(0)}</span>
                        <span className="text-[10px] text-slate-500">/100</span>
                      </div>
                    </td>

                    {/* Subject */}
                    <td className="py-4 px-6 font-semibold text-slate-200 max-w-[280px] truncate">
                      <Link href={`/incidents/${inc.id}`} className="hover:text-indigo-400 transition-colors">
                        {inc.subject || "(No Subject)"}
                      </Link>
                    </td>

                    {/* Sender */}
                    <td className="py-4 px-6 font-mono text-slate-400 max-w-[200px] truncate">
                      {inc.sender}
                    </td>

                    {/* Timestamp */}
                    <td className="py-4 px-6 text-slate-400 font-mono">
                      {new Date(inc.received_at || inc.ingested_at).toLocaleString(undefined, {
                        month: "short",
                        day: "2-digit",
                        hour: "2-digit",
                        minute: "2-digit",
                        hour12: false,
                      })}
                    </td>

                    {/* Status badge */}
                    <td className="py-4 px-6">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase tracking-wider ${
                        inc.status === "RESOLVED" ? "badge-resolved" :
                        inc.status === "INVESTIGATING" ? "badge-medium" : "badge-low"
                      }`}>
                        {inc.status}
                      </span>
                    </td>

                    {/* Analyst Assigned */}
                    <td className="py-4 px-6 text-slate-300 font-medium">
                      {inc.assigned_analyst || (
                        <span className="text-slate-600 text-[11px] italic">Unassigned</span>
                      )}
                    </td>

                    {/* Action */}
                    <td className="py-4 px-6 text-center">
                      <Link
                        href={`/incidents/${inc.id}`}
                        className="px-3.5 py-1.5 rounded bg-indigo-950/40 hover:bg-indigo-600 text-indigo-400 hover:text-white border border-indigo-900/50 hover:border-indigo-500 text-[10px] font-black uppercase tracking-widest transition-all cursor-pointer"
                      >
                        Triage Case
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
