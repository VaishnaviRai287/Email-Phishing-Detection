"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

interface DashboardLayoutProps {
  children: React.ReactNode;
}

export default function DashboardLayout({ children }: DashboardLayoutProps) {
  const pathname = usePathname();
  const [time, setTime] = useState("");
  const [dbStatus, setDbStatus] = useState<"checking" | "online" | "offline">("checking");

  useEffect(() => {
    // Tick clock every second
    const updateClock = () => {
      const now = new Date();
      setTime(
        now.toLocaleDateString("en-US", {
          month: "short",
          day: "2-digit",
          year: "numeric",
        }) + " | " + now.toLocaleTimeString("en-US", { hour12: false }) + " UTC"
      );
    };
    updateClock();
    const interval = setInterval(updateClock, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Ping API server to check status
    const checkServer = async () => {
      try {
        const res = await fetch("http://localhost:8000/");
        if (res.ok) {
          setDbStatus("online");
        } else {
          setDbStatus("offline");
        }
      } catch (err) {
        setDbStatus("offline");
      }
    };
    checkServer();
    const checkInterval = setInterval(checkServer, 10000); // Check every 10s
    return () => clearInterval(checkInterval);
  }, []);

  const navItems = [
    {
      name: "SOC Overview",
      path: "/",
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2H6a2 2 0 01-2-2v-4zM14 16a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2h-2a2 2 0 01-2-2v-4z" />
        </svg>
      ),
    },
    {
      name: "Incident Triage",
      path: "/incidents",
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      ),
    },
    {
      name: "Triage & Reports",
      path: "/reports",
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
      ),
    },
  ];

  return (
    <div className="flex min-h-screen bg-[#070e16] text-slate-100 font-sans selection:bg-indigo-500 selection:text-white">
      {/* Sidebar Navigation */}
      <aside className="w-64 border-r border-slate-800 bg-[#080d15]/90 flex flex-col justify-between shrink-0">
        <div>
          {/* Logo Brand Header */}
          <div className="h-16 flex items-center px-6 border-b border-slate-800/60">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-rose-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-indigo-500/10">
                <svg className="w-4.5 h-4.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div>
                <span className="font-bold text-sm tracking-wider uppercase bg-gradient-to-r from-slate-100 to-slate-400 bg-clip-text text-transparent">PHISH-SHIELD</span>
                <div className="text-[10px] text-indigo-400 font-semibold tracking-widest uppercase glow-text-cyan">SOC Triage v1</div>
              </div>
            </div>
          </div>

          {/* Links */}
          <nav className="p-4 space-y-1">
            {navItems.map((item) => {
              const active = pathname === item.path || (item.path !== "/" && pathname?.startsWith(item.path));
              return (
                <Link
                  key={item.name}
                  href={item.path}
                  className={`flex items-center gap-3.5 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                    active
                      ? "bg-indigo-600/15 border-l-2 border-indigo-500 text-indigo-300 shadow-sm"
                      : "text-slate-400 hover:bg-slate-800/40 hover:text-slate-200"
                  }`}
                >
                  {item.icon}
                  {item.name}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* System Information Panel */}
        <div className="p-4 border-t border-slate-800/60 bg-[#060a10]/55 space-y-3.5">
          <div className="space-y-1">
            <div className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider">Engine Status</div>
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full animate-pulse ${
                dbStatus === "online" ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" : "bg-rose-500"
              }`} />
              <span className="text-xs font-semibold capitalize text-slate-300">
                {dbStatus === "online" ? "Active (API Online)" : "Triage Engine Offline"}
              </span>
            </div>
          </div>

          <div className="h-px bg-slate-800/40" />

          <div>
            <div className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider mb-0.5">Active Agent</div>
            <div className="text-xs font-medium text-slate-300">SOC Analyst #94</div>
          </div>
        </div>
      </aside>

      {/* Main Panel Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header Top Bar */}
        <header className="h-16 border-b border-slate-800 bg-[#070e16]/80 backdrop-blur-md flex items-center justify-between px-8 z-10 shrink-0">
          <div className="flex items-center gap-4">
            <h1 className="text-base font-bold text-slate-200 tracking-wide uppercase">
              {pathname === "/" && "Incident Response Console"}
              {pathname?.startsWith("/incidents") && "Security Incident Desk"}
              {pathname === "/reports" && "Triage Reporting Center"}
            </h1>
          </div>

          <div className="flex items-center gap-6">
            {/* Live Clock Timer */}
            <div className="text-xs font-mono text-indigo-400 bg-indigo-950/35 border border-indigo-900/40 px-3.5 py-1.5 rounded-md shadow-inner">
              {time || "SYSTEM SYNCHRONIZING..."}
            </div>
            
            {/* User Indicator Avatar */}
            <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-xs text-indigo-400 shadow-md">
              SA
            </div>
          </div>
        </header>

        {/* Inside Page Container */}
        <main className="flex-1 overflow-y-auto p-8 relative">
          {children}
        </main>
      </div>
    </div>
  );
}
