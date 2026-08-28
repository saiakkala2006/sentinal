'use client';

import React from 'react';
import { Route, Clock, Server, CheckCircle, AlertOctagon, ArrowDown } from 'lucide-react';

interface Hop {
  from?: string;
  by?: string;
  ip?: string;
  timestamp?: string;
  datetime?: string;
  with?: string;
  id?: string;
}

interface TimelineProps {
  hops: Hop[];
  dateHeader?: string;
}

export default function Timeline({ hops = [], dateHeader }: TimelineProps) {
  if (!hops || hops.length === 0) {
    return (
      <div className="glass-panel p-6 rounded-3xl border border-slate-800 text-center text-slate-500 text-xs">
        <Route className="w-8 h-8 mx-auto mb-2 text-slate-600 animate-pulse" />
        <span>No intermediate Received headers detected in metadata</span>
      </div>
    );
  }

  return (
    <div className="glass-panel p-6 rounded-3xl border border-slate-800">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center space-x-2">
          <Route className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-mono font-bold tracking-wider uppercase text-slate-200">
            Hop-by-Hop Relay Chain ({hops.length} Hops)
          </span>
        </div>
        {dateHeader && (
          <div className="flex items-center space-x-1 text-[11px] font-mono text-slate-400 bg-slate-950/60 px-2.5 py-1 rounded-lg border border-slate-800">
            <Clock className="w-3 h-3 text-cyan-400" />
            <span>{dateHeader}</span>
          </div>
        )}
      </div>

      <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-cyan-500 before:via-blue-500 before:to-emerald-500">
        {hops.map((hop, idx) => {
          const isOrigin = idx === hops.length - 1;
          const isDestination = idx === 0;

          return (
            <div key={idx} className="relative group">
              {/* Timeline Marker Dot */}
              <div
                className={`absolute -left-[27px] top-1.5 w-3.5 h-3.5 rounded-full border-2 border-[#070B14] shadow-md transition-all group-hover:scale-125 ${
                  isOrigin
                    ? 'bg-rose-400'
                    : isDestination
                    ? 'bg-emerald-400'
                    : 'bg-cyan-400'
                }`}
              />

              <div className="p-3.5 rounded-2xl bg-slate-950/70 border border-slate-800/80 hover:border-cyan-500/30 transition-all text-xs font-mono">
                <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                  <span className="font-bold text-slate-200 flex items-center space-x-1.5">
                    <Server className="w-3.5 h-3.5 text-cyan-400" />
                    <span>
                      {isOrigin ? 'Origin Egress Node' : isDestination ? 'Final MX Destination' : `Relay Hop #${hops.length - idx}`}
                    </span>
                  </span>
                  {hop.ip && (
                    <span className="px-2 py-0.5 rounded-md bg-slate-900 text-cyan-300 border border-slate-800 font-semibold text-[11px]">
                      IP: {hop.ip}
                    </span>
                  )}
                </div>

                <div className="space-y-1 text-slate-400 text-[11px]">
                  {hop.from && (
                    <div className="truncate">
                      <span className="text-slate-600">From: </span>
                      <span className="text-slate-300">{hop.from}</span>
                    </div>
                  )}
                  {hop.by && (
                    <div className="truncate">
                      <span className="text-slate-600">By: </span>
                      <span className="text-slate-300">{hop.by}</span>
                    </div>
                  )}
                  {hop.timestamp && (
                    <div className="text-[10px] text-slate-500 flex items-center space-x-1 pt-1">
                      <Clock className="w-3 h-3 text-slate-600" />
                      <span>{hop.timestamp}</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
