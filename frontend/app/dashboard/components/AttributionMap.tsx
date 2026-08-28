'use client';

import React from 'react';
import { Globe, ShieldAlert, Wifi, CheckCircle2, MapPin, Radio, Layers } from 'lucide-react';
import { motion } from 'framer-motion';

interface AttributionProps {
  attribution: {
    primary_region?: string;
    confidence?: number;
    tier?: string;
    tier_code?: string;
    vpn_detected?: boolean;
    all_regions?: Record<string, number>;
    signals_used?: number;
    signals?: {
      webmail_ip_leak?: string;
      timezone_offset?: number;
      language_fingerprint?: string;
      infrastructure_reuse?: number;
      hop_chain_forgery?: number;
      vpn_exit_node?: boolean;
      webmail_provider?: string;
      tld?: string;
    };
  };
}

export default function AttributionMap({ attribution }: AttributionProps) {
  if (!attribution || !attribution.primary_region) {
    return (
      <div className="glass-panel p-6 rounded-3xl border border-slate-800 text-center text-slate-500 text-xs">
        <Globe className="w-8 h-8 mx-auto mb-2 text-slate-600 animate-pulse" />
        <span>Awaiting email analysis telemetry for Bayesian geo-attribution</span>
      </div>
    );
  }

  const {
    primary_region = 'Unknown',
    confidence = 0,
    tier = 'Tier C',
    tier_code = 'C',
    vpn_detected = false,
    all_regions = {},
    signals_used = 0,
    signals = {}
  } = attribution;

  const sortedRegions = Object.entries(all_regions).sort((a, b) => b[1] - a[1]);

  return (
    <div className="glass-panel p-6 rounded-3xl border border-slate-800 relative overflow-hidden">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
        <div className="flex items-center space-x-2">
          <Globe className="w-4 h-4 text-purple-400" />
          <span className="text-xs font-mono font-bold tracking-wider uppercase text-slate-200">
            HunterTrace Bayesian Geolocation
          </span>
        </div>

        {/* VPN Detection Flag (Separate from physical location) */}
        <div className="flex items-center space-x-2">
          {vpn_detected ? (
            <span className="flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30 animate-pulse">
              <Wifi className="w-3.5 h-3.5" />
              <span>VPN / PROXY DETECTED</span>
            </span>
          ) : (
            <span className="flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-semibold bg-slate-900 text-slate-400 border border-slate-800">
              <Wifi className="w-3.5 h-3.5 text-slate-500" />
              <span>Direct Routing</span>
            </span>
          )}
        </div>
      </div>

      {/* Primary Attribution Spotlight Card */}
      <div className="p-5 rounded-2xl bg-gradient-to-r from-purple-950/40 via-slate-900/60 to-slate-950/80 border border-purple-500/30 mb-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <div className="text-[11px] font-mono text-purple-400 uppercase tracking-wider font-semibold flex items-center space-x-1.5">
              <MapPin className="w-3.5 h-3.5" />
              <span>Attributed Attacker Physical Origin</span>
            </div>
            <div className="text-2xl sm:text-3xl font-black text-white font-mono mt-1">
              {primary_region}
            </div>
          </div>

          <div className="flex items-center space-x-3 text-right">
            <div className="text-right">
              <div className="text-2xl font-black font-mono text-purple-400">
                {confidence}%
              </div>
              <div className="text-[10px] font-mono text-slate-400 uppercase">
                {tier}
              </div>
            </div>
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center font-mono font-bold text-lg border ${
              tier_code === 'A'
                ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                : tier_code === 'B'
                ? 'bg-purple-500/20 text-purple-400 border-purple-500/40'
                : 'bg-amber-500/20 text-amber-400 border-amber-500/40'
            }`}>
              {tier_code}
            </div>
          </div>
        </div>
      </div>

      {/* Bayesian Posterior Probability Distribution */}
      <div className="mb-6">
        <div className="text-xs font-mono font-bold uppercase text-slate-400 mb-3 flex items-center justify-between">
          <span className="flex items-center space-x-1.5">
            <Radio className="w-3.5 h-3.5 text-purple-400" />
            <span>Regional Posterior Probability</span>
          </span>
          <span className="text-[11px] text-slate-500">{signals_used} Signals Evaluated</span>
        </div>

        <div className="space-y-2.5">
          {sortedRegions.map(([reg, prob], idx) => {
            const isPrimary = idx === 0;
            return (
              <div key={reg} className="space-y-1">
                <div className="flex justify-between text-xs font-mono">
                  <span className={isPrimary ? 'text-white font-bold' : 'text-slate-400'}>
                    {reg}
                  </span>
                  <span className={isPrimary ? 'text-purple-400 font-bold' : 'text-slate-500'}>
                    {prob.toFixed(1)}%
                  </span>
                </div>
                <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                  <motion.div
                    className={`h-full rounded-full ${isPrimary ? 'bg-gradient-to-r from-purple-500 to-cyan-400' : 'bg-slate-700'}`}
                    initial={{ width: 0 }}
                    animate={{ width: `${prob}%` }}
                    transition={{ duration: 0.8, delay: idx * 0.05 }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Active Invariant Forensic Signals Grid */}
      <div className="border-t border-slate-800 pt-4">
        <div className="text-xs font-mono font-bold uppercase text-slate-400 mb-3 flex items-center space-x-1.5">
          <Layers className="w-3.5 h-3.5 text-cyan-400" />
          <span>FUSED FORENSIC TELEMETRY SIGNALS</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono">
          <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800">
            <div className="text-slate-500">IP Leak:</div>
            <div className="text-slate-200 truncate">{signals.webmail_ip_leak || 'None'}</div>
          </div>
          <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800">
            <div className="text-slate-500">Timezone Offset:</div>
            <div className="text-cyan-300">
              {signals.timezone_offset !== undefined ? `UTC ${signals.timezone_offset >= 0 ? '+' : ''}${signals.timezone_offset}h` : 'N/A'}
            </div>
          </div>
          <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800">
            <div className="text-slate-500">Language / Charset:</div>
            <div className="text-slate-200 truncate">{signals.language_fingerprint || 'N/A'}</div>
          </div>
          <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800">
            <div className="text-slate-500">Sender TLD:</div>
            <div className="text-slate-200">{signals.tld || 'N/A'}</div>
          </div>
        </div>
      </div>
    </div>
  );
}
