'use client';

import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2, Lock, Flame } from 'lucide-react';
import { motion } from 'framer-motion';

interface RiskScoreProps {
  score: number;
  detectionScore: number;
  anomalyScore: number;
  severity: string;
  action: string;
  explanation: string;
}

export default function RiskScore({
  score = 0,
  detectionScore = 0,
  anomalyScore = 0,
  severity = 'LOW',
  action = 'ALLOW',
  explanation = 'Analysis pending.',
}: RiskScoreProps) {
  // Determine color scheme
  const getColor = () => {
    if (score >= 75) return { text: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/30', stroke: '#F43F5E', glow: 'shadow-rose-500/20' };
    if (score >= 50) return { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30', stroke: '#F59E0B', glow: 'shadow-amber-500/20' };
    if (score >= 25) return { text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', stroke: '#EAB308', glow: 'shadow-yellow-500/20' };
    return { text: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', stroke: '#10B981', glow: 'shadow-emerald-500/20' };
  };

  const scheme = getColor();
  const radius = 64;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className={`glass-panel p-6 rounded-3xl border ${scheme.border} relative overflow-hidden transition-all duration-500 shadow-xl ${scheme.glow}`}>
      {/* Background radial highlight */}
      <div
        className="absolute -top-16 -right-16 w-44 h-44 rounded-full blur-3xl opacity-20 pointer-events-none"
        style={{ backgroundColor: scheme.stroke }}
      />

      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <Flame className={`w-4 h-4 ${scheme.text}`} />
          <span className="text-xs font-mono font-bold tracking-wider uppercase text-slate-300">
            Composite Threat Posture
          </span>
        </div>
        <div className={`px-3 py-1 rounded-full text-xs font-mono font-bold uppercase tracking-wider ${scheme.bg} ${scheme.text} border ${scheme.border}`}>
          {action} • {severity}
        </div>
      </div>

      <div className="flex flex-col sm:flex-row items-center gap-6 mt-2">
        {/* Radial Animated Gauge */}
        <div className="relative w-36 h-36 flex items-center justify-center flex-shrink-0">
          <svg className="w-36 h-36 transform -rotate-90">
            <circle
              cx="72"
              cy="72"
              r={radius}
              stroke="#1E293B"
              strokeWidth="10"
              fill="transparent"
            />
            <motion.circle
              cx="72"
              cy="72"
              r={radius}
              stroke={scheme.stroke}
              strokeWidth="10"
              strokeDasharray={circumference}
              initial={{ strokeDashoffset: circumference }}
              animate={{ strokeDashoffset }}
              transition={{ duration: 1.2, ease: 'easeOut' }}
              strokeLinecap="round"
              fill="transparent"
            />
          </svg>

          <div className="absolute flex flex-col items-center justify-center text-center">
            <span className={`text-3xl font-black font-mono tracking-tight ${scheme.text}`}>
              {score.toFixed(0)}
            </span>
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
              / 100 Risk
            </span>
          </div>
        </div>

        {/* Score Decomposition */}
        <div className="flex-1 w-full space-y-3">
          <div>
            <div className="flex justify-between text-xs font-mono mb-1">
              <span className="text-slate-400">Forensic Agent Detection (60%)</span>
              <span className="text-cyan-400 font-bold">{detectionScore.toFixed(0)}/100</span>
            </div>
            <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-cyan-400 rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${detectionScore}%` }}
                transition={{ duration: 1, ease: 'easeOut' }}
              />
            </div>
          </div>

          <div>
            <div className="flex justify-between text-xs font-mono mb-1">
              <span className="text-slate-400">Digital Twin Deviation (40%)</span>
              <span className="text-purple-400 font-bold">{(anomalyScore * 100).toFixed(0)}%</span>
            </div>
            <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-purple-400 rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${Math.min(anomalyScore * 100, 100)}%` }}
                transition={{ duration: 1, ease: 'easeOut' }}
              />
            </div>
          </div>

          <div className="text-[11px] font-mono text-slate-400 pt-1">
            Formula: <span className="text-slate-200">0.60 × Detection + 0.40 × Twin Anomaly</span>
          </div>
        </div>
      </div>

      {/* Plain English User Explanation */}
      <div className="mt-5 p-4 rounded-2xl bg-slate-950/70 border border-slate-800/80">
        <div className="text-[11px] font-mono font-bold uppercase text-cyan-400 mb-1 flex items-center space-x-1.5">
          <CheckCircle2 className="w-3.5 h-3.5" />
          <span>Security Translator Explanation</span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          {explanation}
        </p>
      </div>
    </div>
  );
}
