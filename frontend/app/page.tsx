'use client';

import React from 'react';
import Link from 'next/link';
import { Shield, ShieldAlert, Cpu, Network, Zap, Lock, Globe, Terminal, ArrowRight, EyeOff, Activity, CheckCircle2 } from 'lucide-react';
import { motion } from 'framer-motion';

export default function LandingPage() {
  return (
    <div className="relative min-h-screen bg-[#070B14] overflow-hidden text-slate-100 font-sans">
      {/* Background Cyber Grid & Glow Orbs */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_10%,rgba(6,182,212,0.15),transparent_45%)] pointer-events-none" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_80%_80%,rgba(139,92,246,0.12),transparent_40%)] pointer-events-none" />
      <div className="absolute inset-0 opacity-20 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none" />

      {/* Top Navigation */}
      <header className="relative z-20 border-b border-slate-800/80 backdrop-blur-md bg-slate-950/60">
        <div className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/25">
              <Shield className="w-6 h-6 text-black font-bold" />
            </div>
            <div>
              <span className="text-xl font-black tracking-wider text-white font-mono">SENTINEL</span>
              <span className="ml-2 text-xs font-semibold px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800">
                IMMUNE v1.0
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <div className="hidden md:flex items-center space-x-2 text-xs text-slate-400 bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-800">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              <span>Zero Body Access • Differential Privacy Active</span>
            </div>
            <Link
              href="/dashboard"
              className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 hover:from-cyan-400 to-blue-600 hover:to-blue-500 text-slate-950 font-bold text-sm transition-all shadow-lg shadow-cyan-500/20 flex items-center space-x-2 group"
            >
              <span>Launch Command Center</span>
              <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="relative z-10 max-w-7xl mx-auto px-6 pt-16 pb-24">
        <div className="text-center max-w-4xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="inline-flex items-center space-x-2 px-4 py-2 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-400 text-xs font-mono mb-8"
          >
            <Zap className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>Autonomous Self-Healing Email Security Engine</span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="text-5xl md:text-7xl font-extrabold tracking-tight text-white leading-tight"
          >
            An AI Digital Twin that <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-blue-500">
              Hunts Attacker Infrastructure
            </span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="mt-6 text-lg md:text-xl text-slate-300 max-w-3xl mx-auto leading-relaxed"
          >
            Sentinel continuously learns your organization’s communication baseline through metadata-only behavioral profiling.
            When an attack strikes, our multi-agent swarm quarantines the threat, geo-traces the attacker through VPNs using Bayesian inference, and autonomously self-heals your defenses.
          </motion.p>

          {/* Action CTAs */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4"
          >
            <Link
              href="/dashboard"
              className="w-full sm:w-auto px-8 py-4 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-base transition-all shadow-xl shadow-cyan-500/25 flex items-center justify-center space-x-3 group"
            >
              <Terminal className="w-5 h-5" />
              <span>Open Security Dashboard</span>
              <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
            </Link>

            <a
              href="#architecture"
              className="w-full sm:w-auto px-8 py-4 rounded-xl bg-slate-900/90 hover:bg-slate-800 border border-slate-700 text-slate-200 font-semibold text-base transition-all flex items-center justify-center space-x-2"
            >
              <Activity className="w-5 h-5 text-slate-400" />
              <span>Explore 4-Layer Architecture</span>
            </a>
          </motion.div>

          {/* Key Stat Badges */}
          <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto">
            <div className="glass-panel p-5 rounded-2xl border border-slate-800 text-left">
              <div className="text-3xl font-black text-cyan-400 font-mono">98%</div>
              <div className="text-xs text-slate-400 mt-1">TwinGuard Behavioral Accuracy</div>
            </div>
            <div className="glass-panel p-5 rounded-2xl border border-slate-800 text-left">
              <div className="text-3xl font-black text-emerald-400 font-mono">0% Body</div>
              <div className="text-xs text-slate-400 mt-1">Zero Email Body Content Stored</div>
            </div>
            <div className="glass-panel p-5 rounded-2xl border border-slate-800 text-left">
              <div className="text-3xl font-black text-purple-400 font-mono">8+ Signals</div>
              <div className="text-xs text-slate-400 mt-1">Bayesian VPN-Resistant Geo Fusion</div>
            </div>
            <div className="glass-panel p-5 rounded-2xl border border-slate-800 text-left">
              <div className="text-3xl font-black text-amber-400 font-mono">&lt; 100ms</div>
              <div className="text-xs text-slate-400 mt-1">Autonomous Self-Healing Policy Patch</div>
            </div>
          </div>
        </div>

        {/* 4-Layer Architecture Section */}
        <section id="architecture" className="mt-32">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-extrabold text-white">
              Autonomous 4-Layer Cyber Defense Stack
            </h2>
            <p className="text-slate-400 mt-3 max-w-2xl mx-auto">
              Engineered on peer-reviewed security research: TwinGuard (2025), HunterTrace, and EvoMail adversarial co-evolution.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {/* Layer 1 */}
            <div className="glass-panel p-8 rounded-3xl border border-slate-800/80 hover:border-cyan-500/40 transition-all group">
              <div className="w-12 h-12 rounded-2xl bg-cyan-950 border border-cyan-800/60 flex items-center justify-center mb-6 text-cyan-400">
                <EyeOff className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-cyan-400 tracking-wider uppercase font-semibold">Layer 1</span>
              <h3 className="text-2xl font-bold text-white mt-1">Privacy-Preserving Digital Twin</h3>
              <p className="text-slate-400 mt-3 leading-relaxed">
                Builds dynamic temporal and relational baselines for every employee. Evaluates transmission hour distributions, SHA-256 hashed contact graphs, /24 subnet prefixes, and device user-agents without inspecting email bodies.
              </p>
              <div className="mt-6 flex flex-wrap gap-2">
                <span className="text-xs bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-slate-300">Hour & Day Deviations</span>
                <span className="text-xs bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-slate-300">SHA-256 Contact Graph</span>
                <span className="text-xs bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-slate-300">Subnet Anonymization</span>
              </div>
            </div>

            {/* Layer 2 */}
            <div className="glass-panel p-8 rounded-3xl border border-slate-800/80 hover:border-purple-500/40 transition-all group">
              <div className="w-12 h-12 rounded-2xl bg-purple-950 border border-purple-800/60 flex items-center justify-center mb-6 text-purple-400">
                <Cpu className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-purple-400 tracking-wider uppercase font-semibold">Layer 2</span>
              <h3 className="text-2xl font-bold text-white mt-1">Multi-Agent AI Swarm (CrewAI)</h3>
              <p className="text-slate-400 mt-3 leading-relaxed">
                4 specialized autonomous agents collaborate in an asynchronous pipeline: Forensic Detection Analyst, Risk Scoring Specialist, Plain-English Security Translator, and Red-Team Adversarial Challenger.
              </p>
              <div className="mt-6 flex flex-wrap gap-2">
                <span className="text-xs bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-slate-300">Detection Agent</span>
                <span className="text-xs bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-slate-300">Deterministic Risk Fusion</span>
                <span className="text-xs bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-slate-300">Adversarial Evasion Check</span>
              </div>
            </div>

            {/* Layer 3 */}
            <div className="glass-panel p-8 rounded-3xl border border-slate-800/80 hover:border-emerald-500/40 transition-all group">
              <div className="w-12 h-12 rounded-2xl bg-emerald-950 border border-emerald-800/60 flex items-center justify-center mb-6 text-emerald-400">
                <Globe className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-emerald-400 tracking-wider uppercase font-semibold">Layer 3</span>
              <h3 className="text-2xl font-bold text-white mt-1">Bayesian VPN-Resistant Hunter</h3>
              <p className="text-slate-400 mt-3 leading-relaxed">
                Attackers use commercial VPNs and cloud proxies to hide their locations. HunterTrace fuses 8+ invariant forensic signals (IP leaks, timestamp offsets, charset markers, hop chains) to isolate the true physical origin region.
              </p>
              <div className="mt-6 flex flex-wrap gap-2">
                <span className="text-xs bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-slate-300">8+ Signal Fusion</span>
                <span className="text-xs bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-slate-300">Confidence Tiering (A/B/C)</span>
                <span className="text-xs bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-slate-300">VPN Proxy De-Cloaking</span>
              </div>
            </div>

            {/* Layer 4 */}
            <div className="glass-panel p-8 rounded-3xl border border-slate-800/80 hover:border-amber-500/40 transition-all group">
              <div className="w-12 h-12 rounded-2xl bg-amber-950 border border-amber-800/60 flex items-center justify-center mb-6 text-amber-400">
                <Zap className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-amber-400 tracking-wider uppercase font-semibold">Layer 4</span>
              <h3 className="text-2xl font-bold text-white mt-1">Attack Graphs & Self-Healing</h3>
              <p className="text-slate-400 mt-3 leading-relaxed">
                NetworkX graph clustering links isolated emails into organized threat campaigns. Adversarial feedback triggers dynamic policy updates: auto-blocking domains, expanding off-hours defense matrices, and tuning anomaly sensitivity.
              </p>
              <div className="mt-6 flex flex-wrap gap-2">
                <span className="text-xs bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-slate-300">NetworkX Graph Centrality</span>
                <span className="text-xs bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-slate-300">Campaign Clustering</span>
                <span className="text-xs bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-slate-300">Autonomous Auto-Patching</span>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-8 text-center text-xs text-slate-500">
        <p>PROJECT SENTINEL • Advanced Threat Attribution & Self-Healing Defense System</p>
        <p className="mt-1">Strictly Metadata-Only Forensic Operations • GDPR & DPDP Compliant Architecture</p>
      </footer>
    </div>
  );
}
