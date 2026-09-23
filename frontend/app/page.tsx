'use client';

import React from 'react';
import Link from 'next/link';
import { Shield, Cpu, Zap, Globe, Terminal, ArrowRight, EyeOff, Activity } from 'lucide-react';
import { motion } from 'framer-motion';

export default function LandingPage() {
  return (
    <div className="relative min-h-screen bg-[#F5F2EC] overflow-hidden text-[#2C2A26] font-sans">
      {/* Background soft organic glow orbs */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_10%,rgba(126,188,138,0.18),transparent_50%)] pointer-events-none" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_75%_85%,rgba(91,141,184,0.12),transparent_45%)] pointer-events-none" />
      <div className="absolute inset-0 bg-leaf-pattern opacity-60 pointer-events-none" />

      {/* Top Navigation */}
      <header className="relative z-20 border-b border-[#DDD8CE] backdrop-blur-md bg-[#FDFCF8]/80">
        <div className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-[#4A7C59] to-[#7EBC8A] flex items-center justify-center shadow-md shadow-[#4A7C59]/20">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <span className="text-xl font-black tracking-wider text-[#2C2A26] font-mono">SENTINEL</span>
              <span className="ml-2 text-xs font-semibold px-2 py-0.5 rounded-full bg-[#4A7C59]/10 text-[#4A7C59] border border-[#4A7C59]/25">
                IMMUNE v1.0
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <div className="hidden md:flex items-center space-x-2 text-xs text-[#7A7368] bg-[#F0EBE1] px-3 py-1.5 rounded-lg border border-[#DDD8CE]">
              <span className="w-2 h-2 rounded-full bg-[#4A7C59] animate-ping" />
              <span>Zero Body Access • Differential Privacy Active</span>
            </div>
            <Link
              href="/dashboard"
              className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-[#4A7C59] to-[#5E9470] hover:from-[#3D6B4A] hover:to-[#4A7C59] text-white font-bold text-sm transition-all shadow-md shadow-[#4A7C59]/20 flex items-center space-x-2 group"
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
            className="inline-flex items-center space-x-2 px-4 py-2 rounded-full bg-[#4A7C59]/10 border border-[#4A7C59]/30 text-[#4A7C59] text-xs font-mono mb-8"
          >
            <Zap className="w-3.5 h-3.5 text-[#4A7C59] animate-pulse" />
            <span>Autonomous Self-Healing Email Security Engine</span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="text-5xl md:text-7xl font-extrabold tracking-tight text-[#2C2A26] leading-tight"
          >
            An AI Digital Twin that <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#4A7C59] via-[#5E9470] to-[#5B8DB8]">
              Hunts Attacker Infrastructure
            </span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="mt-6 text-lg md:text-xl text-[#6B6560] max-w-3xl mx-auto leading-relaxed"
          >
            Sentinel continuously learns your organization&apos;s communication baseline through metadata-only behavioral profiling.
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
              className="w-full sm:w-auto px-8 py-4 rounded-xl bg-[#4A7C59] hover:bg-[#3D6B4A] text-white font-bold text-base transition-all shadow-lg shadow-[#4A7C59]/20 flex items-center justify-center space-x-3 group"
            >
              <Terminal className="w-5 h-5" />
              <span>Open Security Dashboard</span>
              <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
            </Link>

            <a
              href="#architecture"
              className="w-full sm:w-auto px-8 py-4 rounded-xl bg-[#FDFCF8] hover:bg-[#F0EBE1] border border-[#DDD8CE] text-[#2C2A26] font-semibold text-base transition-all flex items-center justify-center space-x-2 shadow-sm"
            >
              <Activity className="w-5 h-5 text-[#7A7368]" />
              <span>Explore 4-Layer Architecture</span>
            </a>
          </motion.div>

          {/* Key Stat Badges */}
          <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto">
            <div className="glass-panel p-5 rounded-2xl text-left hover:shadow-md transition-all">
              <div className="text-3xl font-black text-[#4A7C59] font-mono">98%</div>
              <div className="text-xs text-[#7A7368] mt-1">TwinGuard Behavioral Accuracy</div>
            </div>
            <div className="glass-panel p-5 rounded-2xl text-left hover:shadow-md transition-all">
              <div className="text-3xl font-black text-[#5B8DB8] font-mono">0% Body</div>
              <div className="text-xs text-[#7A7368] mt-1">Zero Email Body Content Stored</div>
            </div>
            <div className="glass-panel p-5 rounded-2xl text-left hover:shadow-md transition-all">
              <div className="text-3xl font-black text-[#7EBC8A] font-mono">8+ Signals</div>
              <div className="text-xs text-[#7A7368] mt-1">Bayesian VPN-Resistant Geo Fusion</div>
            </div>
            <div className="glass-panel p-5 rounded-2xl text-left hover:shadow-md transition-all">
              <div className="text-3xl font-black text-[#C49A3C] font-mono">&lt; 100ms</div>
              <div className="text-xs text-[#7A7368] mt-1">Autonomous Self-Healing Policy Patch</div>
            </div>
          </div>
        </div>

        {/* 4-Layer Architecture Section */}
        <section id="architecture" className="mt-32">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-extrabold text-[#2C2A26]">
              Autonomous 4-Layer Cyber Defense Stack
            </h2>
            <p className="text-[#7A7368] mt-3 max-w-2xl mx-auto">
              Engineered on peer-reviewed security research: TwinGuard (2025), HunterTrace, and EvoMail adversarial co-evolution.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {/* Layer 1 */}
            <div className="glass-panel p-8 rounded-3xl hover:border-[#4A7C59]/40 transition-all group">
              <div className="w-12 h-12 rounded-2xl bg-[#4A7C59]/10 border border-[#4A7C59]/25 flex items-center justify-center mb-6 text-[#4A7C59]">
                <EyeOff className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-[#4A7C59] tracking-wider uppercase font-semibold">Layer 1</span>
              <h3 className="text-2xl font-bold text-[#2C2A26] mt-1">Privacy-Preserving Digital Twin</h3>
              <p className="text-[#6B6560] mt-3 leading-relaxed">
                Builds dynamic temporal and relational baselines for every employee. Evaluates transmission hour distributions, SHA-256 hashed contact graphs, /24 subnet prefixes, and device user-agents without inspecting email bodies.
              </p>
              <div className="mt-6 flex flex-wrap gap-2">
                <span className="text-xs bg-[#F0EBE1] border border-[#DDD8CE] px-3 py-1 rounded-full text-[#6B6560]">Hour &amp; Day Deviations</span>
                <span className="text-xs bg-[#F0EBE1] border border-[#DDD8CE] px-3 py-1 rounded-full text-[#6B6560]">SHA-256 Contact Graph</span>
                <span className="text-xs bg-[#F0EBE1] border border-[#DDD8CE] px-3 py-1 rounded-full text-[#6B6560]">Subnet Anonymization</span>
              </div>
            </div>

            {/* Layer 2 */}
            <div className="glass-panel p-8 rounded-3xl hover:border-[#5B8DB8]/30 transition-all group">
              <div className="w-12 h-12 rounded-2xl bg-[#5B8DB8]/10 border border-[#5B8DB8]/25 flex items-center justify-center mb-6 text-[#5B8DB8]">
                <Cpu className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-[#5B8DB8] tracking-wider uppercase font-semibold">Layer 2</span>
              <h3 className="text-2xl font-bold text-[#2C2A26] mt-1">Multi-Agent AI Swarm (CrewAI)</h3>
              <p className="text-[#6B6560] mt-3 leading-relaxed">
                4 specialized autonomous agents collaborate in an asynchronous pipeline: Forensic Detection Analyst, Risk Scoring Specialist, Plain-English Security Translator, and Red-Team Adversarial Challenger.
              </p>
              <div className="mt-6 flex flex-wrap gap-2">
                <span className="text-xs bg-[#F0EBE1] border border-[#DDD8CE] px-3 py-1 rounded-full text-[#6B6560]">Detection Agent</span>
                <span className="text-xs bg-[#F0EBE1] border border-[#DDD8CE] px-3 py-1 rounded-full text-[#6B6560]">Deterministic Risk Fusion</span>
                <span className="text-xs bg-[#F0EBE1] border border-[#DDD8CE] px-3 py-1 rounded-full text-[#6B6560]">Adversarial Evasion Check</span>
              </div>
            </div>

            {/* Layer 3 */}
            <div className="glass-panel p-8 rounded-3xl hover:border-[#7EBC8A]/30 transition-all group">
              <div className="w-12 h-12 rounded-2xl bg-[#7EBC8A]/15 border border-[#7EBC8A]/30 flex items-center justify-center mb-6 text-[#4A7C59]">
                <Globe className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-[#4A7C59] tracking-wider uppercase font-semibold">Layer 3</span>
              <h3 className="text-2xl font-bold text-[#2C2A26] mt-1">Bayesian VPN-Resistant Hunter</h3>
              <p className="text-[#6B6560] mt-3 leading-relaxed">
                Attackers use commercial VPNs and cloud proxies to hide their locations. HunterTrace fuses 8+ invariant forensic signals (IP leaks, timestamp offsets, charset markers, hop chains) to isolate the true physical origin region.
              </p>
              <div className="mt-6 flex flex-wrap gap-2">
                <span className="text-xs bg-[#F0EBE1] border border-[#DDD8CE] px-3 py-1 rounded-full text-[#6B6560]">8+ Signal Fusion</span>
                <span className="text-xs bg-[#F0EBE1] border border-[#DDD8CE] px-3 py-1 rounded-full text-[#6B6560]">Confidence Tiering (A/B/C)</span>
                <span className="text-xs bg-[#F0EBE1] border border-[#DDD8CE] px-3 py-1 rounded-full text-[#6B6560]">VPN Proxy De-Cloaking</span>
              </div>
            </div>

            {/* Layer 4 */}
            <div className="glass-panel p-8 rounded-3xl hover:border-[#C49A3C]/30 transition-all group">
              <div className="w-12 h-12 rounded-2xl bg-[#C49A3C]/10 border border-[#C49A3C]/25 flex items-center justify-center mb-6 text-[#C49A3C]">
                <Zap className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-[#C49A3C] tracking-wider uppercase font-semibold">Layer 4</span>
              <h3 className="text-2xl font-bold text-[#2C2A26] mt-1">Attack Graphs &amp; Self-Healing</h3>
              <p className="text-[#6B6560] mt-3 leading-relaxed">
                NetworkX graph clustering links isolated emails into organized threat campaigns. Adversarial feedback triggers dynamic policy updates: auto-blocking domains, expanding off-hours defense matrices, and tuning anomaly sensitivity.
              </p>
              <div className="mt-6 flex flex-wrap gap-2">
                <span className="text-xs bg-[#F0EBE1] border border-[#DDD8CE] px-3 py-1 rounded-full text-[#6B6560]">NetworkX Graph Centrality</span>
                <span className="text-xs bg-[#F0EBE1] border border-[#DDD8CE] px-3 py-1 rounded-full text-[#6B6560]">Campaign Clustering</span>
                <span className="text-xs bg-[#F0EBE1] border border-[#DDD8CE] px-3 py-1 rounded-full text-[#6B6560]">Autonomous Auto-Patching</span>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#DDD8CE] py-8 text-center text-xs text-[#9A9188]">
        <p>PROJECT SENTINEL • Advanced Threat Attribution &amp; Self-Healing Defense System</p>
        <p className="mt-1">Strictly Metadata-Only Forensic Operations • GDPR &amp; DPDP Compliant Architecture</p>
      </footer>
    </div>
  );
}
