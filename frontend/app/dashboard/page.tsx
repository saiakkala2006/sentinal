'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { useDropzone } from 'react-dropzone';
import axios from 'axios';
import toast from 'react-hot-toast';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  UploadCloud,
  FileText,
  Activity,
  Zap,
  Globe,
  Radio,
  Cpu,
  RefreshCw,
  EyeOff,
  Terminal,
  Lock,
  Layers,
  ArrowRight,
  Flame,
  AlertTriangle,
  FolderLock
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

import AttackGraph from './components/AttackGraph';
import RiskScore from './components/RiskScore';
import Timeline from './components/Timeline';
import AttributionMap from './components/AttributionMap';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const WS_URL = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws';

export default function DashboardPage() {
  const [analyzing, setAnalyzing] = useState(false);
  const [currentResult, setCurrentResult] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({
    total_emails_analyzed: 0,
    quarantined_count: 0,
    alert_count: 0,
    allowed_count: 0,
    active_campaigns_count: 0,
    self_healing_events_count: 0,
    blocked_domains_count: 0,
  });
  const [graphData, setGraphData] = useState<any>({ nodes: [], edges: [] });
  const [twinSummary, setTwinSummary] = useState<any>(null);
  const [policiesData, setPoliciesData] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'graph' | 'twin' | 'policies'>('overview');

  // Load telemetry stats, graph, and policies
  const loadDashboardData = useCallback(async () => {
    try {
      const [statsRes, graphRes, twinRes, policiesRes] = await Promise.all([
        axios.get(`${API_BASE}/dashboard/stats`).catch(() => ({ data: {} })),
        axios.get(`${API_BASE}/dashboard/graph`).catch(() => ({ data: { nodes: [], edges: [] } })),
        axios.get(`${API_BASE}/digital-twin/secops_admin`).catch(() => ({ data: null })),
        axios.get(`${API_BASE}/policies`).catch(() => ({ data: null })),
      ]);

      if (statsRes.data) {
        setStats(statsRes.data);
        if (statsRes.data.recent_results && statsRes.data.recent_results.length > 0) {
          setHistory(statsRes.data.recent_results);
          if (!currentResult) {
            setCurrentResult(statsRes.data.recent_results[0]);
          }
        }
      }
      if (graphRes.data) setGraphData(graphRes.data);
      if (twinRes.data) setTwinSummary(twinRes.data);
      if (policiesRes.data) setPoliciesData(policiesRes.data);
    } catch (err) {
      console.error('Error fetching dashboard state', err);
    }
  }, [currentResult]);

  useEffect(() => {
    loadDashboardData();

    // WebSocket connection for real-time streaming
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(WS_URL);
      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.event === 'NEW_ANALYSIS') {
            toast.success(`Real-Time: Analyzed ${payload.data.filename || 'Email'}`);
            setCurrentResult(payload.data);
            loadDashboardData();
          }
        } catch (e) {}
      };
    } catch (e) {}

    return () => {
      if (ws) ws.close();
    };
  }, [loadDashboardData]);

  // Handle File Upload
  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    if (acceptedFiles.length === 0) return;

    setAnalyzing(true);
    const toastId = toast.loading('Executing Sentinel multi-agent defense pipeline...');

    try {
      if (acceptedFiles.length === 1) {
        const file = acceptedFiles[0];
        const formData = new FormData();
        formData.append('file', file);
        formData.append('user_id', 'secops_admin');
        formData.append('update_twin', 'true');

        const response = await axios.post(`${API_BASE}/analyze`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        });

        setCurrentResult(response.data);
        setHistory(prev => [response.data, ...prev]);
        toast.success(`Analysis Complete: ${response.data.recommended_action}`, { id: toastId });
      } else {
        const formData = new FormData();
        acceptedFiles.forEach(file => {
          formData.append('files', file);
        });
        formData.append('user_id', 'secops_admin');

        const response = await axios.post(`${API_BASE}/analyze/batch`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        });

        if (response.data.results && response.data.results.length > 0) {
          setCurrentResult(response.data.results[0]);
          setHistory(prev => [...response.data.results, ...prev]);
        }
        toast.success(`Batch Processed: ${response.data.total_analyzed} emails`, { id: toastId });
      }

      await loadDashboardData();
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Failed to analyze email', { id: toastId });
    } finally {
      setAnalyzing(false);
    }
  }, [loadDashboardData]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'message/rfc822': ['.eml'] },
    maxFiles: 10,
  });

  // Seed baseline helper
  const handleSeedBaseline = async () => {
    const toastId = toast.loading('Training Digital Twin behavioral baseline...');
    try {
      const res = await axios.post(`${API_BASE}/digital-twin/train-seed`);
      setTwinSummary(res.data.summary);
      toast.success('Digital Twin Baseline Profile Seeded (6 normal communications)', { id: toastId });
      await loadDashboardData();
    } catch (err) {
      toast.error('Failed to seed baseline', { id: toastId });
    }
  };

  // Quick Load Sample EML Files
  const handleLoadSample = async (sampleName: string) => {
    setAnalyzing(true);
    const toastId = toast.loading(`Loading test artifact: ${sampleName}...`);
    try {
      // Create synthetic sample file content
      let emlContent = '';
      if (sampleName === 'phishing.eml') {
        emlContent = `From: "Security Team IT" <support@sec-update-portal.xyz>
To: target.user@acme-corp.com
Subject: URGENT: Mandatory Password Reset Required Within 24 Hours
Date: Sun, 24 Aug 2026 02:45:12 +0300
Message-ID: <20260824024512.98124.qmail@sec-update-portal.xyz>
Return-Path: <bounce-daemon@botnet-node4.net>
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
X-Originating-IP: [185.220.101.5]
Content-Type: text/plain; charset=windows-1251
Received: from relay01.sec-update-portal.xyz ([104.244.76.13]); Sun, 24 Aug 2026 02:45:13 +0300
Received: from node9.vpn-egress.ru ([185.220.101.5]); Sun, 24 Aug 2026 02:45:12 +0300

[Body isolated]`;
      } else if (sampleName === 'benign.eml') {
        emlContent = `From: "Alice Johnson" <alice.johnson@acme-corp.com>
To: target.user@acme-corp.com
Subject: Q3 Planning & Budget Review Sync
Date: Mon, 25 Aug 2026 10:15:30 -0400
Message-ID: <CABhZwV=xN9bZ82n1_a0p4d3@mail.gmail.com>
Return-Path: <alice.johnson@acme-corp.com>
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset=utf-8
Content-Language: en-US
Received: from mail-sor-f41.google.com ([209.85.220.41]); Mon, 25 Aug 2026 10:15:32 -0400

Hi team, agenda attached.`;
      } else {
        emlContent = `From: "CEO Tim Steiner" <tim.steiner@acme-corp.com>
To: target.user@acme-corp.com
Subject: Quick confidential request - wire transfer approval
Date: Sun, 24 Aug 2026 23:45:00 +0000
Message-ID: <NJK9812984128.89123@sec-update-portal.xyz>
Return-Path: <exec-drop@wire-processing-fast.org>
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
X-Originating-IP: [104.244.76.13]
Content-Type: text/plain; charset=utf-8
Received: from internal-relay.sec-update-portal.xyz ([104.244.76.13]); Sun, 24 Aug 2026 23:45:02 +0000

Are you at your desk? Urgent wire request.`;
      }

      const blob = new Blob([emlContent], { type: 'message/rfc822' });
      const file = new File([blob], sampleName, { type: 'message/rfc822' });

      const formData = new FormData();
      formData.append('file', file);
      formData.append('user_id', 'secops_admin');
      formData.append('update_twin', 'false');

      const response = await axios.post(`${API_BASE}/analyze`, formData);
      setCurrentResult(response.data);
      setHistory(prev => [response.data, ...prev]);
      toast.success(`Sample Ingested: ${response.data.recommended_action}`, { id: toastId });
      await loadDashboardData();
    } catch (err: any) {
      toast.error('Failed to analyze sample', { id: toastId });
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070B14] text-slate-100 font-sans pb-16">
      {/* Top App Header */}
      <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-6 h-18 py-3 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Link href="/" className="flex items-center space-x-3 group">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 group-hover:scale-105 transition-transform">
                <Shield className="w-5 h-5 text-black font-bold" />
              </div>
              <div>
                <span className="text-lg font-black tracking-wider text-white font-mono">SENTINEL</span>
                <span className="ml-2 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">
                  COMMAND CENTER
                </span>
              </div>
            </Link>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={handleSeedBaseline}
              className="hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 text-xs font-mono transition-all"
            >
              <Cpu className="w-3.5 h-3.5 text-purple-400" />
              <span>Seed Behavioral Baseline</span>
            </button>

            <button
              onClick={loadDashboardData}
              className="p-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs transition-all"
              title="Refresh Telemetry"
            >
              <RefreshCw className="w-4 h-4 text-cyan-400" />
            </button>
          </div>
        </div>

        {/* Sub-Navigation Tabs */}
        <div className="max-w-7xl mx-auto px-6 flex space-x-6 text-xs font-mono border-t border-slate-900 pt-2 pb-1">
          <button
            onClick={() => setActiveTab('overview')}
            className={`pb-2 border-b-2 transition-all ${
              activeTab === 'overview'
                ? 'border-cyan-400 text-cyan-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Live Defense Console
          </button>
          <button
            onClick={() => setActiveTab('graph')}
            className={`pb-2 border-b-2 transition-all ${
              activeTab === 'graph'
                ? 'border-cyan-400 text-cyan-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Attack Graph & Campaigns ({stats.active_campaigns_count || 0})
          </button>
          <button
            onClick={() => setActiveTab('twin')}
            className={`pb-2 border-b-2 transition-all ${
              activeTab === 'twin'
                ? 'border-cyan-400 text-cyan-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Digital Twin Profiling
          </button>
          <button
            onClick={() => setActiveTab('policies')}
            className={`pb-2 border-b-2 transition-all ${
              activeTab === 'policies'
                ? 'border-cyan-400 text-cyan-400 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Self-Healing Policies ({stats.self_healing_events_count || 0})
          </button>
        </div>
      </header>

      {/* Main Dashboard Body */}
      <main className="max-w-7xl mx-auto px-6 pt-6">
        {/* Top Telemetry Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="glass-panel p-4 rounded-2xl border border-slate-800">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400">Total Analyzed</span>
              <FileText className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-black font-mono text-white mt-2">
              {stats.total_emails_analyzed || history.length}
            </div>
            <div className="text-[10px] font-mono text-slate-500 mt-1">Metadata-only ingestion</div>
          </div>

          <div className="glass-panel p-4 rounded-2xl border border-rose-500/20 bg-rose-500/5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-rose-300">Quarantined Attacks</span>
              <FolderLock className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-2xl font-black font-mono text-rose-400 mt-2">
              {stats.quarantined_count || 0}
            </div>
            <div className="text-[10px] font-mono text-rose-500/70 mt-1">Autonomous isolation</div>
          </div>

          <div className="glass-panel p-4 rounded-2xl border border-purple-500/20 bg-purple-500/5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-purple-300">Campaign Clusters</span>
              <Layers className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-black font-mono text-purple-400 mt-2">
              {stats.active_campaigns_count || 0}
            </div>
            <div className="text-[10px] font-mono text-purple-500/70 mt-1">NetworkX connected components</div>
          </div>

          <div className="glass-panel p-4 rounded-2xl border border-amber-500/20 bg-amber-500/5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-amber-300">Self-Healing Updates</span>
              <Zap className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-black font-mono text-amber-400 mt-2">
              {stats.self_healing_events_count || 0}
            </div>
            <div className="text-[10px] font-mono text-amber-500/70 mt-1">Dynamic rule auto-patches</div>
          </div>
        </div>

        {/* Tab 1: Live Defense Console */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Upload Zone & Quick Sample Loaders */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Dropzone Card */}
              <div
                {...getRootProps()}
                className={`lg:col-span-2 glass-panel p-8 rounded-3xl border-2 border-dashed transition-all cursor-pointer flex flex-col items-center justify-center text-center ${
                  isDragActive
                    ? 'border-cyan-400 bg-cyan-950/30'
                    : 'border-slate-800 hover:border-cyan-500/40'
                }`}
              >
                <input {...getInputProps()} />
                <div className="w-14 h-14 rounded-2xl bg-cyan-950/60 border border-cyan-800/80 flex items-center justify-center text-cyan-400 mb-4 shadow-lg shadow-cyan-500/10">
                  <UploadCloud className="w-7 h-7" />
                </div>
                <div className="text-base font-bold text-white">
                  Drop .eml files here to analyze forensic metadata
                </div>
                <p className="text-xs text-slate-400 mt-1.5 max-w-md">
                  Strictly zero body parsing. Evaluates authentication headers, hop chains, behavioral Digital Twin deviations, and Bayesian attribution.
                </p>
                <div className="mt-4 px-4 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-[11px] font-mono text-cyan-400">
                  Supports single or batch .eml uploads
                </div>
              </div>

              {/* Quick Sample Attack Selector */}
              <div className="glass-panel p-6 rounded-3xl border border-slate-800 flex flex-col justify-between">
                <div>
                  <div className="text-xs font-mono font-bold uppercase text-slate-300 flex items-center space-x-2 mb-3">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    <span>Preset Forensic Scenarios</span>
                  </div>
                  <p className="text-xs text-slate-400 mb-4">
                    Instant test cases to demonstrate multi-agent detection, attribution, and self-healing:
                  </p>
                </div>

                <div className="space-y-2">
                  <button
                    onClick={() => handleLoadSample('phishing.eml')}
                    disabled={analyzing}
                    className="w-full text-left p-3 rounded-2xl bg-rose-950/30 hover:bg-rose-900/40 border border-rose-800/40 text-xs font-mono transition-all flex items-center justify-between text-rose-300 group"
                  >
                    <div>
                      <div className="font-bold flex items-center space-x-1.5">
                        <Flame className="w-3.5 h-3.5 text-rose-400" />
                        <span>Credential Phishing (.eml)</span>
                      </div>
                      <div className="text-[10px] text-rose-400/70 mt-0.5">SPF fail • VPN egress • Windows-1251</div>
                    </div>
                    <ArrowRight className="w-4 h-4 opacity-60 group-hover:opacity-100 group-hover:translate-x-0.5 transition-all" />
                  </button>

                  <button
                    onClick={() => handleLoadSample('bec_spoof.eml')}
                    disabled={analyzing}
                    className="w-full text-left p-3 rounded-2xl bg-amber-950/30 hover:bg-amber-900/40 border border-amber-800/40 text-xs font-mono transition-all flex items-center justify-between text-amber-300 group"
                  >
                    <div>
                      <div className="font-bold flex items-center space-x-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                        <span>Executive Spoof / BEC (.eml)</span>
                      </div>
                      <div className="text-[10px] text-amber-400/70 mt-0.5">Mismatched Return-Path • Proxy node</div>
                    </div>
                    <ArrowRight className="w-4 h-4 opacity-60 group-hover:opacity-100 group-hover:translate-x-0.5 transition-all" />
                  </button>

                  <button
                    onClick={() => handleLoadSample('benign.eml')}
                    disabled={analyzing}
                    className="w-full text-left p-3 rounded-2xl bg-emerald-950/30 hover:bg-emerald-900/40 border border-emerald-800/40 text-xs font-mono transition-all flex items-center justify-between text-emerald-300 group"
                  >
                    <div>
                      <div className="font-bold flex items-center space-x-1.5">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Legitimate Corporate (.eml)</span>
                      </div>
                      <div className="text-[10px] text-emerald-400/70 mt-0.5">Full SPF/DKIM/DMARC pass</div>
                    </div>
                    <ArrowRight className="w-4 h-4 opacity-60 group-hover:opacity-100 group-hover:translate-x-0.5 transition-all" />
                  </button>
                </div>
              </div>
            </div>

            {/* Active Analysis Results Grid */}
            {currentResult && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Left Column: Risk Gauge & Attribution */}
                <div className="space-y-6">
                  <RiskScore
                    score={currentResult.risk_score || 0}
                    detectionScore={currentResult.detection_score || 0}
                    anomalyScore={currentResult.anomaly_score || 0}
                    severity={currentResult.severity || 'LOW'}
                    action={currentResult.recommended_action || 'ALLOW'}
                    explanation={currentResult.explanation || ''}
                  />

                  <AttributionMap attribution={currentResult.attribution || {}} />
                </div>

                {/* Right Column: Hop-by-Hop Timeline & Forensic Telemetry */}
                <div className="space-y-6">
                  <Timeline
                    hops={currentResult.metadata?.received_chain || []}
                    dateHeader={currentResult.metadata?.date}
                  />

                  {/* Header Authentication Badges */}
                  <div className="glass-panel p-6 rounded-3xl border border-slate-800">
                    <div className="text-xs font-mono font-bold uppercase text-slate-300 mb-4 flex items-center space-x-2">
                      <Lock className="w-4 h-4 text-cyan-400" />
                      <span>Cryptographic Auth & Protocol Telemetry</span>
                    </div>

                    <div className="grid grid-cols-3 gap-3 font-mono text-xs text-center">
                      <div className="p-3 rounded-2xl bg-slate-950/70 border border-slate-800">
                        <div className="text-slate-500 text-[10px]">SPF Status</div>
                        <div
                          className={`font-bold mt-1 uppercase ${
                            currentResult.metadata?.spf?.status === 'pass'
                              ? 'text-emerald-400'
                              : currentResult.metadata?.spf?.status === 'fail'
                              ? 'text-rose-400'
                              : 'text-amber-400'
                          }`}
                        >
                          {currentResult.metadata?.spf?.status || 'none'}
                        </div>
                      </div>

                      <div className="p-3 rounded-2xl bg-slate-950/70 border border-slate-800">
                        <div className="text-slate-500 text-[10px]">DKIM Signature</div>
                        <div
                          className={`font-bold mt-1 uppercase ${
                            currentResult.metadata?.dkim?.status === 'pass'
                              ? 'text-emerald-400'
                              : currentResult.metadata?.dkim?.status === 'fail'
                              ? 'text-rose-400'
                              : 'text-amber-400'
                          }`}
                        >
                          {currentResult.metadata?.dkim?.status || 'none'}
                        </div>
                      </div>

                      <div className="p-3 rounded-2xl bg-slate-950/70 border border-slate-800">
                        <div className="text-slate-500 text-[10px]">DMARC Policy</div>
                        <div
                          className={`font-bold mt-1 uppercase ${
                            currentResult.metadata?.dmarc?.status === 'pass'
                              ? 'text-emerald-400'
                              : currentResult.metadata?.dmarc?.status === 'fail'
                              ? 'text-rose-400'
                              : 'text-amber-400'
                          }`}
                        >
                          {currentResult.metadata?.dmarc?.status || 'none'}
                        </div>
                      </div>
                    </div>

                    {/* Metadata summary list */}
                    <div className="mt-4 p-3.5 rounded-2xl bg-slate-950/50 border border-slate-800/80 font-mono text-[11px] space-y-1.5 text-slate-300">
                      <div>
                        <span className="text-slate-500">From Header: </span>
                        <span className="text-slate-200">{currentResult.metadata?.from_addr || currentResult.metadata?.from || 'N/A'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Return-Path: </span>
                        <span className="text-amber-300">{currentResult.metadata?.return_path || 'N/A'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Subject: </span>
                        <span className="text-slate-200">{currentResult.metadata?.subject || 'N/A'}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Attack Graph */}
        {activeTab === 'graph' && (
          <div className="space-y-6">
            <AttackGraph data={graphData} />
          </div>
        )}

        {/* Tab 3: Digital Twin Profiling */}
        {activeTab === 'twin' && (
          <div className="space-y-6">
            <div className="glass-panel p-8 rounded-3xl border border-slate-800">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-xl font-bold text-white">
                    User Behavioral Digital Twin (TwinGuard Model)
                  </h3>
                  <p className="text-xs text-slate-400 mt-1 font-mono">
                    User ID: secops_admin • Differential Privacy Enabled • Body Free
                  </p>
                </div>
                <button
                  onClick={handleSeedBaseline}
                  className="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-mono font-bold transition-all"
                >
                  Re-Train Profile Baseline
                </button>
              </div>

              {twinSummary ? (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="p-5 rounded-2xl bg-slate-950/70 border border-slate-800 font-mono">
                    <div className="text-xs text-slate-400">Total Analyzed Interactions</div>
                    <div className="text-3xl font-black text-cyan-400 mt-2">
                      {twinSummary.total_emails}
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1">Profile baseline maturity</div>
                  </div>

                  <div className="p-5 rounded-2xl bg-slate-950/70 border border-slate-800 font-mono">
                    <div className="text-xs text-slate-400">Unique Hashed Contacts</div>
                    <div className="text-3xl font-black text-purple-400 mt-2">
                      {twinSummary.unique_contacts}
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1">SHA-256 protected identities</div>
                  </div>

                  <div className="p-5 rounded-2xl bg-slate-950/70 border border-slate-800 font-mono">
                    <div className="text-xs text-slate-400">Trusted Subnet Prefixes</div>
                    <div className="text-3xl font-black text-emerald-400 mt-2">
                      {twinSummary.unique_ip_prefixes}
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1">/24 anonymized networks</div>
                  </div>

                  <div className="md:col-span-3 p-5 rounded-2xl bg-slate-950/70 border border-slate-800 font-mono">
                    <div className="text-xs text-slate-400 mb-2">Typical Communication Hours (UTC)</div>
                    <div className="flex gap-2">
                      {twinSummary.typical_hours?.map((h: number) => (
                        <span key={h} className="px-3 py-1 rounded-lg bg-slate-900 text-cyan-300 border border-slate-800 text-xs font-bold">
                          {h.toString().padStart(2, '0')}:00 UTC
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-slate-500 text-xs font-mono">
                  Loading behavioral baseline metrics...
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 4: Self-Healing Policies */}
        {activeTab === 'policies' && (
          <div className="space-y-6">
            <div className="glass-panel p-8 rounded-3xl border border-slate-800">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-xl font-bold text-white">
                    Autonomous Self-Healing Policy State (EvoMail)
                  </h3>
                  <p className="text-xs text-slate-400 mt-1 font-mono">
                    Dynamic firewall rules auto-adapted after adversarial challenge evaluations.
                  </p>
                </div>
                <div className="px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-xs font-mono font-bold">
                  AUTONOMOUS HEALING ACTIVE
                </div>
              </div>

              {policiesData?.policies && (
                <div className="space-y-6">
                  {/* Blocked Domains */}
                  <div>
                    <div className="text-xs font-mono font-bold uppercase text-slate-300 mb-2">
                      Autonomous Blocked Sender Domains ({policiesData.policies.blocked_domains?.length || 0})
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {policiesData.policies.blocked_domains?.map((d: string) => (
                        <span key={d} className="px-3 py-1 rounded-xl bg-rose-950/40 text-rose-300 border border-rose-800/60 text-xs font-mono">
                          {d}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Suspicious Off-Hours Matrix */}
                  <div>
                    <div className="text-xs font-mono font-bold uppercase text-slate-300 mb-2">
                      Dynamic Off-Hours Anomaly Matrix (UTC Hours Flagged)
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {policiesData.policies.suspicious_hours?.map((h: number) => (
                        <span key={h} className="px-2.5 py-1 rounded-lg bg-amber-950/40 text-amber-300 border border-amber-800/60 text-xs font-mono">
                          {h.toString().padStart(2, '0')}:00
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Audit Trail */}
                  <div>
                    <div className="text-xs font-mono font-bold uppercase text-slate-300 mb-3">
                      Recent Self-Healing Audit Trail
                    </div>
                    <div className="space-y-2 max-h-72 overflow-y-auto pr-2">
                      {policiesData.audit_log?.map((log: any, idx: number) => (
                        <div key={idx} className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-xs font-mono flex items-start justify-between">
                          <div>
                            <span className="text-cyan-400 font-bold">{log.action}: </span>
                            <span className="text-slate-300">{log.reason || log.description}</span>
                            {log.target && <span className="text-amber-400"> ({log.target})</span>}
                          </div>
                          <span className="text-[10px] text-slate-500 ml-4 flex-shrink-0">
                            {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : ''}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
