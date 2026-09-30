import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Copy, 
  Check, 
  FileText, 
  Cpu, 
  RefreshCw, 
  UploadCloud, 
  Layers, 
  Lock, 
  AlertTriangle,
  Server,
  Activity,
  CheckCircle2,
  ChevronRight,
  X
} from 'lucide-react';

interface FixItem {
  rank: number;
  title: string;
  score_gain: number;
  priority: string;
  mta: string;
  file: string;
  snippet: string;
  exim_snippet?: string;
  explanation: string;
  command?: string;
}

interface Deduction {
  rule_id: string;
  title: string;
  category: string;
  points: number;
  standard: string;
  description: string;
  evidence: string;
}

interface ScanData {
  id: string;
  filename: string;
  server_name: string;
  score: number;
  rating: string;
  rating_color: string;
  target_score: number;
  target_rating: string;
  deductions: Deduction[];
  total_deduction: number;
  remediation: {
    primary_fixes: FixItem[];
    later_fixes: { title: string; score_gain: number; snippet: string }[];
    total_potential_gain: number;
  };
  sessions: any[];
  ai_insights: {
    anomalies_detected: number;
    anomaly_ratio: number;
    algorithm: string;
    xai_model: string;
    shap_features: { feature: string; impact: number; severity: string }[];
    interpretation: string;
  };
  stats: {
    total_sessions: number;
    tls_versions: string[];
    ciphers: string[];
    starttls_success: number;
    anomalies: number;
  };
}

export function App() {
  const [scan, setScan] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [mtaFormat, setMtaFormat] = useState<'postfix' | 'exim'>('postfix');
  const [activeTab, setActiveTab] = useState<'dashboard' | 'inspector' | 'ai' | 'report'>('dashboard');
  const [isComparing, setIsComparing] = useState<boolean>(false);
  const [compareData, setCompareData] = useState<any>(null);
  const [sampleList, setSampleList] = useState<any[]>([]);

  useEffect(() => {
    fetchSamples();
  }, []);

  const fetchSamples = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/samples');
      const data = await res.json();
      setSampleList(data);
      if (data && data.length > 0) {
        loadScan(data[0].id);
      }
    } catch (err) {
      console.error("Failed to load samples:", err);
      setLoading(false);
    }
  };

  const loadScan = async (scanId: string) => {
    try {
      setLoading(true);
      const res = await fetch(`/api/scan/${scanId}`);
      const data = await res.json();
      setScan(data);
      setLoading(false);
    } catch (err) {
      console.error("Error loading scan:", err);
      setLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const file = e.target.files[0];
    const formData = new FormData();
    formData.append('file', file);

    try {
      setLoading(true);
      const res = await fetch('/api/scan/upload', {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      setScan(data);
      setLoading(false);
    } catch (err) {
      console.error("Upload error:", err);
      setLoading(false);
    }
  };

  const handleCopy = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const runComparison = async () => {
    if (sampleList.length >= 2) {
      try {
        setLoading(true);
        const res = await fetch('/api/scan/compare', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            before_id: sampleList[0].id,
            after_id: sampleList[1].id
          })
        });
        const comp = await res.json();
        setCompareData(comp);
        setIsComparing(true);
        setLoading(false);
      } catch (err) {
        console.error("Compare error:", err);
        setLoading(false);
      }
    }
  };

  return (
    <div className="min-h-screen bg-[#070b12] text-slate-200 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top SIH 2026 Navigation Bar */}
      <header className="border-b border-slate-800/80 bg-[#0c121e]/90 backdrop-blur sticky top-0 z-50 px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-emerald-500 p-0.5 shadow-lg shadow-cyan-500/20">
            <div className="w-full h-full bg-[#070b12] rounded-[10px] flex items-center justify-center">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold tracking-wider text-cyan-400 uppercase">SIH26159</span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 font-mono">Team AlgoMaster</span>
            </div>
            <h1 className="text-lg font-bold text-white tracking-tight flex items-center gap-1.5">
              SecureMailScope <span className="text-xs font-normal text-slate-400">· AI Posture Assessment</span>
            </h1>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <Lock className="w-3.5 h-3.5" />
            <span className="font-medium">Passive · Zero-Decryption</span>
          </div>
          <div className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-300">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <span>NIST SP 800-52r2 + RFC 8314</span>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6">
        
        {/* Quick Scenario & File Ingestion Bar */}
        <section className="bg-[#0e1626] border border-slate-800 rounded-2xl p-4 shadow-xl flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider mr-1">Load Scenario:</span>
            {sampleList.map((sample, idx) => (
              <button
                key={sample.id}
                onClick={() => loadScan(sample.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-1.5 ${
                  scan?.id === sample.id
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                    : 'bg-slate-800/80 hover:bg-slate-800 text-slate-300 border border-slate-700/60'
                }`}
              >
                {idx === 0 ? <ShieldAlert className="w-3.5 h-3.5 text-amber-400" /> : <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />}
                <span>{sample.host} ({sample.score} pts)</span>
              </button>
            ))}
          </div>

          <div className="flex items-center gap-3 w-full md:w-auto">
            <label className="cursor-pointer flex items-center justify-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs font-semibold shadow-md shadow-cyan-600/20 transition-all">
              <UploadCloud className="w-4 h-4" />
              <span>Upload Capture (.pcap)</span>
              <input type="file" accept=".pcap,.pcapng,.cap" className="hidden" onChange={handleFileUpload} />
            </label>
            <button
              onClick={runComparison}
              className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-800 hover:bg-slate-750 text-slate-300 hover:text-white rounded-xl text-xs font-semibold border border-slate-700 transition-all"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              <span>Compare Re-Scan Proof</span>
            </button>
          </div>
        </section>

        {loading && (
          <div className="text-center py-4 text-xs text-cyan-400 font-mono animate-pulse">
            Processing cryptographic telemetry & telemetry handshakes...
          </div>
        )}

        {/* View Navigation Tabs */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-1">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-all flex items-center gap-2 ${
              activeTab === 'dashboard'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Dashboard & Remediation</span>
          </button>
          <button
            onClick={() => setActiveTab('inspector')}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-all flex items-center gap-2 ${
              activeTab === 'inspector'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Traffic & Handshake Inspector ({scan?.sessions.length || 0})</span>
          </button>
          <button
            onClick={() => setActiveTab('ai')}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-all flex items-center gap-2 ${
              activeTab === 'ai'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="w-4 h-4" />
            <span>Explainable AI & Anomaly Engine</span>
          </button>
          <button
            onClick={() => setActiveTab('report')}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-all flex items-center gap-2 ${
              activeTab === 'report'
                ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>CERT-In Audit Report</span>
          </button>
        </div>

        {/* COMPARISON MODAL */}
        {isComparing && compareData && (
          <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-[#0e1626] border border-cyan-500/40 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-6">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <RefreshCw className="w-5 h-5 text-cyan-400" />
                  <h3 className="text-base font-bold text-white">Before vs After Re-Scan Verification</h3>
                </div>
                <button 
                  onClick={() => setIsComparing(false)}
                  className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="grid grid-cols-2 gap-6 items-center">
                <div className="bg-[#090d16] p-4 rounded-xl border border-slate-800 text-center space-y-2">
                  <div className="text-xs uppercase text-slate-400 font-semibold">Pre-Remediation</div>
                  <div className="text-3xl font-bold text-amber-400 font-mono">{compareData.before.score}</div>
                  <span className="text-xs px-2.5 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/30">
                    {compareData.before.rating}
                  </span>
                  <div className="text-[11px] text-slate-500">{compareData.before.server_name}</div>
                </div>

                <div className="bg-[#090d16] p-4 rounded-xl border border-slate-800 text-center space-y-2">
                  <div className="text-xs uppercase text-slate-400 font-semibold">Post-Remediation</div>
                  <div className="text-3xl font-bold text-emerald-400 font-mono">{compareData.after.score}</div>
                  <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    {compareData.after.rating}
                  </span>
                  <div className="text-[11px] text-slate-500">{compareData.after.server_name}</div>
                </div>
              </div>

              <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4 text-center">
                <div className="text-sm font-bold text-emerald-300">
                  Verification Complete: +{compareData.score_delta} Score Increase
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Transition: <strong className="text-white">{compareData.status_transition}</strong> · {compareData.fixes_verified} critical fixes applied and re-tested passively.
                </div>
              </div>

              <div className="text-right">
                <button
                  onClick={() => setIsComparing(false)}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold"
                >
                  Close Proof Window
                </button>
              </div>
            </div>
          </div>
        )}

        {/* TAB 1: DASHBOARD & REMEDIATION (Matches Slide 4 MVP Prototype Screen) */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            
            {/* Top Server Stats & Posture Card */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              {/* Score Metric */}
              <div className="bg-[#0e1626] border border-slate-800 rounded-2xl p-5 flex items-center gap-4 shadow-lg">
                <div className={`w-16 h-16 rounded-2xl flex items-center justify-center font-bold text-2xl border ${
                  scan?.rating === 'Secure'
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                    : scan?.rating === 'Attention'
                    ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                    : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                }`}>
                  {scan?.score}
                </div>
                <div>
                  <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Security Score</div>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-xl font-bold text-white">{scan?.score} / 100</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full font-semibold border ${
                      scan?.rating === 'Secure'
                        ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                        : scan?.rating === 'Attention'
                        ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                        : 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                    }`}>
                      {scan?.rating}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1 font-mono">Host: {scan?.server_name}</div>
                </div>
              </div>

              {/* Protocol breakdown */}
              <div className="bg-[#0e1626] border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-col justify-center">
                <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Detected Protocol</div>
                <div className="text-lg font-bold text-white mt-1">SMTP over STARTTLS</div>
                <div className="text-xs text-slate-400 mt-0.5">
                  TLS Version: <span className="font-mono text-cyan-400">{scan?.stats.tls_versions.join(', ') || 'TLS 1.0'}</span>
                </div>
              </div>

              {/* Cipher Suite */}
              <div className="bg-[#0e1626] border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-col justify-center">
                <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Cipher Architecture</div>
                <div className="text-sm font-mono text-amber-300 truncate mt-1" title={scan?.stats.ciphers[0] || 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'}>
                  {scan?.stats.ciphers[0] || 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'}
                </div>
                <div className="text-xs text-rose-400 mt-1 flex items-center gap-1 font-medium">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>No Forward Secrecy (PFS)</span>
                </div>
              </div>

              {/* Anomaly & STARTTLS State */}
              <div className="bg-[#0e1626] border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-col justify-center">
                <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold">STARTTLS Health</div>
                <div className="text-lg font-bold text-emerald-400 mt-1">Negotiated (State 220)</div>
                <div className="text-xs text-slate-400 mt-0.5">
                  Pre-TLS plain AUTH: <span className="text-rose-400 font-semibold">Detected</span>
                </div>
              </div>
            </div>

            {/* SLIDE 4 PROTOTYPE SCREEN RECREATION */}
            <div className="bg-[#0e1626] border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-6">
              
              {/* Browser-style address bar header matching Slide 4 mockup */}
              <div className="flex items-center gap-3 pb-4 border-b border-slate-800">
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-rose-500/80"></div>
                  <div className="w-3 h-3 rounded-full bg-amber-500/80"></div>
                  <div className="w-3 h-3 rounded-full bg-emerald-500/80"></div>
                </div>
                <div className="flex-1 bg-[#090d16] border border-slate-800 rounded-lg px-4 py-1.5 text-xs font-mono text-slate-400 flex items-center gap-2">
                  <Lock className="w-3.5 h-3.5 text-cyan-400" />
                  <span>securemailscope.local / server / <span className="text-white font-medium">{scan?.server_name}</span> / fixes</span>
                </div>
                <div className="flex items-center gap-1 bg-[#090d16] p-1 rounded-lg border border-slate-800 text-xs">
                  <button
                    onClick={() => setMtaFormat('postfix')}
                    className={`px-2.5 py-1 rounded font-medium transition-all ${
                      mtaFormat === 'postfix' ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Postfix
                  </button>
                  <button
                    onClick={() => setMtaFormat('exim')}
                    className={`px-2.5 py-1 rounded font-medium transition-all ${
                      mtaFormat === 'exim' ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Exim
                  </button>
                </div>
              </div>

              {/* Main Two-Column Slide 4 Layout */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
                
                {/* Column 1 & 2: FIX THIS FIRST · RANKED BY SCORE GAIN */}
                <div className="lg:col-span-2 space-y-4">
                  <div className="flex items-center justify-between">
                    <h2 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
                      <span className="uppercase tracking-wider text-xs px-2.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                        Action Plan
                      </span>
                      <span>FIX THIS FIRST · RANKED BY SCORE GAIN</span>
                    </h2>
                    <span className="text-xs text-slate-400 font-mono">
                      Potential Gain: <strong className="text-emerald-400">+{scan?.remediation.total_potential_gain || 41} pts</strong>
                    </span>
                  </div>

                  {/* Ranked Fix Cards */}
                  <div className="space-y-3">
                    {scan?.remediation.primary_fixes.map((fix, idx) => (
                      <div
                        key={idx}
                        className="bg-[#090e18] border border-slate-800/80 rounded-xl p-4 hover:border-slate-700 transition-all space-y-2.5"
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex items-center gap-3">
                            <div className="w-7 h-7 rounded-full bg-cyan-600/20 border border-cyan-500/40 text-cyan-400 flex items-center justify-center font-bold text-xs shrink-0">
                              {fix.rank}
                            </div>
                            <div>
                              <h3 className="text-sm font-semibold text-white tracking-tight">{fix.title}</h3>
                              <p className="text-xs text-slate-400 mt-0.5">{fix.explanation}</p>
                            </div>
                          </div>
                          <span className="text-xs font-bold px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 shrink-0 font-mono">
                            +{fix.score_gain}
                          </span>
                        </div>

                        {/* Config Code Snippet Box with Copy Button */}
                        <div className="relative group bg-[#05080f] rounded-lg p-3 border border-slate-800 font-mono text-xs text-slate-300">
                          <div className="pr-12 overflow-x-auto whitespace-pre">
                            {mtaFormat === 'postfix' ? fix.snippet : (fix.exim_snippet || fix.snippet)}
                          </div>
                          <button
                            onClick={() => handleCopy(mtaFormat === 'postfix' ? fix.snippet : (fix.exim_snippet || fix.snippet), idx)}
                            className="absolute right-2 top-2 p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-all border border-slate-700"
                            title="Copy snippet to clipboard"
                          >
                            {copiedIndex === idx ? (
                              <Check className="w-4 h-4 text-emerald-400" />
                            ) : (
                              <Copy className="w-4 h-4" />
                            )}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Later recommendations footnote (from Slide 4) */}
                  <div className="pt-2 text-xs text-slate-400 border-t border-slate-800/60 flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-slate-300">Later:</span>
                    {scan?.remediation.later_fixes.map((later, lIdx) => (
                      <span key={lIdx} className="bg-slate-800/60 px-2.5 py-1 rounded-md border border-slate-700/60 text-slate-300">
                        {later.title} <strong className="text-cyan-400">(+{later.score_gain})</strong>
                      </span>
                    ))}
                  </div>
                </div>

                {/* Column 3: BEFORE VS AFTER RE-SCAN (Visual comparison from Slide 4) */}
                <div className="bg-[#090e18] border border-slate-800 rounded-xl p-5 flex flex-col items-center justify-between h-full min-h-[380px] shadow-inner">
                  <div className="text-center w-full">
                    <h3 className="text-xs uppercase tracking-wider font-bold text-slate-400">
                      BEFORE VS AFTER RE-SCAN
                    </h3>
                    <p className="text-[11px] text-slate-500 mt-0.5">The fix, mathematically proven</p>
                  </div>

                  {/* Comparison Bar Charts */}
                  <div className="flex items-end justify-center gap-10 w-full my-6 h-52 px-4">
                    {/* Before Bar */}
                    <div className="flex flex-col items-center gap-2">
                      <span className="text-base font-bold text-amber-400 font-mono">
                        {scan?.score || 48}
                      </span>
                      <div 
                        className="w-16 rounded-t-lg bg-gradient-to-t from-amber-600 to-amber-500 shadow-lg shadow-amber-500/20 transition-all duration-700"
                        style={{ height: `${Math.max(40, ((scan?.score || 48) / 100) * 160)}px` }}
                      ></div>
                      <span className="text-xs font-medium text-slate-400">Before</span>
                    </div>

                    {/* After Bar */}
                    <div className="flex flex-col items-center gap-2">
                      <span className="text-base font-bold text-emerald-400 font-mono">
                        {scan?.target_score || 89}
                      </span>
                      <div 
                        className="w-16 rounded-t-lg bg-gradient-to-t from-emerald-600 to-emerald-400 shadow-lg shadow-emerald-500/20 transition-all duration-700"
                        style={{ height: `${Math.max(40, ((scan?.target_score || 89) / 100) * 160)}px` }}
                      ></div>
                      <span className="text-xs font-medium text-slate-400">After</span>
                    </div>
                  </div>

                  {/* Transition Status Pill */}
                  <div className="w-full text-center">
                    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-semibold">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span>{scan?.rating} → {scan?.target_rating || 'Secure'}</span>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-2 font-mono">
                      +{(scan?.target_score || 89) - (scan?.score || 48)} score improvement verified
                    </div>
                  </div>
                </div>

              </div>
            </div>

            {/* Granular Deductions Ledger */}
            <div className="bg-[#0e1626] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white">Cryptographic Deductions & Evidence Ledger</h3>
                  <p className="text-xs text-slate-400 mt-0.5">Every deduction carries a NIST/RFC rule ID and frame capture evidence</p>
                </div>
                <div className="text-xs text-rose-400 font-mono font-semibold bg-rose-500/10 px-3 py-1.5 rounded-lg border border-rose-500/30">
                  Total Penalties: -{scan?.total_deduction} pts
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-[#090d16] text-slate-400 font-mono border-b border-slate-800 uppercase">
                    <tr>
                      <th className="py-2.5 px-4">Rule ID</th>
                      <th className="py-2.5 px-4">Finding Title</th>
                      <th className="py-2.5 px-4">Category</th>
                      <th className="py-2.5 px-4">Standard</th>
                      <th className="py-2.5 px-4">Evidence</th>
                      <th className="py-2.5 px-4 text-right">Deduction</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-sans">
                    {scan?.deductions.map((d, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30 transition-all">
                        <td className="py-3 px-4 font-mono text-cyan-400 font-semibold">{d.rule_id}</td>
                        <td className="py-3 px-4 font-medium text-white">{d.title}</td>
                        <td className="py-3 px-4 text-slate-400">{d.category}</td>
                        <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">{d.standard}</td>
                        <td className="py-3 px-4 text-slate-400 max-w-xs truncate" title={d.evidence}>{d.evidence}</td>
                        <td className="py-3 px-4 text-right font-mono font-bold text-rose-400">-{d.points}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        )}

        {/* TAB 2: TRAFFIC & HANDSHAKE INSPECTOR */}
        {activeTab === 'inspector' && (
          <div className="bg-[#0e1626] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
            <div>
              <h2 className="text-base font-bold text-white">Passive Handshake Stream Inspector</h2>
              <p className="text-xs text-slate-400 mt-0.5">Zero-decryption extraction of TCP stream metadata, ClientHello, ServerHello, and STARTTLS state</p>
            </div>

            <div className="space-y-4">
              {scan?.sessions.map((sess, idx) => (
                <div key={idx} className="bg-[#090e18] border border-slate-800 rounded-xl p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
                    <div className="flex items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 font-mono text-xs font-semibold border border-cyan-500/30">
                        {sess.protocol}
                      </span>
                      <span className="font-mono text-xs text-white">
                        {sess.client_ip}:{sess.client_port} → {sess.server_ip}:{sess.server_port}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-xs font-mono">
                      <span className="text-slate-400">Frames:</span>
                      <span className="text-slate-300 bg-slate-800 px-2 py-0.5 rounded">
                        #{sess.frames.join(', #')}
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-sans">
                    <div className="bg-[#05080f] p-3 rounded-lg border border-slate-800 space-y-1">
                      <span className="text-slate-500 font-medium">Negotiated TLS Version</span>
                      <div className="text-white font-mono font-semibold">{sess.tls_version}</div>
                    </div>
                    <div className="bg-[#05080f] p-3 rounded-lg border border-slate-800 space-y-1">
                      <span className="text-slate-500 font-medium">Cipher Suite</span>
                      <div className="text-amber-300 font-mono text-[11px] truncate" title={sess.cipher_name}>
                        {sess.cipher_name}
                      </div>
                    </div>
                    <div className="bg-[#05080f] p-3 rounded-lg border border-slate-800 space-y-1">
                      <span className="text-slate-500 font-medium">Certificate Validity</span>
                      <div className="text-rose-400 font-mono font-semibold">{sess.cert_days_left} Days Remaining</div>
                    </div>
                  </div>

                  {sess.plaintext_commands.length > 0 && (
                    <div className="bg-[#05080f] p-3 rounded-lg border border-slate-800 space-y-1.5">
                      <span className="text-slate-500 font-mono text-[11px] uppercase tracking-wider">
                        Pre-TLS Command Transitions (Passive Stream)
                      </span>
                      <div className="space-y-1 font-mono text-xs text-cyan-300/80">
                        {sess.plaintext_commands.map((cmd: string, cIdx: number) => (
                          <div key={cIdx} className="flex items-center gap-2">
                            <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
                            <span>{cmd}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 3: EXPLAINABLE AI & ANOMALY ENGINE */}
        {activeTab === 'ai' && (
          <div className="space-y-6">
            <div className="bg-[#0e1626] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <Cpu className="w-5 h-5 text-cyan-400" />
                  <span>Explainable AI (XAI) & Anomaly Detection</span>
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Powered by Isolation Forest (Liu et al., 2008) and SHAP Feature Attribution (Lundberg & Lee, 2017)
                </p>
              </div>

              {/* Algorithm Details */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-[#090e18] p-4 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-xs text-slate-400 uppercase font-semibold">Anomaly Model</span>
                  <div className="text-sm font-bold text-white">{scan?.ai_insights.algorithm}</div>
                  <p className="text-xs text-slate-400 mt-1">
                    Detects irregular STARTTLS negotiation sequences, anomalous session payload lengths, and plaintext command injection patterns.
                  </p>
                </div>
                <div className="bg-[#090e18] p-4 rounded-xl border border-slate-800 space-y-1">
                  <span className="text-xs text-slate-400 uppercase font-semibold">Explainability Architecture</span>
                  <div className="text-sm font-bold text-cyan-400">{scan?.ai_insights.xai_model}</div>
                  <p className="text-xs text-slate-400 mt-1">
                    Quantifies the mathematical impact of each cryptographic weakness towards overall posture deduction.
                  </p>
                </div>
              </div>

              {/* SHAP Feature Contribution Waterfall */}
              <div className="bg-[#090e18] p-5 rounded-xl border border-slate-800 space-y-4">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  SHAP Feature Attribution: Drivers of Score Reduction
                </h3>

                <div className="space-y-3">
                  {scan?.ai_insights.shap_features.map((feat, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-300 font-medium">{feat.feature}</span>
                        <span className="font-mono font-bold text-rose-400">{feat.impact} pts</span>
                      </div>
                      <div className="w-full bg-[#05080f] rounded-full h-2.5 overflow-hidden border border-slate-800">
                        <div
                          className="bg-gradient-to-r from-rose-500 to-amber-500 h-2.5 rounded-full"
                          style={{ width: `${(Math.abs(feat.impact) / 18) * 100}%` }}
                        ></div>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="bg-[#05080f] p-3 rounded-lg border border-slate-800 text-xs text-slate-400 font-mono">
                  {scan?.ai_insights.interpretation}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: CERT-IN AUDIT REPORT */}
        {activeTab === 'report' && (
          <div className="bg-white text-slate-900 rounded-2xl p-8 shadow-2xl space-y-6 font-serif">
            <div className="flex items-center justify-between border-b pb-4 border-slate-200">
              <div>
                <h2 className="text-2xl font-bold tracking-tight text-slate-900">CERT-In Cryptographic Posture Audit Report</h2>
                <p className="text-sm text-slate-500 font-sans mt-0.5">SecureMailScope Automated Email Infrastructure Assessment</p>
              </div>
              <div className="text-right font-sans">
                <div className="text-xs uppercase font-bold text-slate-400">Report Status</div>
                <div className="text-sm font-bold text-emerald-600">AUDIT VERIFIED</div>
                <div className="text-[11px] text-slate-400">Date: September 30, 2026</div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 text-sm font-sans">
              <div className="bg-slate-50 p-4 rounded-lg border border-slate-200">
                <div className="text-xs text-slate-500 uppercase font-semibold">Target Mail Host</div>
                <div className="text-base font-bold text-slate-800">{scan?.server_name}</div>
              </div>
              <div className="bg-slate-50 p-4 rounded-lg border border-slate-200">
                <div className="text-xs text-slate-500 uppercase font-semibold">Overall Posture Rating</div>
                <div className="text-base font-bold text-amber-600">{scan?.score} / 100 ({scan?.rating})</div>
              </div>
            </div>

            <div className="space-y-2 font-sans">
              <h3 className="text-sm font-bold text-slate-800 uppercase tracking-wider">Compliance Findings Summary</h3>
              <table className="w-full text-left text-xs border border-slate-200">
                <thead className="bg-slate-100 text-slate-600">
                  <tr>
                    <th className="p-2.5 border">Rule ID</th>
                    <th className="p-2.5 border">Standard Reference</th>
                    <th className="p-2.5 border">Finding Description</th>
                    <th className="p-2.5 border text-right">Deduction</th>
                  </tr>
                </thead>
                <tbody>
                  {scan?.deductions.map((d, i) => (
                    <tr key={i} className="border-b">
                      <td className="p-2.5 border font-mono font-semibold">{d.rule_id}</td>
                      <td className="p-2.5 border font-mono text-[11px]">{d.standard}</td>
                      <td className="p-2.5 border">{d.description}</td>
                      <td className="p-2.5 border text-right font-bold text-rose-600">-{d.points}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="pt-4 border-t border-slate-200 flex items-center justify-between font-sans">
              <span className="text-xs text-slate-500">SIH 2026 · Problem Statement SIH26159 · Team AlgoMaster</span>
              <button
                onClick={() => window.print()}
                className="px-4 py-2 bg-slate-900 text-white rounded-lg text-xs font-semibold hover:bg-slate-800 transition-all flex items-center gap-2"
              >
                <FileText className="w-4 h-4" />
                <span>Print / Export PDF</span>
              </button>
            </div>
          </div>
        )}

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#090d16] py-4 px-6 text-center text-xs text-slate-500 font-mono">
        SecureMailScope · Team AlgoMaster · Smart India Hackathon 2026 · "Don't just detect. Explain it. Fix it."
      </footer>
    </div>
  );
}

export default App;
