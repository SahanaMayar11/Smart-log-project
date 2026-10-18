import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
  Shield, 
  ArrowRight, 
  Activity, 
  Terminal, 
  Cpu, 
  Sparkles, 
  Lock, 
  Layers, 
  UploadCloud,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  BarChart2,
  FileText,
  Server,
  Zap,
  Clock
} from 'lucide-react';
import GlassCard from '../components/ui/GlassCard';
import FloatingActionButtons from '../components/ui/FloatingActionButtons';
import heroBg from '../assets/hero_bg.jpg';
import { fetchDashboardStats, fetchDetectionResults, fetchShapExplanations } from '../services/api';

const LandingPage = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [detections, setDetections] = useState([]);
  const [shapData, setShapData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadHomepageData();
  }, []);

  const loadHomepageData = async () => {
    try {
      const [sData, dData, shData] = await Promise.all([
        fetchDashboardStats().catch(() => null),
        fetchDetectionResults().catch(() => []),
        fetchShapExplanations().catch(() => []),
      ]);
      setStats(sData);
      setDetections(dData.slice(0, 5));
      setShapData(shData.slice(0, 4));
    } catch (err) {
      console.error('Error loading homepage live preview data:', err);
    } finally {
      setLoading(false);
    }
  };

  const behavioralFeatures = [
    { name: 'Event Frequency', desc: 'Monitors sudden surges in log message generation frequency' },
    { name: 'Sequence Length', desc: 'Tracks length of sequential event execution chains' },
    { name: 'Error Count', desc: 'Calculates total error events within temporal log windows' },
    { name: 'Error Pattern', desc: 'Detects repetitive error sequences indicating system faults' },
    { name: 'Login Attempts', desc: 'Measures total user/system authentication requests' },
    { name: 'Failed Login Attempts', desc: 'Identifies SSH brute-force and credential stuffing' },
    { name: 'Warning Count', desc: 'Tracks cumulative system warning indicators' },
    { name: 'Unknown Events', desc: 'Flags unclassified or rare syslog message types' },
  ];

  const processSteps = [
    { title: 'SERVER LOGS', desc: 'Raw Syslog Ingestion' },
    { title: 'PARSING', desc: 'Regex Attributes Parsing' },
    { title: 'DATA CLEANING', desc: 'Noise Stripping & Formats' },
    { title: '8 FEATURES', desc: 'Behavioral Feature Extraction' },
    { title: 'ISOLATION FOREST', desc: 'Unsupervised ML Scoring' },
    { title: 'ANOMALY DETECTION', desc: 'Severity Risk Meter' },
    { title: 'SHAP', desc: 'Explainable AI Reasoning' },
  ];

  return (
    <div className="min-h-screen bg-[#050816] text-[#F8FAFC] flex flex-col justify-between relative overflow-hidden">
      {/* 1. HERO SECTION (~90vh) */}
      <section className="relative min-h-[92vh] pt-32 pb-20 flex flex-col items-center justify-center text-center overflow-hidden">
        {/* Full-width Cybersecurity Background Image */}
        <img
          src={heroBg}
          alt="Cybersecurity SOC Background"
          className="absolute inset-0 w-full h-full object-cover opacity-35 filter brightness-90 contrast-125 mix-blend-luminosity"
        />

        {/* Dark Gradient Overlay */}
        <div className="absolute inset-0 bg-gradient-to-b from-[#050816]/80 via-[#050816]/65 to-[#050816]/95 z-0" />

        {/* Hero Foreground Content in container-soc */}
        <div className="container-soc relative z-10 space-y-6 flex flex-col items-center">
          {/* Small Badge (mb-5 / 20px) */}
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-[#00E5FF]/10 border border-[#00E5FF]/30 text-[#00E5FF] text-xs font-mono font-bold tracking-wider uppercase mb-2 glow-cyan"
          >
            <Zap className="w-3.5 h-3.5 text-[#00E5FF] animate-pulse" />
            <span>AI-POWERED SERVER SECURITY</span>
          </motion.div>

          {/* Main Heading (mb-5 / 20px, max-w-4xl) */}
          <motion.h1
            initial={{ opacity: 0, y: 25 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="text-4xl sm:text-6xl md:text-7xl font-black tracking-tight text-white leading-tight max-w-4xl"
          >
            Detect <span className="gradient-text-cyan-blue">Threats</span>. <br />
            Understand <span className="gradient-text-cyan-purple">Logs</span>. <br />
            Secure Your <span className="gradient-text-purple-cyan">Servers</span>.
          </motion.h1>

          {/* Description (mb-8 / 32px, max-w-2xl) */}
          <motion.p
            initial={{ opacity: 0, y: 25 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="max-w-2xl text-base sm:text-lg text-[#94A3B8] leading-relaxed font-sans"
          >
            Smart-Log automatically analyzes server logs, detects abnormal behaviour using Isolation Forest, and explains every detection using SHAP.
          </motion.p>

          {/* CTA Buttons (mb-10 / 40px, Equal Height: h-[52px]) */}
          <motion.div
            initial={{ opacity: 0, y: 25 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4 w-full sm:w-auto"
          >
            <button
              onClick={() => navigate('/upload')}
              className="w-full sm:w-auto h-[52px] px-7 rounded-[12px] bg-gradient-to-r from-[#00E5FF] via-[#2563EB] to-[#8B5CF6] text-slate-950 font-black text-sm uppercase tracking-wider flex items-center justify-center gap-3 glow-cyan hover:scale-105 transition-all"
            >
              <span>Upload Server Logs</span>
              <ArrowRight className="w-4 h-4" />
            </button>

            <button
              onClick={() => navigate('/dashboard')}
              className="w-full sm:w-auto h-[52px] px-7 rounded-[12px] bg-slate-900/90 border border-slate-700/80 text-white font-bold text-sm uppercase tracking-wider hover:border-[#00E5FF]/50 hover:bg-slate-800 hover:scale-105 transition-all flex items-center justify-center"
            >
              Explore Dashboard
            </button>
          </motion.div>

          {/* HERO ACTION CARD (padding: 28px / p-7, gap: 20px / space-y-5) */}
          <motion.div
            initial={{ opacity: 0, y: 35 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.4 }}
            className="w-full max-w-3xl p-7 rounded-2xl glass-panel border border-[#00E5FF]/30 glow-cyan text-left space-y-5"
          >
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-800 pb-4">
              <div>
                <h3 className="text-xl font-extrabold text-white flex items-center gap-2">
                  <Server className="w-5 h-5 text-[#00E5FF]" /> Analyze Your Server Logs
                </h3>
                <p className="text-xs text-[#94A3B8] mt-1">Drag and drop log files to execute automated AI anomaly detection</p>
              </div>

              <div className="flex gap-2 font-mono text-[10px]">
                <span className="px-3 py-1 rounded-full bg-[#00E5FF]/10 text-[#00E5FF] border border-[#00E5FF]/30 font-bold">
                  Upload .LOG
                </span>
                <span className="px-3 py-1 rounded-full bg-[#2563EB]/10 text-[#2563EB] border border-[#2563EB]/30 font-bold">
                  Upload .TXT
                </span>
                <span className="px-3 py-1 rounded-full bg-[#8B5CF6]/10 text-[#8B5CF6] border border-[#8B5CF6]/30 font-bold">
                  Upload .CSV
                </span>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-center gap-4">
              <button
                onClick={() => navigate('/upload')}
                className="w-full sm:w-auto flex-1 h-[52px] px-7 rounded-[12px] bg-gradient-to-r from-[#00E5FF] to-[#2563EB] text-slate-950 font-black text-sm uppercase tracking-wider flex items-center justify-center gap-3 glow-cyan hover:scale-[1.01] transition-all"
              >
                <span>UPLOAD LOG</span>
                <UploadCloud className="w-5 h-5" />
              </button>

              <button
                onClick={() => navigate('/dashboard')}
                className="w-full sm:w-auto h-[52px] px-7 rounded-[12px] bg-slate-950 border border-slate-700 hover:border-[#00E5FF] text-white font-bold text-sm uppercase tracking-wider hover:bg-slate-900 transition-all flex items-center justify-center gap-2"
              >
                <span>VIEW DASHBOARD</span>
              </button>
            </div>

            {/* Checkmark Highlights */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs font-mono text-slate-300">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#10B981]" />
                <span>Isolation Forest</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#00E5FF]" />
                <span>8 Behavioral Features</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#8B5CF6]" />
                <span>SHAP Explainability</span>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Floating Circular Action Buttons */}
      <FloatingActionButtons />

      {/* 2. FEATURE SECTION: Intelligent Server Security (3-Column Desktop Grid) */}
      <section className="py-20 relative z-10">
        <div className="container-soc space-y-12">
          <div className="text-center">
            <span className="text-xs font-mono font-bold uppercase tracking-widest text-[#00E5FF]">Intelligent Engine</span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white mt-1">Intelligent Server Security</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <GlassCard className="p-8 border-[#00E5FF]/30 glass-panel-hover relative overflow-hidden flex flex-col justify-between">
              <span className="text-4xl font-mono font-black text-[#00E5FF]/20 absolute top-4 right-6">01</span>
              <div>
                <div className="p-3.5 rounded-2xl bg-[#00E5FF]/10 text-[#00E5FF] border border-[#00E5FF]/30 w-fit mb-5">
                  <FileText className="w-6 h-6" />
                </div>
                <h3 className="text-xl font-bold text-white mb-2">LOG ANALYSIS</h3>
                <p className="text-xs text-[#94A3B8] leading-relaxed">
                  Regex-based syslog parsing, timestamp formatting, noise cleaning, and multi-attribute severity filtering.
                </p>
              </div>
            </GlassCard>

            <GlassCard className="p-8 border-[#8B5CF6]/30 glass-panel-hover relative overflow-hidden flex flex-col justify-between">
              <span className="text-4xl font-mono font-black text-[#8B5CF6]/20 absolute top-4 right-6">02</span>
              <div>
                <div className="p-3.5 rounded-2xl bg-[#8B5CF6]/10 text-[#8B5CF6] border border-[#8B5CF6]/30 w-fit mb-5">
                  <Cpu className="w-6 h-6" />
                </div>
                <h3 className="text-xl font-bold text-white mb-2">ISOLATION FOREST</h3>
                <p className="text-xs text-[#94A3B8] leading-relaxed">
                  Unsupervised machine learning anomaly scoring isolating abnormal server behavior in 8-dimensional space.
                </p>
              </div>
            </GlassCard>

            <GlassCard className="p-8 border-[#2563EB]/30 glass-panel-hover relative overflow-hidden flex flex-col justify-between">
              <span className="text-4xl font-mono font-black text-[#2563EB]/20 absolute top-4 right-6">03</span>
              <div>
                <div className="p-3.5 rounded-2xl bg-[#2563EB]/10 text-[#2563EB] border border-[#2563EB]/30 w-fit mb-5">
                  <Sparkles className="w-6 h-6" />
                </div>
                <h3 className="text-xl font-bold text-white mb-2">SHAP EXPLAINABILITY</h3>
                <p className="text-xs text-[#94A3B8] leading-relaxed">
                  Decomposes predictions into feature contribution waterfalls and natural language explanation statements.
                </p>
              </div>
            </GlassCard>
          </div>
        </div>
      </section>

      {/* 3. PROCESS SECTION: Animated Connected Stage Cards */}
      <section className="py-16 relative z-10 border-t border-slate-800/80">
        <div className="container-soc space-y-10">
          <div className="text-center">
            <span className="text-xs font-mono font-bold uppercase tracking-widest text-[#8B5CF6]">End-to-End Flow</span>
            <h2 className="text-3xl font-extrabold text-white mt-1">Automated Execution Pipeline</h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-7 gap-3">
            {processSteps.map((step, idx) => (
              <div key={idx} className="p-4 rounded-xl glass-panel border border-slate-800 flex flex-col items-center text-center group hover:border-[#00E5FF] transition-all">
                <span className="text-[10px] font-mono text-[#00E5FF] font-bold mb-1">0{idx + 1}</span>
                <h4 className="text-xs font-bold text-white mb-1">{step.title}</h4>
                <p className="text-[10px] text-[#94A3B8]">{step.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 4. DASHBOARD PREVIEW SECTION: Your Security Operations Center */}
      <section className="py-16 relative z-10 border-t border-slate-800/80">
        <div className="container-soc space-y-8">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
            <div>
              <span className="text-xs font-mono font-bold uppercase tracking-widest text-[#00E5FF]">Live Telemetry</span>
              <h2 className="text-3xl font-extrabold text-white mt-1">Your Security Operations Center</h2>
            </div>
            <button
              onClick={() => navigate('/dashboard')}
              className="h-11 px-5 rounded-xl bg-slate-900 border border-slate-700 text-xs font-bold text-[#00E5FF] hover:border-[#00E5FF] transition-all flex items-center gap-2"
            >
              <span>Open Full Dashboard</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

          {/* Live KPI Cards Preview (4-Column Grid) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="p-6 rounded-2xl glass-panel border border-slate-800 flex flex-col justify-between">
              <span className="text-xs font-mono text-[#94A3B8] uppercase">Total Logs Processed</span>
              <p className="text-3xl font-black text-white mt-2 font-mono">{stats?.total_logs || 0}</p>
              <span className="text-[10px] text-[#00E5FF] mt-1 block">Parsed syslog stream</span>
            </div>

            <div className="p-6 rounded-2xl glass-panel border border-[#10B981]/30 flex flex-col justify-between">
              <span className="text-xs font-mono text-[#94A3B8] uppercase">Normal Baseline Logs</span>
              <p className="text-3xl font-black text-[#10B981] mt-2 font-mono">{stats?.normal_logs || 0}</p>
              <span className="text-[10px] text-[#10B981] mt-1 block">Operational system state</span>
            </div>

            <div className="p-6 rounded-2xl glass-panel border border-[#EF4444]/30 glow-red flex flex-col justify-between">
              <span className="text-xs font-mono text-[#94A3B8] uppercase">Anomaly Logs Flagged</span>
              <p className="text-3xl font-black text-[#EF4444] mt-2 font-mono">{stats?.anomaly_logs || 0}</p>
              <span className="text-[10px] text-[#EF4444] mt-1 block">Isolation Forest threats</span>
            </div>

            <div className="p-6 rounded-2xl glass-panel border border-[#8B5CF6]/30 flex flex-col justify-between">
              <span className="text-xs font-mono text-[#94A3B8] uppercase">Current Threat Level</span>
              <p className="text-3xl font-black text-[#8B5CF6] mt-2 font-mono">
                {stats?.anomaly_logs > 0 ? 'HIGH' : 'NORMAL'}
              </p>
              <span className="text-[10px] text-[#8B5CF6] mt-1 block">SOC Risk Assessment</span>
            </div>
          </div>
        </div>
      </section>

      {/* 5. ANOMALY SECTION: Find What Doesn't Belong */}
      <section className="py-16 relative z-10 border-t border-slate-800/80">
        <div className="container-soc space-y-8">
          <div className="text-center">
            <span className="text-xs font-mono font-bold uppercase tracking-widest text-[#EF4444]">Threat Detection</span>
            <h2 className="text-3xl font-extrabold text-white mt-1">Find What Doesn't Belong</h2>
            <p className="text-xs text-[#94A3B8] mt-2 max-w-xl mx-auto">
              Categorizes server events into glowing severity levels using continuous Isolation Forest anomaly scoring.
            </p>
          </div>

          {/* Glowing Indicators */}
          <div className="flex flex-wrap justify-center items-center gap-4">
            <div className="px-5 py-2.5 rounded-xl bg-[#10B981]/15 border border-[#10B981]/40 text-[#10B981] text-xs font-mono font-bold flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-[#10B981]" />
              <span>NORMAL — Baseline Behavior</span>
            </div>
            <div className="px-5 py-2.5 rounded-xl bg-amber-500/15 border border-amber-500/40 text-amber-400 text-xs font-mono font-bold flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-amber-400" />
              <span>WARNING — Moderate Deviation</span>
            </div>
            <div className="px-5 py-2.5 rounded-xl bg-[#EF4444]/15 border border-[#EF4444]/40 text-[#EF4444] text-xs font-mono font-bold flex items-center gap-2 glow-red">
              <div className="w-2.5 h-2.5 rounded-full bg-[#EF4444] animate-ping" />
              <span>ANOMALY — Critical Cyber Threat</span>
            </div>
          </div>

          {/* Live Detections Table Preview */}
          <div className="glass-panel overflow-hidden border border-slate-800">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-[#081225] text-[#94A3B8] uppercase text-[10px] font-mono border-b border-slate-800">
                <tr>
                  <th className="p-3.5">Log ID</th>
                  <th className="p-3.5">Timestamp</th>
                  <th className="p-3.5">Service</th>
                  <th className="p-3.5">Classification</th>
                  <th className="p-3.5">Anomaly Score</th>
                  <th className="p-3.5">Message Snippet</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {detections.length > 0 ? (
                  detections.map((r) => (
                    <tr key={r.id} className={`transition-colors ${r.is_anomaly === 1 ? 'bg-[#EF4444]/10 hover:bg-[#EF4444]/20 border-l-2 border-l-[#EF4444]' : 'hover:bg-slate-900/40'}`}>
                      <td className="p-3.5 text-[#00E5FF] font-bold">#{r.log_id}</td>
                      <td className="p-3.5 text-slate-400">{r.timestamp}</td>
                      <td className="p-3.5 text-[#8B5CF6] font-semibold">{r.service}</td>
                      <td className="p-3.5">
                        <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                          r.is_anomaly === 1 ? 'bg-[#EF4444]/20 text-[#EF4444] border border-[#EF4444]/40 glow-red' : 'bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/40'
                        }`}>
                          {r.is_anomaly === 1 ? 'ANOMALY' : 'NORMAL'}
                        </span>
                      </td>
                      <td className="p-3.5 font-bold text-white">{r.anomaly_score}</td>
                      <td className="p-3.5 text-slate-300 max-w-xs truncate">{r.message}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="6" className="p-6 text-center text-slate-500">Loading detection stream...</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* 6. SHAP SECTION: Don't Just Detect. Understand Why. */}
      <section className="py-16 relative z-10 border-t border-slate-800/80">
        <div className="container-soc space-y-10">
          <div className="text-center">
            <span className="text-xs font-mono font-bold uppercase tracking-widest text-[#00E5FF]">Explainable AI</span>
            <h2 className="text-3xl font-extrabold text-white mt-1">Don't Just Detect. Understand Why.</h2>
            <p className="text-xs text-[#94A3B8] mt-2 max-w-xl mx-auto">
              Quantifies the exact mathematical contribution of all 8 behavioral features to explain model decisions.
            </p>
          </div>

          {/* 8 Behavioral Feature Cards (4-Column Grid) */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {behavioralFeatures.map((feat, idx) => (
              <div key={idx} className="p-4 rounded-xl glass-panel border border-slate-800 hover:border-[#00E5FF]/50 transition-all flex flex-col justify-between">
                <div>
                  <span className="text-[10px] font-mono font-bold text-[#00E5FF] block mb-1">FEATURE 0{idx + 1}</span>
                  <h4 className="text-xs font-bold text-white">{feat.name}</h4>
                  <p className="text-[11px] text-[#94A3B8] mt-1 leading-relaxed">{feat.desc}</p>
                </div>
              </div>
            ))}
          </div>

          {/* SHAP Explanations Preview */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {shapData.map((item) => (
              <div key={item.log_id} className="p-4 rounded-xl glass-panel border border-slate-800 text-xs flex flex-col justify-between">
                <div>
                  <div className="flex justify-between items-center mb-2 font-mono">
                    <span className="text-[#00E5FF] font-bold">Log #{item.log_id}</span>
                    <span className="text-purple-400 font-semibold">{item.service}</span>
                  </div>
                  <p className="text-slate-200 mb-2">{item.natural_explanation}</p>
                </div>
                <div className="text-[10px] font-mono text-[#94A3B8] pt-2 border-t border-slate-800 flex justify-between">
                  <span>Top Driver: <strong className="text-cyan-300">{item.top_reason}</strong></span>
                  <span>Score: {item.anomaly_score}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-6 border-t border-slate-800 bg-[#081225]/90 backdrop-blur-md relative z-10 text-center text-xs text-[#94A3B8]">
        <div className="container-soc">
          SMART-LOG | Department of Computer Science and Engineering Major Project 2025–2026 | Bapuji Institute of Engineering and Technology, Davanagere (VTU)
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;
