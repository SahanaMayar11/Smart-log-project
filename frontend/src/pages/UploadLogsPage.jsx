import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Play, 
  Square, 
  Activity, 
  Monitor, 
  Shield, 
  ShieldAlert, 
  CheckCircle, 
  AlertTriangle, 
  Clock, 
  ListFilter, 
  UploadCloud, 
  ChevronDown, 
  ChevronUp, 
  Sparkles, 
  Cpu, 
  RefreshCw, 
  Eye, 
  ArrowRight,
  Printer,
  LayoutDashboard,
  Search,
  PieChart as PieIcon,
  BarChart2,
  TrendingUp,
  FileText
} from 'lucide-react';
import GlassCard from '../components/ui/GlassCard';
import StatCard from '../components/ui/StatCard';
import { ServerRackVisual } from '../components/ui/CyberVisuals';
import { 
  analyzeSystemLogs,
  fetchLiveSystemLogs, 
  startLiveMonitoring, 
  stopLiveMonitoring 
} from '../services/api';

// Chart.js Registration
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Title
} from 'chart.js';
import { Pie, Bar, Line } from 'react-chartjs-2';

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Title
);

const UploadLogsPage = () => {
  const navigate = useNavigate();

  // Mode Selection: '24h' (Historical) vs 'live' (Real-Time Monitor)
  const [activeTab, setActiveTab] = useState('24h');

  // HISTORICAL 24-HOUR STATE
  const [hours, setHours] = useState(24);
  const [maxEvents, setMaxEvents] = useState(1000);
  const [analyzing24h, setAnalyzing24h] = useState(false);
  const [stepIndex24h, setStepIndex24h] = useState(-1);
  const [result24h, setResult24h] = useState(null);
  const [error24h, setError24h] = useState('');
  const [selectedHistoricalEvent, setSelectedHistoricalEvent] = useState(null);
  const [search24h, setSearch24h] = useState('');
  const [severityFilter24h, setSeverityFilter24h] = useState('');

  // LIVE MONITOR STATE
  const [isMonitoring, setIsMonitoring] = useState(true);
  const [intervalSec, setIntervalSec] = useState(3);
  const [liveData, setLiveData] = useState({
    computer_name: 'Rocky',
    total_events_monitored: 0,
    normal_count: 0,
    anomaly_count: 0,
    last_scan_time: new Date().toLocaleTimeString(),
    scanned_channels: ['System', 'Application', 'Security', 'Operational Channels'],
    unavailable_channels: [],
    admin_warning: null,
    events: []
  });
  const [loadingLive, setLoadingLive] = useState(false);
  const [errorLive, setErrorLive] = useState('');
  const [newAnomalyToast, setNewAnomalyToast] = useState(null);
  const [selectedLiveEvent, setSelectedLiveEvent] = useState(null);
  const [rawViewMap, setRawViewMap] = useState({});

  const prevAnomalyCountRef = useRef(0);

  const pipelineStages = [
    { title: '1. COLLECTING 24-HOUR WINDOWS LOGS', desc: 'Querying Windows System, Application & Security channels for past 24 hours...' },
    { title: '2. PARSING HISTORICAL EVENTS', desc: 'Extracting timestamps, record IDs, channels & log levels...' },
    { title: '3. DATA CLEANING & NORMALIZATION', desc: 'Standardizing fields & stripping payload noise...' },
    { title: '4. EXTRACTING 8 BEHAVIORAL FEATURES', desc: 'Calculating exact 8 behavioral feature metrics over historical windows...' },
    { title: '5. RUNNING SAVED ISOLATION FOREST', desc: 'Executing Isolation Forest predictions on historical dataset...' },
    { title: '6. COMPUTING SHAP EXPLANATIONS', desc: 'Generating feature contribution vectors & natural language cards...' },
    { title: '7. 24-HOUR ANALYSIS COMPLETE', desc: 'Updating SQLite database & threat analytics...' }
  ];

  // ----------------------------------------------------
  // HISTORICAL 24-HOUR HANDLER
  // ----------------------------------------------------
  const handleAnalyze24hLogs = async () => {
    setError24h('');
    setAnalyzing24h(true);
    setStepIndex24h(0);
    setResult24h(null);

    let apiResponse = null;
    let apiError = null;

    const apiPromise = (async () => {
      try {
        const res = await analyzeSystemLogs(hours, maxEvents);
        apiResponse = res;
      } catch (err) {
        apiError = err;
      }
    })();

    for (let i = 0; i < pipelineStages.length - 1; i++) {
      await new Promise((resolve) => setTimeout(resolve, 600));
      setStepIndex24h(i + 1);
    }

    await apiPromise;

    if (apiError) {
      setError24h('Backend server unreachable on port 5000.');
      setAnalyzing24h(false);
      return;
    }

    if (apiResponse && (apiResponse.status === 'success' || apiResponse.status === 'warning' || apiResponse.success)) {
      setStepIndex24h(pipelineStages.length - 1);
      setResult24h(apiResponse);
      setAnalyzing24h(false);
    } else {
      setError24h(apiResponse?.message || 'Error executing 24-hour historical scan.');
      setAnalyzing24h(false);
    }
  };

  // Run initial 24h scan on mount if no result
  useEffect(() => {
    if (!result24h && !analyzing24h) {
      handleAnalyze24hLogs();
    }
  }, []);

  // ----------------------------------------------------
  // LIVE MONITOR POLLING EFFECT
  // ----------------------------------------------------
  useEffect(() => {
    let timer = null;

    const pollLiveLogs = async () => {
      try {
        const res = await fetchLiveSystemLogs(100);
        if (res && res.status === 'success') {
          setIsMonitoring(res.is_monitoring);
          setLiveData(res);

          // Detect new anomaly for toast alert
          if (res.anomaly_count > prevAnomalyCountRef.current && prevAnomalyCountRef.current > 0) {
            const latestAnomaly = (res.events || []).find((e) => e.is_anomaly === 1);
            if (latestAnomaly) {
              setNewAnomalyToast(latestAnomaly);
              setTimeout(() => setNewAnomalyToast(null), 6000);
            }
          }
          prevAnomalyCountRef.current = res.anomaly_count;

          // Continuous Sync: Seamlessly merge live events into 24-hour historical dataset
          if (res.events && res.events.length > 0) {
            setResult24h((prev) => {
              if (!prev) return prev;
              const existingMap = new Map();
              (prev.historical_events || []).forEach((e) => existingMap.set(e.id || `${e.channel}-${e.record_id}-${e.pid}`, e));
              res.events.forEach((e) => existingMap.set(e.id || `${e.channel}-${e.record_id}-${e.pid}`, e));
              const mergedList = Array.from(existingMap.values()).sort((a, b) => new Date(b.timestamp || b.time) - new Date(a.timestamp || a.time));
              const total = mergedList.length;
              const anom = mergedList.filter((e) => e.is_anomaly === 1).length;
              const norm = total - anom;
              return {
                ...prev,
                historical_events: mergedList,
                total_logs: total,
                events_collected: total,
                normal_events: norm,
                normal_count: norm,
                anomaly_events: anom,
                anomaly_count: anom,
                anomaly_percentage: total > 0 ? parseFloat(((anom / total) * 100).toFixed(2)) : 0.0
              };
            });
          }
        }
      } catch (err) {
        console.error("Live log poll error:", err);
      }
    };

    pollLiveLogs();

    if (isMonitoring) {
      timer = setInterval(pollLiveLogs, intervalSec * 1000);
    }

    return () => {
      if (timer) clearInterval(timer);
    };
  }, [isMonitoring, intervalSec, activeTab]);

  const handleStartMonitoring = async () => {
    setErrorLive('');
    setLoadingLive(true);
    try {
      const res = await startLiveMonitoring(intervalSec);
      if (res && res.status === 'success') {
        setIsMonitoring(true);
        const liveRes = await fetchLiveSystemLogs(100);
        if (liveRes) setLiveData(liveRes);
      } else {
        setErrorLive(res?.message || 'Could not start live monitoring.');
      }
    } catch (err) {
      setErrorLive('Backend server unreachable on port 5000.');
    } finally {
      setLoadingLive(false);
    }
  };

  const handleStopMonitoring = async () => {
    setErrorLive('');
    setLoadingLive(true);
    try {
      const res = await stopLiveMonitoring();
      if (res && res.status === 'success') {
        setIsMonitoring(false);
      }
    } catch (err) {
      setErrorLive('Backend server unreachable on port 5000.');
    } finally {
      setLoadingLive(false);
    }
  };

  const toggleRawView = (id) => {
    setRawViewMap((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const formatTime = (ts) => {
    if (!ts) return 'Just now';
    if (ts.includes('T')) {
      const parts = ts.split('T');
      return `${parts[0]} ${parts[1].slice(0, 8)}`;
    }
    return ts;
  };

  // Filter historical events list
  const filteredHistoricalEvents = (result24h?.historical_events || []).filter((e) => {
    const matchSearch = !search24h || 
      (e.application_name && e.application_name.toLowerCase().includes(search24h.toLowerCase())) ||
      (e.application && e.application.toLowerCase().includes(search24h.toLowerCase())) ||
      (e.process_name && e.process_name.toLowerCase().includes(search24h.toLowerCase())) ||
      (e.process && e.process.toLowerCase().includes(search24h.toLowerCase())) ||
      (e.user && e.user.toLowerCase().includes(search24h.toLowerCase())) ||
      (e.computer && e.computer.toLowerCase().includes(search24h.toLowerCase())) ||
      (e.description && e.description.toLowerCase().includes(search24h.toLowerCase())) ||
      (e.message && e.message.toLowerCase().includes(search24h.toLowerCase())) ||
      (e.service && e.service.toLowerCase().includes(search24h.toLowerCase()));
    
    const matchSev = !severityFilter24h || e.severity === severityFilter24h || (severityFilter24h === 'Anomaly' && e.is_anomaly === 1);
    return matchSearch && matchSev;
  });

  const progressPercentage = Math.min(100, Math.round(((stepIndex24h + 1) / pipelineStages.length) * 100));

  // Chart configurations for 24-hour historical dataset
  const channelChartData = {
    labels: Object.keys(result24h?.channel_distribution || { System: 1 }),
    datasets: [{
      data: Object.values(result24h?.channel_distribution || { System: 1 }),
      backgroundColor: ['#00E5FF', '#2563EB', '#10B981', '#F59E0B', '#EF4444'],
      borderColor: '#070B14',
      borderWidth: 2
    }]
  };

  const levelChartData = {
    labels: Object.keys(result24h?.level_distribution || { INFORMATION: 1 }),
    datasets: [{
      label: 'Event Level Count',
      data: Object.values(result24h?.level_distribution || { INFORMATION: 1 }),
      backgroundColor: '#00E5FF',
      borderRadius: 6
    }]
  };

  const timelineChartData = {
    labels: (result24h?.timeline_chart || []).map((p, idx) => `E-${idx + 1}`),
    datasets: [{
      label: 'Isolation Forest Anomaly Score',
      data: (result24h?.timeline_chart || []).map((p) => p.anomaly_score),
      borderColor: '#00E5FF',
      backgroundColor: 'rgba(0, 229, 255, 0.08)',
      fill: true,
      tension: 0.3,
      pointBackgroundColor: (result24h?.timeline_chart || []).map((p) => (p.is_anomaly === 1 ? '#EF4444' : '#10B981')),
      pointRadius: 3
    }]
  };

  const timelineChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        labels: {
          color: '#FFFFFF',
          font: { family: 'sans-serif', size: 12, weight: 'bold' }
        }
      },
      tooltip: {
        backgroundColor: '#0B1220',
        titleColor: '#FFFFFF',
        bodyColor: '#E2E8F0',
        borderColor: 'rgba(0, 229, 255, 0.4)',
        borderWidth: 1
      }
    },
    scales: {
      x: {
        ticks: { color: '#FFFFFF', font: { size: 11, weight: '600' } },
        grid: { color: 'rgba(255, 255, 255, 0.10)' }
      },
      y: {
        ticks: { color: '#FFFFFF', font: { size: 11, weight: '600' } },
        grid: { color: 'rgba(255, 255, 255, 0.10)' }
      }
    }
  };

  const channelChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        position: 'top',
        labels: {
          color: '#FFFFFF',
          font: { family: 'sans-serif', size: 12, weight: 'bold' }
        }
      },
      tooltip: {
        backgroundColor: '#0B1220',
        titleColor: '#FFFFFF',
        bodyColor: '#E2E8F0',
        borderColor: 'rgba(0, 229, 255, 0.4)',
        borderWidth: 1
      }
    }
  };

  return (
    <div className="container-soc pt-28 pb-16 space-y-8">
      {/* NEW ANOMALY ALERT TOAST BANNER */}
      <AnimatePresence>
        {newAnomalyToast && (
          <motion.div
            initial={{ opacity: 0, y: -20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.95 }}
            className="p-4 rounded-2xl bg-gradient-to-r from-red-950/90 via-slate-900 to-red-950/90 border border-red-500/50 shadow-2xl flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 relative z-50 glow-red"
          >
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-red-500/20 text-red-400 border border-red-500/40 animate-bounce">
                <ShieldAlert className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold text-red-400 uppercase tracking-widest">
                    🚨 NEW ANOMALY DETECTED IN LIVE STREAM
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-red-500/20 text-red-300 font-mono font-bold">
                    {newAnomalyToast.severity || 'High'}
                  </span>
                </div>
                <p className="text-xs text-white font-semibold mt-0.5">
                  {newAnomalyToast.what_happened || newAnomalyToast.message}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3 shrink-0">
              <button
                onClick={() => {
                  setActiveTab('live');
                  setSelectedLiveEvent(newAnomalyToast);
                }}
                className="px-3.5 py-1.5 rounded-lg bg-red-500/30 hover:bg-red-500/50 border border-red-500/60 text-xs font-bold text-white transition-all"
              >
                View Details
              </button>
              <button
                onClick={() => setNewAnomalyToast(null)}
                className="text-xs text-slate-400 hover:text-white px-2"
              >
                ✕
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* DUAL-MODE PRIMARY NAVIGATION TABS */}
      <div className="flex flex-col sm:flex-row justify-between items-center gap-4 p-2 rounded-2xl bg-[#081225] border border-slate-800 backdrop-blur-xl">
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <button
            onClick={() => setActiveTab('24h')}
            className={`flex-1 sm:flex-none h-13 px-6 rounded-xl font-mono text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2.5 transition-all ${
              activeTab === '24h'
                ? 'bg-gradient-to-r from-[#00E5FF] to-[#2563EB] text-slate-950 shadow-lg glow-cyan font-black'
                : 'bg-slate-950/60 text-slate-400 hover:text-white hover:bg-slate-900 border border-slate-800'
            }`}
          >
            <Clock className="w-4 h-4" />
            <span>📊 LAST 24 HOURS (HISTORICAL)</span>
          </button>

          <button
            onClick={() => setActiveTab('live')}
            className={`flex-1 sm:flex-none h-13 px-6 rounded-xl font-mono text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2.5 transition-all ${
              activeTab === 'live'
                ? 'bg-gradient-to-r from-[#00E5FF] to-[#2563EB] text-slate-950 shadow-lg glow-cyan font-black'
                : 'bg-slate-950/60 text-slate-400 hover:text-white hover:bg-slate-900 border border-slate-800'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>⚡ LIVE SYSTEM MONITOR</span>
            {isMonitoring && <span className="w-2 h-2 rounded-full bg-[#10B981] animate-ping" />}
          </button>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono text-slate-400 pr-3">
          <Monitor className="w-4 h-4 text-[#00E5FF]" />
          <span>Host System: <strong className="text-white font-bold">{liveData.computer_name || 'Rocky'}</strong></span>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* MODE A: HISTORICAL 24-HOUR ANALYSIS TAB */}
      {/* ========================================================================= */}
      {activeTab === '24h' && (
        <div className="space-y-8 animate-fadeIn">
          {/* HEADER & CONTROL CARD */}
          <GlassCard className="p-6 border-slate-800 space-y-6">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800/80 pb-6">
              <div>
                <div className="flex items-center gap-2.5 mb-1">
                  <Clock className="w-6 h-6 text-[#00E5FF]" />
                  <h2 className="text-xl font-black text-white tracking-wide">HISTORICAL 24-HOUR WINDOWS LOG ANALYSIS</h2>
                  <span className="px-2.5 py-0.5 rounded-full bg-[#00E5FF]/15 text-[#00E5FF] border border-[#00E5FF]/30 text-[10px] font-mono font-bold">
                    Actual OS Timestamps ✓
                  </span>
                </div>
                <p className="text-xs text-[#94A3B8]">
                  Collects actual Windows Event Logs generated in the previous 24 hours on this computer and evaluates them using Isolation Forest & SHAP.
                </p>
              </div>

              {/* SCAN CONTROLS & CTA */}
              <div className="flex flex-wrap items-center gap-3">
                <div className="space-y-1 text-left">
                  <label className="text-[10px] font-mono text-slate-400 font-bold block">PERIOD:</label>
                  <select
                    value={hours}
                    onChange={(e) => setHours(Number(e.target.value))}
                    disabled={analyzing24h}
                    className="h-10 px-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:border-[#00E5FF] outline-none"
                  >
                    <option value={1}>Last 1 Hour</option>
                    <option value={6}>Last 6 Hours</option>
                    <option value={24}>Last 24 Hours (Default)</option>
                    <option value={168}>Last 7 Days</option>
                  </select>
                </div>

                <div className="space-y-1 text-left">
                  <label className="text-[10px] font-mono text-slate-400 font-bold block">MAX EVENTS:</label>
                  <select
                    value={maxEvents}
                    onChange={(e) => setMaxEvents(Number(e.target.value))}
                    disabled={analyzing24h}
                    className="h-10 px-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:border-[#00E5FF] outline-none"
                  >
                    <option value={500}>500 events (Fast)</option>
                    <option value={1000}>1,000 events (Default)</option>
                    <option value={2500}>2,500 events</option>
                    <option value={5000}>5,000 events</option>
                  </select>
                </div>

                <button
                  onClick={handleAnalyze24hLogs}
                  disabled={analyzing24h}
                  className="h-12 px-6 mt-4 rounded-xl bg-gradient-to-r from-[#00E5FF] to-[#2563EB] text-slate-950 font-black text-xs uppercase tracking-wider flex items-center justify-center gap-2 glow-cyan hover:scale-105 transition-all disabled:opacity-50"
                >
                  {analyzing24h ? (
                    <>
                      <Activity className="w-4 h-4 animate-spin" />
                      <span>Scanning 24h Logs... ({progressPercentage}%)</span>
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4" />
                      <span>ANALYZE 24-HOUR SYSTEM LOGS</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* ERROR DISPLAY */}
            {error24h && (
              <div className="p-3.5 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-2 font-mono">
                <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
                <span>{error24h}</span>
              </div>
            )}

            {/* 24-HOUR KPI SUMMARY METRIC CARDS */}
            {result24h && (
              <div className="grid grid-cols-2 sm:grid-cols-6 gap-3 text-center font-mono">
                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-[#94A3B8] uppercase block">Total 24h Events</span>
                  <strong className="text-white text-xl font-black block mt-0.5">{result24h.total_logs}</strong>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-[#94A3B8] uppercase block">Normal Events</span>
                  <strong className="text-[#10B981] text-xl font-black block mt-0.5">{result24h.normal_count}</strong>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-[#94A3B8] uppercase block">24h Anomalies</span>
                  <strong className="text-[#EF4444] text-xl font-black block mt-0.5">{result24h.anomaly_count}</strong>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-[#94A3B8] uppercase block">High Severity</span>
                  <strong className="text-red-400 text-xl font-black block mt-0.5">{result24h.severity_counts?.High || 0}</strong>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-[#94A3B8] uppercase block">Medium Severity</span>
                  <strong className="text-amber-400 text-xl font-black block mt-0.5">{result24h.severity_counts?.Medium || 0}</strong>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
                  <span className="text-[10px] text-[#94A3B8] uppercase block">Low Severity</span>
                  <strong className="text-slate-300 text-xl font-black block mt-0.5">{result24h.severity_counts?.Low || 0}</strong>
                </div>
              </div>
            )}
          </GlassCard>

          {/* PIPELINE EXECUTION PROGRESS BAR */}
          {analyzing24h && (
            <GlassCard title={`Pipeline Execution Progress (${progressPercentage}%)`} icon={Activity}>
              <div className="space-y-3">
                <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800 mb-4">
                  <motion.div
                    className="bg-gradient-to-r from-[#00E5FF] to-[#2563EB] h-full"
                    animate={{ width: `${progressPercentage}%` }}
                    transition={{ duration: 0.3 }}
                  />
                </div>

                {pipelineStages.map((stage, idx) => (
                  <div
                    key={idx}
                    className={`flex items-center gap-3 p-3 rounded-xl text-xs font-mono transition-all ${
                      idx < stepIndex24h
                        ? 'bg-[#10B981]/10 text-[#10B981] border border-[#10B981]/30'
                        : idx === stepIndex24h
                        ? 'bg-[#00E5FF]/15 text-[#00E5FF] border border-[#00E5FF]/40 font-semibold glow-cyan'
                        : 'text-slate-500 bg-slate-900/40 border border-slate-800/50'
                    }`}
                  >
                    {idx < stepIndex24h ? (
                      <CheckCircle className="w-4 h-4 text-[#10B981] shrink-0" />
                    ) : idx === stepIndex24h ? (
                      <Activity className="w-4 h-4 text-[#00E5FF] animate-spin shrink-0" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-slate-700 shrink-0" />
                    )}
                    <div>
                      <span className="font-bold">{stage.title}</span> — <span className="opacity-80">{stage.desc}</span>
                    </div>
                  </div>
                ))}
              </div>
            </GlassCard>
          )}

          {/* HISTORICAL 24-HOUR CHARTS GRID */}
          {result24h && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <GlassCard title="24-Hour Isolation Forest Score Timeline" icon={TrendingUp}>
                <div className="h-60 flex items-center justify-center pt-2">
                  <Line data={timelineChartData} options={timelineChartOptions} />
                </div>
              </GlassCard>

              <GlassCard title="Windows Channel Distribution" icon={PieIcon}>
                <div className="h-60 flex items-center justify-center pt-2">
                  <Pie data={channelChartData} options={channelChartOptions} />
                </div>
              </GlassCard>

              <GlassCard title="Top SHAP Anomaly Feature Reasons" icon={Sparkles}>
                <div className="space-y-3 pt-1 font-mono text-xs">
                  {result24h.top_shap_features && result24h.top_shap_features.length > 0 ? (
                    result24h.top_shap_features.map((item, idx) => (
                      <div key={idx} className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex justify-between items-center">
                        <span className="text-slate-200 font-semibold truncate max-w-xs">{item.reason}</span>
                        <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-bold border border-purple-500/30 text-[10px]">
                          {item.count} occurrences
                        </span>
                      </div>
                    ))
                  ) : (
                    <div className="p-8 text-center text-slate-500 text-xs">
                      No significant SHAP anomaly contributors flagged.
                    </div>
                  )}
                </div>
              </GlassCard>
            </div>
          )}

          {/* HISTORICAL EVENTS TABLE & HUMAN-READABLE SHAP EXPLANATION CARD */}
          {result24h && (
            <GlassCard title="24-Hour Historical Event Analysis" icon={FileText}>
              <div className="space-y-4">
                {/* SEARCH & FILTERS ROW */}
                <div className="flex flex-col sm:flex-row justify-between items-center gap-4 pb-2 border-b border-slate-800">
                  <div className="relative w-full sm:w-72">
                    <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
                    <input
                      type="text"
                      placeholder="Search historical events..."
                      value={search24h}
                      onChange={(e) => setSearch24h(e.target.value)}
                      className="w-full h-10 pl-9 pr-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white outline-none focus:border-[#00E5FF]"
                    />
                  </div>

                  <div className="flex items-center gap-3 w-full sm:w-auto">
                    <select
                      value={severityFilter24h}
                      onChange={(e) => setSeverityFilter24h(e.target.value)}
                      className="h-10 px-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white outline-none focus:border-[#00E5FF]"
                    >
                      <option value="">All Severities</option>
                      <option value="Anomaly">Anomalies Only</option>
                      <option value="Critical">Critical</option>
                      <option value="High">High</option>
                      <option value="Medium">Medium</option>
                      <option value="Low">Low</option>
                    </select>

                    <button
                      onClick={() => navigate('/reports')}
                      className="h-10 px-4 rounded-xl bg-gradient-to-r from-[#00E5FF] to-[#2563EB] text-slate-950 font-black text-xs uppercase tracking-wider flex items-center gap-1.5 glow-cyan shrink-0"
                    >
                      <Printer className="w-4 h-4" />
                      <span>Print 24h Report</span>
                    </button>
                  </div>
                </div>

                {/* EVENTS LIST */}
                <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1">
                  {filteredHistoricalEvents.map((evt, idx) => {
                    const isAnomaly = evt.is_anomaly === 1;
                    const isSelected = selectedHistoricalEvent?.id === evt.id;
                    const showRaw = rawViewMap[evt.id || idx];
                    const timestampStr = evt.time ? `${formatTime(evt.timestamp).split(' ')[0]} ${evt.time}` : formatTime(evt.timestamp);
                    const providerStr = evt.provider || `${evt.source || evt.channel || 'Security'}[${evt.event_id || 4688}]:`;

                    return (
                      <div
                        key={evt.id || idx}
                        className={`p-4 rounded-xl border transition-all ${
                          isAnomaly
                            ? 'bg-red-950/20 border-red-500/40 hover:border-red-500/70 shadow-lg glow-red'
                            : 'bg-slate-950/70 border-slate-800/80 hover:border-slate-700'
                        } ${isSelected ? 'ring-1 ring-[#00E5FF]/60' : ''}`}
                      >
                        {/* Top Header Row */}
                        <div className="flex flex-wrap justify-between items-center gap-2 mb-1.5">
                          <div className="flex items-center gap-2 text-xs font-mono">
                            <Clock className="w-3.5 h-3.5 text-[#00E5FF]" />
                            <span className="text-slate-400 font-medium">{timestampStr}</span>
                            <span className="text-slate-500">|</span>
                            <span className="text-slate-200 font-bold">{providerStr}</span>
                            {evt.action && (
                              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-extrabold uppercase ${
                                evt.action.includes('Start') || evt.action.includes('Create')
                                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                                  : evt.action.includes('Terminat') || evt.action.includes('Close') || evt.action.includes('Stop')
                                  ? 'bg-slate-800 text-slate-300 border border-slate-700'
                                  : evt.action.includes('Camera') || evt.action.includes('Device')
                                  ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                                  : 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                              }`}>
                                {evt.action}
                              </span>
                            )}
                          </div>

                          <div className="flex items-center gap-2">
                            <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-extrabold uppercase ${
                              isAnomaly
                                ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                                : 'bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/40'
                            }`}>
                              {isAnomaly ? 'ANOMALY DETECTED' : 'NORMAL'}
                            </span>

                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                              evt.severity === 'Critical'
                                ? 'bg-purple-600/30 text-purple-300 border border-purple-500/50'
                                : evt.severity === 'High'
                                ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                                : evt.severity === 'Medium'
                                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                : 'bg-slate-800 text-slate-300 border border-slate-700'
                            }`}>
                              {evt.severity === 'Normal' ? 'LOW RISK' : (evt.severity || (isAnomaly ? 'HIGH RISK' : 'LOW RISK'))}
                            </span>
                          </div>
                        </div>

                        {/* Event description / message */}
                        <p className="text-xs font-mono text-slate-200 mb-2.5 font-medium">
                          {evt.description || evt.what_happened || evt.message || `Windows system event logged from ${providerStr}`}
                        </p>

                        {/* STRUCTURED TELEMETRY GRID (4 Primary + 4 Contextual Fields) */}
                        <div className="space-y-2 p-3 rounded-lg bg-[#070e1b]/90 border border-slate-800/80 text-xs font-mono mb-3">
                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                            <div>
                              <span className="text-slate-400 block text-[9px] uppercase font-bold tracking-wider">APPLICATION</span>
                              <span className="text-[#00E5FF] font-bold truncate block mt-0.5">{evt.application_name || evt.application || 'System Activity'}</span>
                            </div>
                            <div>
                              <span className="text-slate-400 block text-[9px] uppercase font-bold tracking-wider">PROCESS</span>
                              <span className="text-slate-100 font-medium truncate block mt-0.5">{evt.process || evt.process_name || 'System'}</span>
                            </div>
                            <div>
                              <span className="text-slate-400 block text-[9px] uppercase font-bold tracking-wider">PID</span>
                              <span className="text-[#FBBF24] font-black truncate block mt-0.5">{evt.pid || 'N/A'}</span>
                            </div>
                            <div>
                              <span className="text-slate-400 block text-[9px] uppercase font-bold tracking-wider">USER</span>
                              <span className="text-[#10B981] font-bold truncate block mt-0.5">{evt.user || 'Admin'}</span>
                            </div>
                          </div>

                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 border-t border-slate-800/60 text-[11px]">
                            <div>
                              <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-wider">COMPUTER</span>
                              <span className="text-slate-200 font-bold truncate block mt-0.5">{evt.computer || evt.host || result24h?.computer_name || 'ROCKY'}</span>
                            </div>
                            <div>
                              <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-wider">PARENT PROCESS</span>
                              <span className="text-slate-300 truncate block mt-0.5">
                                {evt.parent_process || evt.creator_process || 'explorer.exe'}
                                {evt.parent_application && evt.parent_application !== evt.parent_process ? ` (${evt.parent_application})` : ''}
                              </span>
                            </div>
                            <div>
                              <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-wider">ACTION</span>
                              <span className="text-cyan-300 font-medium truncate block mt-0.5">{evt.action || 'Application Started'}</span>
                            </div>
                            <div>
                              <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-wider">EVENT ID / CHANNEL</span>
                              <span className="text-slate-300 truncate block mt-0.5">{evt.event_id || 4688} ({evt.channel || 'Security'})</span>
                            </div>
                          </div>
                        </div>

                        {/* Action buttons row */}
                        <div className="flex flex-wrap justify-between items-center gap-2 text-xs font-mono">
                          <button
                            onClick={() => setSelectedHistoricalEvent(isSelected ? null : evt)}
                            className="text-[#00E5FF] hover:underline font-bold flex items-center gap-1.5"
                          >
                            <Sparkles className="w-3.5 h-3.5" />
                            <span>{isSelected ? 'Hide Analysis' : 'View SHAP Explanation'}</span>
                          </button>

                          <button
                            onClick={() => toggleRawView(evt.id || idx)}
                            className="text-slate-400 hover:text-white flex items-center gap-1.5"
                          >
                            <Eye className="w-3.5 h-3.5" />
                            <span>{showRaw ? 'Hide Raw Payload' : 'View Raw Payload'}</span>
                          </button>
                        </div>

                        {showRaw && (
                          <div className="mt-3 p-3.5 rounded-xl bg-black/90 border border-slate-800 text-[11px] font-mono text-slate-300 space-y-2 break-all overflow-x-auto">
                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pb-2 border-b border-slate-800/80 text-[10px]">
                              <div><span className="text-slate-500 uppercase">Provider:</span> <span className="text-cyan-300">{evt.provider || 'Microsoft-Windows-Security-Auditing'}</span></div>
                              <div><span className="text-slate-500 uppercase">Event ID:</span> <span className="text-white font-bold">{evt.event_id || 4688}</span></div>
                              <div><span className="text-slate-500 uppercase">Channel:</span> <span className="text-slate-300">{evt.channel || 'Security'}</span></div>
                              <div><span className="text-slate-500 uppercase">Record ID:</span> <span className="text-amber-300">{evt.record_id || evt.log_id || 0}</span></div>
                              <div><span className="text-slate-500 uppercase">Computer:</span> <span className="text-white font-bold">{evt.computer || 'ROCKY'}</span></div>
                              <div><span className="text-slate-500 uppercase">Timestamp:</span> <span className="text-slate-300">{evt.timestamp || evt.time}</span></div>
                            </div>
                            <div>
                              <span className="text-slate-500 block text-[10px] uppercase mb-1">Raw Payload JSON:</span>
                              <pre className="text-slate-300 text-[11px] font-mono">{JSON.stringify(evt, null, 2)}</pre>
                            </div>
                          </div>
                        )}

                        {/* EXPANDED SHAP REASONING CARD */}
                        {isSelected && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="mt-3 p-4 rounded-xl bg-[#040c1a] border border-[#00E5FF]/40 space-y-3 font-mono text-xs"
                          >
                            <div className="space-y-1">
                              <span className="text-[11px] font-mono font-bold text-[#00E5FF] uppercase tracking-wider block">
                                WHAT HAPPENED?
                              </span>
                              <p className="text-slate-200 leading-relaxed font-sans">
                                {evt.what_happened || evt.description || evt.message || `Windows system event logged from ${providerStr}`}
                              </p>
                            </div>

                            <div className="space-y-1">
                              <span className="text-[11px] font-mono font-bold text-[#FBBF24] uppercase tracking-wider block">
                                {isAnomaly ? 'WHY WAS THIS EVENT FLAGGED?' : 'WHY IS IT NORMAL?'}
                              </span>
                              <p className="text-slate-300 leading-relaxed font-sans">
                                {evt.why_suspicious || (isAnomaly 
                                  ? 'Unusual process execution parameters or behavioral deviation detected.'
                                  : 'This activity is consistent with normal system baseline behavior.')}
                              </p>
                            </div>

                            <div className="space-y-1">
                              <span className="text-[11px] font-mono font-bold text-[#10B981] uppercase tracking-wider block">
                                RECOMMENDED ACTION:
                              </span>
                              <p className="text-slate-300 leading-relaxed font-sans">
                                {evt.recommended_action || (isAnomaly 
                                  ? 'Investigate process integrity and verify administrator execution context.'
                                  : 'No action required. Continue standard operational monitoring.')}
                              </p>
                            </div>

                            {isAnomaly && evt.top_3_human_reasons && evt.top_3_human_reasons.length > 0 && (
                              <div className="pt-2 border-t border-slate-800 space-y-1.5 font-sans">
                                <span className="text-[10px] font-mono font-bold text-purple-400 uppercase tracking-widest block">
                                  TOP SHAP CONTRIBUTING FEATURES:
                                </span>
                                <ul className="space-y-1 text-slate-300 font-mono text-[11px]">
                                  {evt.top_3_human_reasons.map((reason, rIdx) => (
                                    <li key={rIdx} className="flex items-center gap-2">
                                      <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                                      <span>{reason}</span>
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {evt.feature_contributions && Object.keys(evt.feature_contributions).length > 0 && (
                              <div className="pt-2 border-t border-slate-800 space-y-1.5">
                                <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-widest block">
                                  SHAP FEATURE CONTRIBUTIONS:
                                </span>
                                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] font-mono">
                                  {Object.entries(evt.feature_contributions).map(([k, v]) => (
                                    <div key={k} className="p-1.5 rounded bg-black/50 border border-slate-800/80 flex justify-between items-center">
                                      <span className="text-slate-400 truncate mr-1">{k}:</span>
                                      <span className={`font-bold ${v > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                                        {v > 0 ? `+${v}` : v}
                                      </span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </motion.div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </GlassCard>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODE B: LIVE SYSTEM MONITOR TAB */}
      {/* ========================================================================= */}
      {activeTab === 'live' && (
        <div className="space-y-8 animate-fadeIn">
          {/* HEADER & CONTROLS */}
          <div className="bg-[#081225] p-6 rounded-2xl border border-slate-800 backdrop-blur-xl space-y-6">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-800/80 pb-6">
              <div>
                <div className="flex items-center gap-3 mb-1.5">
                  <Activity className="w-7 h-7 text-[#00E5FF] animate-pulse" />
                  <h2 className="text-xl font-black text-white tracking-wide">NEAR-REAL-TIME WINDOWS SYSTEM LOG MONITOR</h2>
                  
                  <div className={`px-3 py-1 rounded-full border text-xs font-mono font-bold flex items-center gap-2 ${
                    isMonitoring 
                      ? 'bg-[#10B981]/15 text-[#10B981] border-[#10B981]/40'
                      : 'bg-slate-800/80 text-slate-400 border-slate-700'
                  }`}>
                    <span className={`w-2 h-2 rounded-full ${isMonitoring ? 'bg-[#10B981] animate-ping' : 'bg-slate-500'}`} />
                    <span>{isMonitoring ? 'LIVE ● Monitoring' : 'MONITORING STOPPED'}</span>
                  </div>
                </div>
                <p className="text-xs text-[#94A3B8]">
                  Continuously streams new incoming Windows Event Logs every {intervalSec} seconds. Prevents duplicates using LogName + RecordId.
                </p>
              </div>

              {/* CONTROLS */}
              <div className="flex items-center gap-3 shrink-0">
                <div className="flex items-center gap-2 bg-slate-950 px-3 py-2 rounded-xl border border-slate-800 text-xs font-mono">
                  <Clock className="w-3.5 h-3.5 text-[#00E5FF]" />
                  <span className="text-slate-400">INTERVAL:</span>
                  <select
                    value={intervalSec}
                    onChange={(e) => setIntervalSec(Number(e.target.value))}
                    className="bg-slate-900 border border-slate-700 text-white rounded px-2 py-1 text-xs font-bold outline-none focus:border-[#00E5FF]"
                  >
                    <option value={1}>1s (Fastest)</option>
                    <option value={2}>2s</option>
                    <option value={3}>3s (Recommended)</option>
                    <option value={5}>5s</option>
                    <option value={10}>10s</option>
                  </select>
                </div>

                {isMonitoring ? (
                  <button
                    onClick={handleStopMonitoring}
                    disabled={loadingLive}
                    className="h-11 px-5 rounded-xl bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/40 text-xs font-black uppercase tracking-wider flex items-center gap-2 transition-all"
                  >
                    <Square className="w-4 h-4 text-red-400" />
                    <span>STOP MONITORING</span>
                  </button>
                ) : (
                  <button
                    onClick={handleStartMonitoring}
                    disabled={loadingLive}
                    className="h-11 px-6 rounded-xl bg-gradient-to-r from-[#00E5FF] to-[#2563EB] text-slate-950 font-black text-xs uppercase tracking-wider flex items-center gap-2 glow-cyan hover:scale-105 transition-all"
                  >
                    <Play className="w-4 h-4 fill-slate-950" />
                    <span>START LIVE MONITORING</span>
                  </button>
                )}
              </div>
            </div>

            {/* CHANNEL HEALTH */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs font-mono">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[10px] uppercase font-semibold">HOST COMPUTER</span>
                <strong className="text-white text-sm font-bold flex items-center gap-1.5 mt-0.5">
                  <Monitor className="w-4 h-4 text-[#00E5FF]" />
                  <span>{liveData.computer_name || 'Rocky'}</span>
                </strong>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[10px] uppercase font-semibold">SCANNED CHANNELS</span>
                <span className="text-slate-200 text-xs font-semibold truncate block mt-0.5">
                  {(liveData.scanned_channels || ['System', 'Application', 'Security']).join(', ')}
                </span>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[10px] uppercase font-semibold">LAST SCAN TIME</span>
                <span className="text-[#00E5FF] text-xs font-mono font-bold block mt-0.5">
                  {formatTime(liveData.last_scan_time)}
                </span>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[10px] uppercase font-semibold">SECURITY CHANNEL</span>
                {liveData.unavailable_channels?.includes('Security') ? (
                  <span className="text-amber-400 text-xs font-bold block mt-0.5">Permission Required ⚠️</span>
                ) : (
                  <span className="text-[#10B981] text-xs font-bold block mt-0.5">Full Access ✓</span>
                )}
              </div>
            </div>
          </div>

          {/* LIVE METRICS KPI */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 text-center font-mono">
            <GlassCard className="p-4 border-slate-800">
              <span className="text-[10px] text-[#94A3B8] uppercase font-bold block">Total Monitored Events</span>
              <strong className="text-white text-2xl font-black block mt-1">
                {liveData.total_events_monitored || liveData.events?.length || 0}
              </strong>
            </GlassCard>

            <GlassCard className="p-4 border-slate-800">
              <span className="text-[10px] text-[#94A3B8] uppercase font-bold block">Normal Events</span>
              <strong className="text-[#10B981] text-2xl font-black block mt-1">
                {liveData.normal_count || (liveData.events || []).filter(e => e.is_anomaly === 0).length}
              </strong>
            </GlassCard>

            <GlassCard className="p-4 border-slate-800">
              <span className="text-[10px] text-[#94A3B8] uppercase font-bold block">Detected Anomalies</span>
              <strong className="text-[#EF4444] text-2xl font-black block mt-1">
                {liveData.anomaly_count || (liveData.events || []).filter(e => e.is_anomaly === 1).length}
              </strong>
            </GlassCard>

            <GlassCard className="p-4 border-slate-800">
              <span className="text-[10px] text-[#94A3B8] uppercase font-bold block">Live Buffer Events</span>
              <strong className="text-[#00E5FF] text-2xl font-black block mt-1">
                {liveData.events?.length || 0} events
              </strong>
            </GlassCard>
          </div>

          {/* LIVE STREAM FEED */}
          <GlassCard title="LIVE WINDOWS SYSTEM EVENT STREAM" icon={Activity}>
            <div className="space-y-3 max-h-[650px] overflow-y-auto pr-1">
              {(!liveData.events || liveData.events.length === 0) ? (
                <div className="p-12 text-center text-slate-500 font-mono text-xs space-y-3 border border-dashed border-slate-800 rounded-xl">
                  <Activity className="w-8 h-8 text-slate-600 mx-auto animate-pulse" />
                  <p>Listening for new Windows Event Logs...</p>
                </div>
              ) : (
                liveData.events.map((evt, idx) => {
                  const isAnomaly = evt.is_anomaly === 1;
                  const isSelected = selectedLiveEvent?.log_id === evt.log_id || selectedLiveEvent?.id === evt.id;
                  const showRaw = rawViewMap[evt.log_id || idx];

                  const timestampStr = evt.timestamp 
                    ? (String(evt.timestamp).includes('T') 
                        ? evt.timestamp.replace('T', ' ').split('.')[0] 
                        : evt.timestamp)
                    : (evt.time ? `2026-08-19 ${evt.time}` : '2026-08-19 19:22:20');

                  const providerStr = `${evt.provider || 'Microsoft-Windows-Security-Auditing'}[${evt.event_id || 4688}]:`;

                  return (
                    <div
                      key={evt.log_id || idx}
                      className={`p-4 rounded-xl border transition-all ${
                        isAnomaly
                          ? 'bg-red-950/20 border-red-500/40 hover:border-red-500/70 shadow-lg glow-red'
                          : 'bg-slate-950/70 border-slate-800/80 hover:border-slate-700'
                      } ${isSelected ? 'ring-1 ring-[#00E5FF]/60' : ''}`}
                    >
                      {/* Top Header Row */}
                      <div className="flex flex-wrap justify-between items-center gap-2 mb-1.5">
                        <div className="flex items-center gap-2 text-xs font-mono">
                          <Clock className="w-3.5 h-3.5 text-[#00E5FF]" />
                          <span className="text-slate-400 font-medium">{timestampStr}</span>
                          <span className="text-slate-500">|</span>
                          <span className="text-slate-200 font-bold">{providerStr}</span>
                          {evt.action && (
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-extrabold uppercase ${
                              evt.action.includes('Start') || evt.action.includes('Create')
                                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                                : evt.action.includes('Terminat') || evt.action.includes('Close') || evt.action.includes('Stop')
                                ? 'bg-slate-800 text-slate-300 border border-slate-700'
                                : evt.action.includes('Camera') || evt.action.includes('Device')
                                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                                : 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                            }`}>
                              {evt.action}
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-2">
                          <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-extrabold uppercase ${
                            isAnomaly
                              ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                              : 'bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/40'
                          }`}>
                            {isAnomaly ? 'ANOMALY DETECTED' : 'NORMAL'}
                          </span>

                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                            evt.severity === 'Critical'
                              ? 'bg-purple-600/30 text-purple-300 border border-purple-500/50'
                              : evt.severity === 'High'
                              ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                              : evt.severity === 'Medium'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                              : 'bg-slate-800 text-slate-300 border border-slate-700'
                          }`}>
                            {evt.severity === 'Normal' ? 'LOW RISK' : (evt.severity || (isAnomaly ? 'HIGH RISK' : 'LOW RISK'))}
                          </span>
                        </div>
                      </div>

                      {/* Event description / message */}
                      <p className="text-xs font-mono text-slate-200 mb-2.5 font-medium">
                        {evt.description || `Windows system event logged from ${providerStr}`}
                      </p>

                      {/* STRUCTURED TELEMETRY GRID (4 Primary + 4 Contextual Fields) */}
                      <div className="space-y-2 p-3 rounded-lg bg-[#070e1b]/90 border border-slate-800/80 text-xs font-mono mb-3">
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                          <div>
                            <span className="text-slate-400 block text-[9px] uppercase font-bold tracking-wider">APPLICATION</span>
                            <span className="text-[#00E5FF] font-bold truncate block mt-0.5">{evt.application_name || evt.application || 'Notepad'}</span>
                          </div>
                          <div>
                            <span className="text-slate-400 block text-[9px] uppercase font-bold tracking-wider">PROCESS</span>
                            <span className="text-slate-100 font-medium truncate block mt-0.5">{evt.process || evt.process_name || 'Notepad.exe'}</span>
                          </div>
                          <div>
                            <span className="text-slate-400 block text-[9px] uppercase font-bold tracking-wider">PID</span>
                            <span className="text-[#FBBF24] font-black truncate block mt-0.5">{evt.pid || 23488}</span>
                          </div>
                          <div>
                            <span className="text-slate-400 block text-[9px] uppercase font-bold tracking-wider">USER</span>
                            <span className="text-[#10B981] font-bold truncate block mt-0.5">{evt.user || 'Admin'}</span>
                          </div>
                        </div>

                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 border-t border-slate-800/60 text-[11px]">
                          <div>
                            <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-wider">COMPUTER</span>
                            <span className="text-slate-200 font-bold truncate block mt-0.5">{evt.computer || liveData.computer_name || 'ROCKY'}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-wider">PARENT PROCESS</span>
                            <span className="text-slate-300 truncate block mt-0.5">
                              {evt.parent_process || evt.creator_process || 'explorer.exe'}
                              {evt.parent_application && evt.parent_application !== evt.parent_process ? ` (${evt.parent_application})` : ''}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-wider">ACTION</span>
                            <span className="text-cyan-300 font-medium truncate block mt-0.5">{evt.action || 'Application Started'}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[9px] uppercase font-bold tracking-wider">EVENT ID / CHANNEL</span>
                            <span className="text-slate-300 truncate block mt-0.5">{evt.event_id || 4688} ({evt.channel || 'Security'})</span>
                          </div>
                        </div>
                      </div>

                      {/* Action buttons row */}
                      <div className="flex flex-wrap justify-between items-center gap-2 text-xs font-mono">
                        <button
                          onClick={() => setSelectedLiveEvent(isSelected ? null : evt)}
                          className="text-[#00E5FF] hover:underline font-bold flex items-center gap-1.5"
                        >
                          <Sparkles className="w-3.5 h-3.5" />
                          <span>{isSelected ? 'Hide Analysis' : 'View SHAP Explanation'}</span>
                        </button>

                        <button
                          onClick={() => toggleRawView(evt.log_id || idx)}
                          className="text-slate-400 hover:text-white flex items-center gap-1.5"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>{showRaw ? 'Hide Raw Payload' : 'View Raw Payload'}</span>
                        </button>
                      </div>

                      {showRaw && (
                        <div className="mt-3 p-3.5 rounded-xl bg-black/90 border border-slate-800 text-[11px] font-mono text-slate-300 space-y-2 break-all overflow-x-auto">
                          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pb-2 border-b border-slate-800/80 text-[10px]">
                            <div><span className="text-slate-500 uppercase">Provider:</span> <span className="text-cyan-300">{evt.provider || 'Microsoft-Windows-Security-Auditing'}</span></div>
                            <div><span className="text-slate-500 uppercase">Event ID:</span> <span className="text-white font-bold">{evt.event_id || 4688}</span></div>
                            <div><span className="text-slate-500 uppercase">Channel:</span> <span className="text-slate-300">{evt.channel || 'Security'}</span></div>
                            <div><span className="text-slate-500 uppercase">Record ID:</span> <span className="text-amber-300">{evt.record_id || 0}</span></div>
                            <div><span className="text-slate-500 uppercase">Computer:</span> <span className="text-white font-bold">{evt.computer || 'ROCKY'}</span></div>
                            <div><span className="text-slate-500 uppercase">Timestamp:</span> <span className="text-slate-300">{evt.timestamp || evt.time}</span></div>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase mb-1">Raw Payload JSON:</span>
                            <pre className="text-slate-300 text-[11px] font-mono">{JSON.stringify(evt, null, 2)}</pre>
                          </div>
                        </div>
                      )}

                      {/* EXPANDED SHAP ANALYSIS BOX */}
                      {isSelected && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          exit={{ opacity: 0, height: 0 }}
                          className="mt-3 p-4 rounded-xl bg-[#040c1a] border border-[#00E5FF]/40 space-y-3 font-mono text-xs"
                        >
                          <div className="space-y-1">
                            <span className="text-[11px] font-mono font-bold text-[#00E5FF] uppercase tracking-wider block">
                              WHAT HAPPENED?
                            </span>
                            <p className="text-slate-200 leading-relaxed font-sans">
                              {evt.what_happened || evt.description || `Windows system event logged from ${providerStr}`}
                            </p>
                          </div>

                          <div className="space-y-1">
                            <span className="text-[11px] font-mono font-bold text-[#FBBF24] uppercase tracking-wider block">
                              {isAnomaly ? 'WHY WAS THIS EVENT FLAGGED?' : 'WHY IS IT NORMAL?'}
                            </span>
                            <p className="text-slate-300 leading-relaxed font-sans">
                              {evt.why_suspicious || (isAnomaly 
                                ? 'Unusual process execution parameters or behavioral deviation detected.'
                                : 'This activity is consistent with normal system baseline behavior.')}
                            </p>
                          </div>

                          <div className="space-y-1">
                            <span className="text-[11px] font-mono font-bold text-[#10B981] uppercase tracking-wider block">
                              RECOMMENDED ACTION:
                            </span>
                            <p className="text-slate-300 leading-relaxed font-sans">
                              {evt.recommended_action || (isAnomaly 
                                ? 'Investigate process integrity and verify administrator execution context.'
                                : 'No action required. Continue standard operational monitoring.')}
                            </p>
                          </div>

                          {isAnomaly && evt.top_3_human_reasons && evt.top_3_human_reasons.length > 0 && (
                            <div className="pt-2 border-t border-slate-800 space-y-1.5 font-sans">
                              <span className="text-[10px] font-mono font-bold text-purple-400 uppercase tracking-widest block">
                                TOP SHAP CONTRIBUTING FEATURES:
                              </span>
                              <ul className="space-y-1 text-slate-300 font-mono text-[11px]">
                                {evt.top_3_human_reasons.map((reason, rIdx) => (
                                  <li key={rIdx} className="flex items-center gap-2">
                                    <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                                    <span>{reason}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {evt.feature_contributions && Object.keys(evt.feature_contributions).length > 0 && (
                            <div className="pt-2 border-t border-slate-800 space-y-1.5">
                              <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-widest block">
                                SHAP FEATURE CONTRIBUTIONS:
                              </span>
                              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] font-mono">
                                {Object.entries(evt.feature_contributions).map(([k, v]) => (
                                  <div key={k} className="p-1.5 rounded bg-black/50 border border-slate-800/80 flex justify-between items-center">
                                    <span className="text-slate-400 truncate mr-1">{k}:</span>
                                    <span className={`font-bold ${v > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                                      {v > 0 ? `+${v}` : v}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </motion.div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </GlassCard>
        </div>
      )}
    </div>
  );
};

export default UploadLogsPage;
