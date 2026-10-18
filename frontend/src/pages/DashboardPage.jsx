import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  FileText, 
  CheckCircle, 
  AlertTriangle, 
  FileCheck, 
  Activity, 
  Clock,
  Server,
  RefreshCw,
  Info
} from 'lucide-react';
import GlassCard from '../components/ui/GlassCard';
import StatCard from '../components/ui/StatCard';
import { fetchDashboardStats } from '../services/api';

// Chart.js imports
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

const DashboardPage = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStats();
    const timer = setInterval(() => {
      loadStats();
    }, 3000);
    return () => clearInterval(timer);
  }, []);

  const loadStats = async () => {
    try {
      const data = await fetchDashboardStats();
      setStats(data);
    } catch (err) {
      console.error('Error loading dashboard stats:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="container-soc pt-32 pb-16 min-h-[70vh] flex flex-col items-center justify-center text-[#00E5FF] font-mono space-y-3">
        <Activity className="w-8 h-8 animate-spin" />
        <span className="text-sm">Connecting to SOC Command Center...</span>
      </div>
    );
  }

  // Chart Data Setup
  const pieData = {
    labels: ['Normal Events', 'Anomaly Events'],
    datasets: [
      {
        data: [stats?.normal_logs || 0, stats?.anomaly_logs || 0],
        backgroundColor: ['rgba(16, 185, 129, 0.75)', 'rgba(239, 68, 68, 0.75)'],
        borderColor: ['#10B981', '#EF4444'],
        borderWidth: 1.5,
      },
    ],
  };

  const barLabels = Object.keys(stats?.bar_chart || {});
  const barValues = Object.values(stats?.bar_chart || {});

  const barData = {
    labels: barLabels.length ? barLabels : ['No Errors'],
    datasets: [
      {
        label: 'Error Count',
        data: barValues.length ? barValues : [0],
        backgroundColor: 'rgba(139, 92, 246, 0.75)',
        borderColor: '#8B5CF6',
        borderWidth: 1.5,
        borderRadius: 8,
      },
    ],
  };

  const timelineLabels = (stats?.timeline_chart || []).map((t) => `Event #${t.id}`);
  const timelineScores = (stats?.timeline_chart || []).map((t) => t.anomaly_score);

  const lineData = {
    labels: timelineLabels.length ? timelineLabels : ['0'],
    datasets: [
      {
        label: 'Anomaly Score Spectrum',
        data: timelineScores.length ? timelineScores : [0],
        borderColor: '#00E5FF',
        backgroundColor: 'rgba(0, 229, 255, 0.1)',
        tension: 0.35,
        fill: true,
        pointBackgroundColor: '#00E5FF',
        pointRadius: 4,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: '#FFFFFF', font: { family: 'sans-serif', size: 12, weight: 'bold' } }
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
      x: { ticks: { color: '#FFFFFF', font: { size: 11, weight: '600' } }, grid: { color: 'rgba(255, 255, 255, 0.10)' } },
      y: { ticks: { color: '#FFFFFF', font: { size: 11, weight: '600' } }, grid: { color: 'rgba(255, 255, 255, 0.10)' } }
    }
  };

  return (
    <div className="container-soc pt-28 pb-16 space-y-8">
      {/* Top Header Banner */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-[#081225] p-6 rounded-2xl border border-[#00E5FF]/30 glass-panel">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <Server className="w-5 h-5 text-[#00E5FF]" />
            <h1 className="text-2xl font-black text-white tracking-wide">SECURITY OPERATIONS CENTER</h1>
          </div>
          <p className="text-xs text-[#94A3B8]">Windows System Telemetry • Isolation Forest Model & SHAP Explainability Engine</p>
        </div>

        <div className="flex items-center gap-3">
          <button 
            onClick={loadStats} 
            className="p-2.5 rounded-xl bg-slate-900 text-slate-300 hover:text-[#00E5FF] transition-all border border-slate-800 flex items-center justify-center"
            title="Refresh Metrics"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <div className="flex items-center gap-2 text-xs font-mono text-[#00E5FF] bg-[#00E5FF]/10 px-4 py-2.5 rounded-xl border border-[#00E5FF]/30">
            <FileCheck className="w-4 h-4" />
            <span>Dataset: {stats?.latest_file || 'Windows_Event_Logs.log'}</span>
          </div>
        </div>
      </div>

      {/* REQUIREMENT 12: HUMAN-READABLE DASHBOARD SUMMARY HERO CARD */}
      <div className="p-5 rounded-2xl bg-gradient-to-r from-slate-950 via-[#081225] to-slate-950 border border-[#00E5FF]/40 shadow-xl flex items-start gap-4">
        <div className="p-3 rounded-xl bg-[#00E5FF]/10 text-[#00E5FF] border border-[#00E5FF]/30 shrink-0">
          <Info className="w-6 h-6" />
        </div>
        <div className="space-y-1">
          <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[#00E5FF]">
            HUMAN-READABLE EXECUTIVE SUMMARY
          </span>
          <p className="text-base font-bold text-white font-sans leading-relaxed">
            "{stats?.human_summary || `${stats?.total_logs || 0} system events analyzed. ${stats?.normal_logs || 0} events were normal. ${stats?.anomaly_logs || 0} suspicious events were detected.`}"
          </p>
          <p className="text-xs text-slate-400 font-mono">
            Analyzed using Isolation Forest algorithm and SHAP explainability model on local Windows OS logs.
          </p>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-5">
        <StatCard title="Total Events" value={stats?.total_logs || 0} subtext="Parsed system events" icon={FileText} color="cyan" />
        <StatCard title="Normal Events" value={stats?.normal_logs || 0} subtext="Baseline operational" icon={CheckCircle} color="emerald" />
        <StatCard title="Suspicious Events" value={stats?.anomaly_logs || 0} subtext="Isolation Forest flagged" icon={ShieldAlert} color="red" />
        <StatCard title="Recent Alerts" value={stats?.recent_alerts?.length || 0} subtext="SOC review required" icon={AlertTriangle} color="purple" />
        <StatCard title="Active Source" value={stats?.latest_file ? 'Windows OS' : 'None'} subtext="Log telemetry stream" icon={FileCheck} color="cyan" />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <GlassCard title="Event Distribution (Normal vs Anomaly)">
          <div className="h-72 relative flex items-center justify-center p-2">
            <Pie data={pieData} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#FFFFFF', font: { size: 12, weight: 'bold' } } } } }} />
          </div>
        </GlassCard>

        <GlassCard title="Top Error Categories Breakdown">
          <div className="h-72 p-2">
            <Bar data={barData} options={chartOptions} />
          </div>
        </GlassCard>

        <GlassCard title="Anomaly Score Spectrum Timeline" className="md:col-span-2 lg:col-span-1">
          <div className="h-72 p-2">
            <Line data={lineData} options={chartOptions} />
          </div>
        </GlassCard>
      </div>

      {/* Recent Security Alerts Table */}
      <GlassCard title="Recent Security Alerts & Human-Readable Explanations" icon={Clock}>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-[#050816] text-[#94A3B8] uppercase text-[10px] font-mono border-b border-slate-800">
              <tr>
                <th className="p-3.5">Log ID</th>
                <th className="p-3.5">Timestamp</th>
                <th className="p-3.5">Hostname</th>
                <th className="p-3.5">Service/Provider</th>
                <th className="p-3.5">Severity Tag</th>
                <th className="p-3.5">Score</th>
                <th className="p-3.5">Human-Readable Explanation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {stats?.recent_alerts?.length > 0 ? (
                stats.recent_alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="p-3.5 text-[#00E5FF] font-bold">#{alert.id}</td>
                    <td className="p-3.5 text-slate-400">{alert.timestamp}</td>
                    <td className="p-3.5 font-semibold text-white">{alert.hostname}</td>
                    <td className="p-3.5 text-[#8B5CF6] font-mono">{alert.service}</td>
                    <td className="p-3.5">
                      <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                        alert.severity === 'Anomaly' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                      }`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="p-3.5 font-mono text-red-400 font-bold">{alert.anomaly_score}</td>
                    <td className="p-3.5 text-slate-200 font-sans max-w-xs truncate">{alert.natural_explanation}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="7" className="p-6 text-center text-slate-500 font-mono">
                    No recent anomaly alerts detected in latest log stream.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </GlassCard>
    </div>
  );
};

export default DashboardPage;
