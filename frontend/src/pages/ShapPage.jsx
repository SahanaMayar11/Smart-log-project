import React, { useState, useEffect } from 'react';
import { Sparkles, MessageSquare, Activity, BarChart2, Info, ArrowUpRight, ArrowDownRight, Lightbulb, HelpCircle, ShieldAlert } from 'lucide-react';
import GlassCard from '../components/ui/GlassCard';
import { fetchShapExplanations } from '../services/api';

// Chart.js
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
  Legend
} from 'chart.js';
import { Bar } from 'react-chartjs-2';

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

const FEATURE_NAME_HUMAN = {
  'Event Frequency': 'Log Velocity / Burst Rate',
  'Sequence Length': 'Message Complexity & Detail',
  'Error Count': 'Operational Error Volume',
  'Error Pattern': 'Security Denial Pattern',
  'Login Attempts': 'Logon Activity Volume',
  'Failed Login Attempts': 'Repeated Authentication Failures',
  'Warning Count': 'Cautionary System Warnings',
  'Unknown Events': 'Uncommon System Signatures',
  'event_frequency': 'Log Velocity / Burst Rate',
  'sequence_length': 'Message Complexity & Detail',
  'error_count': 'Operational Error Volume',
  'error_pattern': 'Security Denial Pattern',
  'login_attempts': 'Logon Activity Volume',
  'failed_login_attempts': 'Repeated Authentication Failures',
  'warning_count': 'Cautionary System Warnings',
  'unknown_events': 'Uncommon System Signatures',
};

const formatFactorText = (reasonText) => {
  if (!reasonText) return '';
  return reasonText
    .replace(/\(SHAP contribution:\s*[+-]?\d+\.?\d*\)/gi, '')
    .replace(/\s+/g, ' ')
    .trim();
};

const ShapPage = () => {
  const [explanations, setExplanations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAnomaly, setSelectedAnomaly] = useState(null);

  useEffect(() => {
    loadShap();
  }, []);

  const loadShap = async () => {
    try {
      const data = await fetchShapExplanations();
      setExplanations(data);
      const firstAnomaly = data.find((d) => d.is_anomaly === 1) || data[0];
      setSelectedAnomaly(firstAnomaly);
    } catch (err) {
      console.error('Error fetching SHAP explanations:', err);
    } finally {
      setLoading(false);
    }
  };

  const aggregateFeatureImportance = () => {
    const totals = {};
    explanations.forEach((item) => {
      const contribs = item.feature_contributions || {};
      Object.keys(contribs).forEach((feat) => {
        const humanName = FEATURE_NAME_HUMAN[feat] || feat;
        totals[humanName] = (totals[humanName] || 0) + Math.abs(contribs[feat]);
      });
    });
    return totals;
  };

  const featureTotals = aggregateFeatureImportance();
  const summaryLabels = Object.keys(featureTotals);
  const summaryValues = Object.values(featureTotals);

  const summaryChartData = {
    labels: summaryLabels,
    datasets: [
      {
        label: 'Mean Absolute SHAP Value (Impact on Anomaly Score)',
        data: summaryValues,
        backgroundColor: 'rgba(0, 229, 255, 0.75)',
        borderColor: '#00E5FF',
        borderWidth: 1.5,
        borderRadius: 6,
      },
    ],
  };

  const waterfallContribs = selectedAnomaly?.feature_contributions || {};
  const waterfallLabels = Object.keys(waterfallContribs).map((f) => FEATURE_NAME_HUMAN[f] || f);
  const waterfallValues = Object.values(waterfallContribs);

  const waterfallChartData = {
    labels: waterfallLabels,
    datasets: [
      {
        label: `Behavioral Feature Impact for Event #${selectedAnomaly?.log_id || 0}`,
        data: waterfallValues,
        backgroundColor: waterfallValues.map((v) => (v >= 0 ? 'rgba(239, 68, 68, 0.75)' : 'rgba(16, 185, 129, 0.75)')),
        borderColor: waterfallValues.map((v) => (v >= 0 ? '#EF4444' : '#10B981')),
        borderWidth: 1.5,
        borderRadius: 4,
      },
    ],
  };

  const chartOptions = {
    indexAxis: 'y',
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: '#FFFFFF', font: { family: 'sans-serif', size: 12, weight: 'bold' } } },
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
      {/* HEADER */}
      <div className="bg-[#081225] p-6 rounded-2xl border border-[#00E5FF]/30 glass-panel flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <Sparkles className="w-6 h-6 text-[#00E5FF]" />
            <h1 className="text-2xl font-black text-white tracking-wide">SHAP Explainability & Threat Inspector</h1>
          </div>
          <p className="text-xs text-[#94A3B8]">
            SHAP (SHapley Additive exPlanations) translates ML mathematical features into human-readable security explanations.
          </p>

          <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono text-slate-300 mt-3">
            <span className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-purple-300">8 Behavioral Features</span>
            <span className="text-[#00E5FF]">→</span>
            <span className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-[#00E5FF] font-bold">SHAP Axiomatic Contributions</span>
            <span className="text-[#00E5FF]">→</span>
            <span className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-emerald-400 font-bold">Human-Readable Explanation & Action</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="px-3.5 py-2 rounded-xl bg-[#00E5FF]/10 border border-[#00E5FF]/30 text-[#00E5FF] text-xs font-mono glow-cyan font-semibold">
            SHAP Efficiency Axioms Active ✓
          </span>
        </div>
      </div>

      {/* EDUCATIONAL BANNER */}
      <GlassCard className="p-4 bg-[#00E5FF]/05 border-[#00E5FF]/30">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-[#00E5FF] shrink-0 mt-0.5" />
          <div className="text-xs text-slate-300 space-y-1">
            <p className="font-semibold text-white">How SHAP Translates Anomaly Features to Plain Language:</p>
            <p>
              Instead of displaying cryptic mathematical values (e.g. <span className="font-mono text-slate-400">failed_login_attempts = 12, SHAP = 0.42</span>), 
              Smart-Log translates SHAP feature outputs into clear human sentences (e.g. 
              <span className="text-[#00E5FF] font-semibold"> "Failed login attempts were unusually high and strongly contributed to the anomaly classification."</span>).
            </p>
          </div>
        </div>
      </GlassCard>

      {/* FEATURE IMPORTANCE CHARTS GRID */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <GlassCard title="SHAP Feature Importance (Global Impact Ranking)" icon={BarChart2}>
          <div className="h-72 p-2">
            <Bar data={summaryChartData} options={chartOptions} />
          </div>
        </GlassCard>

        <GlassCard
          title={`SHAP Feature Contributions for Event #${selectedAnomaly?.log_id || 0}`}
          icon={Activity}
          action={
            <select
              value={selectedAnomaly?.log_id || ''}
              onChange={(e) => {
                const found = explanations.find((item) => item.log_id === Number(e.target.value));
                if (found) setSelectedAnomaly(found);
              }}
              className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-700 text-xs text-[#00E5FF] font-mono focus:border-[#00E5FF] outline-none"
            >
              {explanations.map((exp) => (
                <option key={exp.log_id} value={exp.log_id}>
                  Event #{exp.log_id} ({exp.is_anomaly ? 'Anomaly' : 'Normal'})
                </option>
              ))}
            </select>
          }
        >
          <div className="h-72 p-2">
            <Bar data={waterfallChartData} options={chartOptions} />
          </div>
        </GlassCard>
      </div>

      {/* DETAILED HUMAN-READABLE SHAP EXPLANATION PANEL FOR SELECTED ANOMALY */}
      {selectedAnomaly && (
        <GlassCard title={`Event #${selectedAnomaly.log_id} — Human-Readable SHAP Security Analysis`} icon={ShieldAlert}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
            {/* LEFT COLUMN: WHAT HAPPENED & WHY SUSPICIOUS */}
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-400 block">WHAT HAPPENED</span>
                <p className="text-white font-sans text-xs font-semibold leading-relaxed">
                  "{selectedAnomaly.what_happened || selectedAnomaly.message}"
                </p>
              </div>

              {/* REQUIREMENT 9: WHY WAS THIS DETECTED AS AN ANOMALY */}
              <div className="p-4 rounded-xl bg-[#EF4444]/10 border border-[#EF4444]/30 space-y-2">
                <span className="text-[10px] uppercase font-bold text-[#EF4444] flex items-center gap-1.5">
                  <HelpCircle className="w-4 h-4 text-[#EF4444]" /> Why was this detected as an anomaly?
                </span>
                <p className="text-red-200 font-sans text-xs leading-relaxed">
                  {selectedAnomaly.why_suspicious || selectedAnomaly.natural_explanation}
                </p>

                {selectedAnomaly.top_3_human_reasons && selectedAnomaly.top_3_human_reasons.length > 0 && (
                  <div className="pt-2 border-t border-[#EF4444]/20 space-y-2 text-[11px] text-red-300 font-sans">
                    <strong className="text-xs text-white block">Top Contributing Behavioral Factors:</strong>
                    <div className="space-y-1.5">
                      {selectedAnomaly.top_3_human_reasons.map((r, idx) => {
                        const cleanR = formatFactorText(r);
                        const parts = cleanR.split(/ - | — /);
                        return (
                          <div key={idx} className="p-2 rounded bg-black/40 border border-red-500/20 text-xs font-mono">
                            <span className="text-slate-400 text-[10px] block uppercase font-bold">Factor #{idx + 1}</span>
                            <span className="text-white font-semibold block">{parts[0]}</span>
                            {parts[1] && <span className="text-red-300/80 block text-[11px] font-sans mt-0.5">{parts[1]}</span>}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* RIGHT COLUMN: RECOMMENDED ACTION & METADATA */}
            <div className="space-y-4">
              {/* REQUIREMENT 10: RECOMMENDED ACTION */}
              <div className="p-4 rounded-xl bg-[#10B981]/10 border border-[#10B981]/30 space-y-2">
                <span className="text-[10px] uppercase font-bold text-[#10B981] flex items-center gap-1.5">
                  <Lightbulb className="w-4 h-4 text-[#10B981]" /> Recommended Action
                </span>
                <p className="text-emerald-200 font-sans text-xs leading-relaxed">
                  "{selectedAnomaly.recommended_action || 'No action required. Continue standard operational monitoring.'}"
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-[11px]">
                <div className="flex justify-between items-center pb-2 border-b border-slate-800">
                  <span className="text-slate-400">Event Source / Provider:</span>
                  <strong className="text-purple-400">{selectedAnomaly.service}</strong>
                </div>
                <div className="flex justify-between items-center pb-2 border-b border-slate-800">
                  <span className="text-slate-400">Computer Name:</span>
                  <strong className="text-white">{selectedAnomaly.hostname || 'Rocky'}</strong>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Anomaly Decision Score:</span>
                  <strong className="text-[#00E5FF] font-bold">{selectedAnomaly.anomaly_score}</strong>
                </div>
              </div>
            </div>
          </div>
        </GlassCard>
      )}

      {/* HUMAN-READABLE SHAP EXPLANATION CARDS LIST */}
      <GlassCard title="Human-Readable Security Cards Feed" icon={MessageSquare}>
        {loading ? (
          <div className="py-12 text-center text-[#00E5FF] font-mono text-xs">Generating SHAP human-readable cards...</div>
        ) : explanations.length === 0 ? (
          <div className="py-12 text-center text-[#94A3B8] font-mono text-xs">No analysis data available. Please analyze system logs first.</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

            {explanations.map((item) => (
              <div
                key={item.log_id}
                onClick={() => setSelectedAnomaly(item)}
                className={`p-4 rounded-xl border transition-all cursor-pointer ${
                  selectedAnomaly && selectedAnomaly.log_id === item.log_id
                    ? 'border-[#00E5FF] bg-slate-900'
                    : item.is_anomaly === 1
                    ? 'bg-red-950/20 border-red-500/30 hover:border-red-500/50'
                    : 'bg-[#050816]/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex justify-between items-center mb-2">
                  <span className="text-xs font-mono font-bold text-[#00E5FF]">Event #{item.log_id}</span>
                  <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                    item.is_anomaly === 1 ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  }`}>
                    {item.is_anomaly === 1 ? 'Anomaly' : 'Normal'}
                  </span>
                </div>

                <p className="text-xs font-mono text-purple-400 mb-1">Provider: {item.service}</p>
                <p className="text-xs text-slate-200 leading-relaxed font-sans mb-3">{item.what_happened || item.natural_explanation}</p>

                <div className="pt-2 border-t border-slate-800/80 flex justify-between items-center text-[10px] text-[#94A3B8] font-mono">
                  <span>Top Behavioral Factor: <strong className="text-cyan-300">{FEATURE_NAME_HUMAN[item.top_reason] || item.top_reason}</strong></span>
                  <span>Score: {item.anomaly_score}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </GlassCard>
    </div>
  );
};

export default ShapPage;
