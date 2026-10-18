import React, { useState, useEffect } from 'react';
import { Cpu, Activity, Info, BarChart2 } from 'lucide-react';
import GlassCard from '../components/ui/GlassCard';
import { fetchExtractedFeatures } from '../services/api';

const BehavioralFeaturePage = () => {
  const [features, setFeatures] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadFeatures();
  }, []);

  const loadFeatures = async () => {
    try {
      const data = await fetchExtractedFeatures();
      setFeatures(data);
    } catch (err) {
      console.error('Error fetching behavioral features:', err);
    } finally {
      setLoading(false);
    }
  };


  const featureMetadata = [
    { name: 'Event Frequency', key: 'event_frequency', desc: 'Number of log messages generated within temporal window' },
    { name: 'Sequence Length', key: 'sequence_length', desc: 'Length of sequential event execution chain' },
    { name: 'Error Count', key: 'error_count', desc: 'Total error events recorded in log window' },
    { name: 'Error Pattern', key: 'error_pattern', desc: 'Repetitive error sequence occurrences indicating fault loops' },
    { name: 'Login Attempts', key: 'login_attempts', desc: 'Total user/system authentication requests' },
    { name: 'Failed Login Attempts', key: 'failed_login_attempts', desc: 'SSH brute-force & credential stuffing indicators' },
    { name: 'Warning Count', key: 'warning_count', desc: 'Cumulative warning level syslog events' },
    { name: 'Unknown Events', key: 'unknown_events', desc: 'Unclassified or rare syslog message formats' },
  ];

  return (
    <div className="container-soc pt-28 pb-16 space-y-8">
      <div className="bg-[#081225] p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-black text-white flex items-center gap-2.5">
            <Cpu className="w-5 h-5 text-[#00E5FF]" /> Behavioral Feature Vector Extraction
          </h1>
          <p className="text-xs text-[#94A3B8] mt-1">8 behavioral features extracted per temporal window to construct the Isolation Forest input matrix.</p>
        </div>
      </div>

      {/* Feature Cards Grid (4-Column Desktop Grid) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {featureMetadata.map((f, idx) => (
          <GlassCard key={f.key} className="p-5 border-slate-800 hover:border-[#00E5FF]/50 flex flex-col justify-between">
            <div>
              <div className="flex justify-between items-center mb-2">
                <span className="text-[10px] font-mono font-bold text-[#00E5FF]">FEATURE 0{idx + 1}</span>
                <span className="text-[10px] font-mono text-purple-400 font-semibold">{f.key}</span>
              </div>
              <h3 className="text-sm font-bold text-white mb-1.5">{f.name}</h3>
              <p className="text-xs text-[#94A3B8] leading-relaxed">{f.desc}</p>
            </div>
          </GlassCard>
        ))}
      </div>

      {/* Feature Matrix Output Table */}
      <GlassCard title="Extracted 8-Dimensional Behavioral Feature Matrix" icon={BarChart2}>
        {loading ? (
          <div className="py-12 text-center text-[#00E5FF] font-mono text-xs">Extracting feature vectors from syslog stream...</div>
        ) : features.length === 0 ? (
          <div className="py-12 text-center text-[#94A3B8] font-mono text-xs">No analysis data available. Please analyze system logs first.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-[#050816] text-[#94A3B8] uppercase text-[10px] font-mono border-b border-slate-800">
                <tr>
                  <th className="p-3.5">Log ID</th>
                  <th className="p-3.5">Freq</th>
                  <th className="p-3.5">Seq Len</th>
                  <th className="p-3.5">Errors</th>
                  <th className="p-3.5">Err Pat</th>
                  <th className="p-3.5">Logins</th>
                  <th className="p-3.5">Failed Logins</th>
                  <th className="p-3.5">Warnings</th>
                  <th className="p-3.5">Unknown</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {features.map((row) => (
                  <tr key={row.id || row.log_id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="p-3.5 text-[#00E5FF] font-bold">#{row.log_id}</td>
                    <td className="p-3.5 font-bold text-white">{row.event_frequency}</td>
                    <td className="p-3.5 text-slate-300">{row.sequence_length}</td>
                    <td className="p-3.5 text-red-400 font-bold">{row.error_count}</td>
                    <td className="p-3.5 text-purple-400">{row.error_pattern}</td>
                    <td className="p-3.5 text-slate-300">{row.login_attempts}</td>
                    <td className="p-3.5 text-red-400 font-bold">{row.failed_login_attempts ?? 0}</td>
                    <td className="p-3.5 text-amber-400">{row.warning_count}</td>
                    <td className="p-3.5 text-slate-400">{row.unknown_events}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </GlassCard>

    </div>
  );
};

export default BehavioralFeaturePage;
