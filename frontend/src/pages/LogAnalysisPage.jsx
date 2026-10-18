import React, { useState, useEffect } from 'react';
import { Search, Filter, FileText, ChevronLeft, ChevronRight, Eye, X } from 'lucide-react';
import GlassCard from '../components/ui/GlassCard';
import { fetchParsedLogs } from '../services/api';

const LogAnalysisPage = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [levelFilter, setLevelFilter] = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedLog, setSelectedLog] = useState(null);
  const itemsPerPage = 10;

  useEffect(() => {
    loadLogs();
  }, []);

  const loadLogs = async () => {
    try {
      const data = await fetchParsedLogs();
      setLogs(data);
    } catch (err) {
      console.error('Error fetching parsed logs:', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredLogs = logs.filter((log) => {
    const matchesSearch = 
      log.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.service.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.hostname.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesLevel = levelFilter === 'ALL' || log.log_level.toUpperCase() === levelFilter.toUpperCase();
    return matchesSearch && matchesLevel;
  });

  const totalPages = Math.ceil(filteredLogs.length / itemsPerPage) || 1;
  const currentLogs = filteredLogs.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  return (
    <div className="container-soc pt-28 pb-16 space-y-8">
      <div className="bg-[#081225] p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-black text-white flex items-center gap-2.5">
            <FileText className="w-5 h-5 text-[#00E5FF]" /> Syslog Records Explorer
          </h1>
          <p className="text-xs text-[#94A3B8] mt-1">Multi-attribute search, level filtering, and raw log message inspection console.</p>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <GlassCard className="p-5">
        <div className="flex flex-col sm:flex-row items-center gap-4">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5" />
            <input
              type="text"
              placeholder="Search message, service (sshd, kernel), or hostname..."
              value={searchTerm}
              onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-900 border border-slate-800 text-xs text-white focus:border-[#00E5FF] focus:outline-none transition-all font-mono"
            />
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <Filter className="w-4 h-4 text-[#00E5FF]" />
            <select
              value={levelFilter}
              onChange={(e) => { setLevelFilter(e.target.value); setCurrentPage(1); }}
              className="px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-800 text-xs text-[#00E5FF] font-mono focus:border-[#00E5FF] focus:outline-none w-full sm:w-auto"
            >
              <option value="ALL">All Severity Levels</option>
              <option value="INFO">INFO</option>
              <option value="WARNING">WARNING</option>
              <option value="ERROR">ERROR</option>
            </select>
          </div>
        </div>
      </GlassCard>

      {/* Log Explorer Table */}
      <GlassCard title={`Parsed Log Stream (${filteredLogs.length} Records)`} icon={FileText}>
        {loading ? (
          <div className="py-12 text-center text-[#00E5FF] font-mono text-xs">Parsing syslog stream dataset...</div>
        ) : logs.length === 0 ? (
          <div className="py-12 text-center text-[#94A3B8] font-mono text-xs">No analysis data available. Please analyze system logs first.</div>
        ) : (
          <div className="space-y-4">

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-[#050816] text-[#94A3B8] uppercase text-[10px] font-mono border-b border-slate-800">
                  <tr>
                    <th className="p-3.5">Log ID</th>
                    <th className="p-3.5">Timestamp</th>
                    <th className="p-3.5">Hostname</th>
                    <th className="p-3.5">Service</th>
                    <th className="p-3.5">Log Level</th>
                    <th className="p-3.5">Message Snippet</th>
                    <th className="p-3.5 text-center">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {currentLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="p-3.5 text-[#00E5FF] font-bold">#{log.id}</td>
                      <td className="p-3.5 text-slate-400">{log.timestamp}</td>
                      <td className="p-3.5 text-white font-semibold">{log.hostname}</td>
                      <td className="p-3.5 text-purple-400">{log.service}</td>
                      <td className="p-3.5">
                        <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                          log.log_level.toUpperCase() === 'ERROR' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                          log.log_level.toUpperCase() === 'WARNING' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                          'bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/30'
                        }`}>
                          {log.log_level}
                        </span>
                      </td>
                      <td className="p-3.5 text-slate-300 max-w-xs truncate">{log.message}</td>
                      <td className="p-3.5 text-center">
                        <button
                          onClick={() => setSelectedLog(log)}
                          className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-[#00E5FF] transition-all"
                          title="View Details"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div className="flex justify-between items-center pt-2 text-xs font-mono text-[#94A3B8]">
              <span>Page {currentPage} of {totalPages}</span>
              <div className="flex gap-2">
                <button
                  disabled={currentPage === 1}
                  onClick={() => setCurrentPage(currentPage - 1)}
                  className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 disabled:opacity-40"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <button
                  disabled={currentPage === totalPages}
                  onClick={() => setCurrentPage(currentPage + 1)}
                  className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 disabled:opacity-40"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        )}
      </GlassCard>

      {/* Detail Inspection Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
          <GlassCard className="max-w-xl w-full p-6 border-[#00E5FF]/40 glow-cyan relative space-y-4">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white font-mono">Log Record Details #{selectedLog.id}</h3>
              <button onClick={() => setSelectedLog(null)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div><span className="text-[#94A3B8]">Timestamp:</span> <strong className="text-white">{selectedLog.timestamp}</strong></div>
              <div><span className="text-[#94A3B8]">Hostname:</span> <strong className="text-white">{selectedLog.hostname}</strong></div>
              <div><span className="text-[#94A3B8]">Service Daemon:</span> <strong className="text-purple-400">{selectedLog.service}</strong></div>
              <div><span className="text-[#94A3B8]">Log Severity Level:</span> <strong className="text-[#00E5FF]">{selectedLog.log_level}</strong></div>
              <div className="pt-2">
                <span className="text-[#94A3B8] block mb-1">Full Log Payload Message:</span>
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 font-mono text-[11px] leading-relaxed break-words">
                  {selectedLog.message}
                </div>
              </div>
            </div>
          </GlassCard>
        </div>
      )}
    </div>
  );
};

export default LogAnalysisPage;
