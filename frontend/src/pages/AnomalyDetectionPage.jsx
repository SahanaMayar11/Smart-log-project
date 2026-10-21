import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  Shield,
  Info,
  HelpCircle,
  Lightbulb,
  Search,
  Zap,
  Play,
  X,
  RefreshCw,
  Terminal,
  Activity,
  ShieldCheck,
  AlertOctagon,
  Trash2,
  Cpu,
  Layers,
  ChevronRight,
  Sparkles
} from 'lucide-react';
import GlassCard from '../components/ui/GlassCard';
import StatCard from '../components/ui/StatCard';
import {
  fetchDetectionResults,
  fetchAttackScenarios,
  injectAttackScenario,
  cleanTestData,
  pasteAndAnalyzeLog
} from '../services/api';

const DEFAULT_SCENARIOS = [
  {
    id: 'ssh_bruteforce',
    name: 'SSH Brute-Force Simulation',
    category: 'Authentication Anomaly',
    description: 'Simulates high-velocity unauthorized SSH authentication attempts across multiple non-existent accounts followed by invalid public key exchanges.',
    target_signals: ['failed_login_attempts', 'error_count', 'sequence_length', 'event_frequency'],
    expected_signals: 'failed_login_attempts: elevated; error_count: spike; event_frequency: high',
    security_recommendation: 'Deploy Fail2ban / SSHGuard to blacklist repeat offenders; enforce SSH key-only authentication; rate-limit port 22 connections with iptables/nftables.',
    model_compatibility: {
      ml_support: 'genuine_ml',
      notes: 'Directly mapped to HDFS domain error/frequency feature projections. Evaluated by Isolation Forest and One-Class SVM.'
    },
    sample_preview: `Oct 18 10:14:02 server sshd[4201]: Failed password for invalid user admin from 192.168.1.105 port 49201 ssh2
Oct 18 10:14:03 server sshd[4205]: Failed password for invalid user root from 192.168.1.105 port 49205 ssh2
Oct 18 10:14:04 server sshd[4209]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.105`
  },
  {
    id: 'buffer_overflow',
    name: 'Buffer Overflow / Oversized Payload',
    category: 'Memory Corruption / Exploit',
    description: 'Simulates memory corruption attempt where a daemon receives an abnormal payload with excessive byte count and segfaults.',
    target_signals: ['bytes_transferred', 'error_count', 'component_entropy'],
    expected_signals: 'bytes_transferred: extreme outlier; error_count: segfault spike',
    security_recommendation: 'Apply latest security patches to daemon; ensure ASLR and stack canaries are enabled; isolate daemon process in a restricted cgroup/container.',
    model_compatibility: {
      ml_support: 'genuine_ml',
      notes: 'Evaluated by ML pipeline. If bytes_transferred is normalized in baseline, high byte count creates strong anomaly divergence.'
    },
    sample_preview: `Oct 18 11:22:10 server app-daemon[5100]: Received oversized payload: 2847291 bytes on socket fd 8
Oct 18 11:22:10 server kernel: [81204.102] app-daemon[5100]: segfault at 00007ffe8290 ip 00007f90 sp 00007ffe8288 error 6 in libc.so
Oct 18 11:22:11 server systemd[1]: app-daemon.service: Main process exited, code=dumped, status=11/SEGV`
  },
  {
    id: 'privilege_escalation',
    name: 'Privilege Escalation / Access Denied',
    category: 'Authorization Violation',
    description: 'Simulates unauthorized user repeatedly attempting sudo / su commands with failed credential validation and /etc/shadow read denial.',
    target_signals: ['failed_login_attempts', 'error_count', 'unique_components'],
    expected_signals: 'failed_login_attempts: elevated; error_count: auth failure; unique_components: sudo/su deviation',
    security_recommendation: 'Audit sudoers configuration; restrict wheel/admin group membership; investigate compromised user credentials; enable pam_wheel or pam_faillock.',
    model_compatibility: {
      ml_support: 'genuine_ml',
      notes: 'Evaluated by ML models via error count, event frequency, and component deviations.'
    },
    sample_preview: `Oct 18 12:05:01 server sudo[6201]: user1 : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash
Oct 18 12:05:05 server su[6220]: FAILED SU (to root) user1 on pts/2
Oct 18 12:05:08 server kernel: [84210.332] audit: type=1400 audit(1729253108.012:991): apparmor="DENIED" operation="open" name="/etc/shadow"`
  },
  {
    id: 'directory_traversal',
    name: 'Sensitive File Access / Path Traversal',
    category: 'Filesystem / Path Traversal',
    description: 'Simulates web service / daemon path traversal attempt requesting sensitive system files (/etc/passwd, /etc/shadow) triggering forbidden access.',
    target_signals: ['error_count', 'event_frequency', 'component_entropy'],
    expected_signals: 'error_count: 403 Forbidden; component_entropy: multi-service traversal signature',
    security_recommendation: 'Harden web server root directory; enable AppArmor/SELinux mandatory access controls; validate and sanitize all input file paths.',
    model_compatibility: {
      ml_support: 'genuine_ml',
      notes: 'Features extracted and processed through ML pipeline. Rule-based path heuristic flags traversal patterns independently.'
    },
    sample_preview: `Oct 18 13:40:12 server nginx[7102]: 10.0.0.45 - - "GET /../../../../etc/passwd HTTP/1.1" 403 162 "-" "curl/7.68.0"
Oct 18 13:40:13 server nginx[7102]: 10.0.0.45 - - "GET /../../../../etc/shadow HTTP/1.1" 403 162 "-" "curl/7.68.0"
Oct 18 13:40:14 server nginx[7102]: 10.0.0.45 - - "GET /..%252f..%252f..%252fetc%252fpasswd HTTP/1.1" 400 166 "-"`
  },
  {
    id: 'dos_burst',
    name: 'Traffic Flood / DoS-Like Burst',
    category: 'Denial of Service / Volume',
    description: 'Simulates sudden high-volume syslog and socket flood causing rapid burst rate, connection dropouts, and service thread starvation.',
    target_signals: ['event_frequency', 'sequence_length', 'bytes_transferred', 'error_count'],
    expected_signals: 'event_frequency: extreme outlier (>10 msg/s); sequence_length: batch burst; error_count: connection dropouts',
    security_recommendation: 'Configure rate limiting with iptables hashlimit or Nginx limit_req; deploy SYN flood protection (syncookies); inspect upstream routing.',
    model_compatibility: {
      ml_support: 'genuine_ml',
      notes: 'Directly mapped to event_frequency and sequence_length features. High probability of Isolation Forest anomaly flag.'
    },
    sample_preview: `Oct 18 14:10:00 server rsyslogd[801]: message repeated 450 times: [ Connection accepted on port 443 ]
Oct 18 14:10:01 server kernel: [86100.12] TCP: possible SYN flooding on port 443. Sending cookies. Check SNMP counters.
Oct 18 14:10:02 server systemd[1]: nginx.service: Failed with result 'resources'. Service restart rate exceeded.`
  }
];

const AnomalyDetectionPage = () => {
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [statusFilter, setStatusFilter] = useState('all'); // 'all', 'anomalies', 'normal', 'simulated'
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  // Attack Simulator state
  const [simulatorOpen, setSimulatorOpen] = useState(false);
  const [scenarios, setScenarios] = useState(DEFAULT_SCENARIOS);
  const [selectedScenarioId, setSelectedScenarioId] = useState('ssh_bruteforce');
  const [injecting, setInjecting] = useState(false);
  const [simFeedback, setSimFeedback] = useState(null);
  const [selectedSimEventId, setSelectedSimEventId] = useState(null);
  const [simError, setSimError] = useState(null);
  const [isCleaning, setIsCleaning] = useState(false);

  // Paste Log state
  const [pastedLogInput, setPastedLogInput] = useState('');
  const [analyzingPastedLog, setAnalyzingPastedLog] = useState(false);
  const [pasteResult, setPasteResult] = useState(null);
  const [pasteError, setPasteError] = useState(null);

  const FEATURE_NAME_HUMAN = {
    'Event Frequency': 'Burst Velocity',
    'Sequence Length': 'Message Complexity',
    'Error Count': 'Operational Errors',
    'Error Pattern': 'Security Denial Pattern',
    'Login Attempts': 'Logon Volume',
    'Failed Login Attempts': 'Logon Failures',
    'Warning Count': 'Warning Alerts',
    'Unknown Events': 'Uncommon Signatures',
    'event_frequency': 'Burst Velocity',
    'sequence_length': 'Message Complexity',
    'error_count': 'Operational Errors',
    'error_pattern': 'Security Denial Pattern',
    'login_attempts': 'Logon Volume',
    'failed_login_attempts': 'Logon Failures',
    'warning_count': 'Warning Alerts',
    'unknown_events': 'Uncommon Signatures'
  };

  const formatFactorText = (reasonText) => {
    if (!reasonText) return '';
    return reasonText
      .replace(/\(SHAP contribution:\s*[+-]?\d+\.?\d*\)/gi, '')
      .replace(/\s+/g, ' ')
      .trim();
  };

  const SAMPLE_PRESETS = [
    {
      label: 'SSH Brute-Force',
      badge: 'Auth Attack',
      color: 'red',
      log: '2026-10-18T10:14:02 server-01 sshd[4201]: Failed password for invalid user admin from 192.168.1.105 port 49201 ssh2\n2026-10-18T10:14:03 server-01 sshd[4205]: Failed password for invalid user root from 192.168.1.105 port 49205 ssh2\n2026-10-18T10:14:04 server-01 sshd[4209]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.105'
    },
    {
      label: 'Privilege Escalation',
      badge: 'Privilege Abuse',
      color: 'amber',
      log: '2026-10-18T12:05:01 server-01 sudo[6201]: user1 : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash\n2026-10-18T12:05:05 server-01 su[6220]: FAILED SU (to root) user1 on pts/2\n2026-10-18T12:05:08 server-01 kernel[0]: [84210.332] audit: type=1400 audit: apparmor="DENIED" operation="open" profile="/usr/bin/python3" name="/etc/shadow" pid=6225 comm="python3" requested_mask="r" denied_mask="r"'
    },
    {
      label: 'Directory Traversal',
      badge: 'Web Exploit',
      color: 'purple',
      log: '2026-10-18T13:40:12 server-01 nginx[7102]: open() "/etc/shadow" failed (13: Permission denied), client: 198.51.100.99, request: "GET /../../../../etc/shadow HTTP/1.1"\n2026-10-18T13:40:13 server-01 nginx[7102]: open() "/etc/passwd" failed (13: Permission denied), client: 198.51.100.99, request: "GET /../../../../etc/passwd HTTP/1.1"'
    },
    {
      label: 'Buffer Overflow',
      badge: 'Memory Corruption',
      color: 'red',
      log: '2026-10-18T10:05:01 server-01 auth[2250]: UNKNOWN_EVENT: Buffer overflow attempt in authentication packet header from 198.51.100.80 payload_hex=0x9090909090909090eb1f5e89760831c088460789460c31bb895b08b00bcd8090909090\n2026-10-18T10:05:02 server-01 kernel[0]: [ 412.9812] traps: auth-daemon[2250] general protection fault ip:7f81a201 sp:7ffe312b error:0 in libc.so.6'
    },
    {
      label: 'Normal Baseline Log',
      badge: 'Routine Daemon',
      color: 'emerald',
      log: '2026-10-18T09:00:00 server-01 systemd[1]: Started Daily apt upgrade and clean activities.\n2026-10-18T09:00:01 server-01 CRON[1002]: (root) CMD (sysstat-collector --interval=60)'
    }
  ];

  const handleAnalyzePastedLog = async () => {
    if (!pastedLogInput || !pastedLogInput.trim()) {
      setPasteError('Please paste or type a log line into the box before analyzing.');
      return;
    }
    setAnalyzingPastedLog(true);
    setPasteError(null);
    setPasteResult(null);

    try {
      const res = await pasteAndAnalyzeLog(pastedLogInput.trim());
      if (res && (res.status === 'success' || res.success)) {
        setPasteResult(res);
        // Refresh the detection list and auto-select newly processed event
        await loadDetections(res.top_event?.id);
        if (res.top_event) {
          setSelectedEvent(res.top_event);
        }
      } else {
        setPasteError(res.message || 'Log analysis failed.');
      }
    } catch (err) {
      console.error('Error analyzing pasted log:', err);
      setPasteError('Server connection error during log analysis.');
    } finally {
      setAnalyzingPastedLog(false);
    }
  };

  useEffect(() => {
    loadDetections();
    loadScenarios();
  }, []);

  const loadDetections = async (autoSelectId = null) => {
    try {
      const data = await fetchDetectionResults();
      setResults(data || []);
      if (data && data.length > 0) {
        if (autoSelectId) {
          const match = data.find((r) => r.id === autoSelectId);
          setSelectedEvent(match || data[0]);
        } else if (!selectedEvent) {
          setSelectedEvent(data[0]);
        }
      }
    } catch (err) {
      console.error('Error fetching detection results:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadScenarios = async () => {
    try {
      const res = await fetchAttackScenarios();
      if (res && res.scenarios && res.scenarios.length > 0) {
        setScenarios(res.scenarios);
      }
    } catch (err) {
      console.warn('Could not fetch scenarios from backend, using defaults:', err);
    }
  };

  const handleInjectScenario = async (scenarioId) => {
    setInjecting(true);
    setSimError(null);
    setSimFeedback(null);

    try {
      const res = await injectAttackScenario(scenarioId);
      if (res && (res.status === 'success' || res.success)) {
        const simData = res.simulation || res;
        setSimFeedback(simData);

        // Refresh detections and auto-select injected event
        const firstInjectedId =
          simData.injected_results && simData.injected_results.length > 0
            ? simData.injected_results[0].id
            : null;

        setSelectedSimEventId(firstInjectedId);
        await loadDetections(firstInjectedId);
      } else {
        setSimError(res?.error || res?.message || 'Simulation injection failed');
      }
    } catch (err) {
      console.error('Injection error:', err);
      setSimError(err.message || 'Failed to communicate with injection backend');
    } finally {
      setInjecting(false);
    }
  };

  const handleCleanupSimulations = async () => {
    if (!window.confirm('Delete all simulated attack records from the database? Real ingested logs will not be affected.')) {
      return;
    }
    setIsCleaning(true);
    try {
      await cleanTestData();
      setSimFeedback(null);
      await loadDetections();
    } catch (err) {
      console.error('Cleanup error:', err);
      alert('Failed to cleanup simulation test data');
    } finally {
      setIsCleaning(false);
    }
  };

  const total = results.length;
  const anomalies = results.filter((r) => r.is_anomaly === 1).length;
  const normals = total - anomalies;
  const simulatedCount = results.filter((r) => r.is_simulated === 1).length;

  const getSeverityBadge = (score, isAnomaly, severity) => {
    if (!isAnomaly) {
      return { label: 'Normal', bg: 'bg-[#10B981]/20 text-[#10B981] border-[#10B981]/40' };
    }
    if (score > 0.85 || severity === 'Critical') {
      return { label: 'Critical', bg: 'bg-purple-600/30 text-purple-300 border-purple-500/50 glow-purple' };
    }
    if (score > 0.70 || severity === 'Anomaly' || severity === 'High') {
      return { label: 'High', bg: 'bg-[#EF4444]/20 text-[#EF4444] border-[#EF4444]/40 glow-red' };
    }
    if (score > 0.55 || severity === 'Warning' || severity === 'Medium') {
      return { label: 'Medium', bg: 'bg-amber-500/20 text-amber-400 border-amber-500/40' };
    }
    return { label: 'Low', bg: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40' };
  };

  const filteredResults = results.filter((r) => {
    // Status Filter
    if (statusFilter === 'anomalies' && r.is_anomaly !== 1) return false;
    if (statusFilter === 'normal' && r.is_anomaly !== 0) return false;
    if (statusFilter === 'simulated' && r.is_simulated !== 1) return false;

    // Severity Filter
    if (severityFilter) {
      const badge = getSeverityBadge(r.anomaly_score, r.is_anomaly === 1, r.severity);
      if (badge.label !== severityFilter && r.severity !== severityFilter) return false;
    }

    // Search Query
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const match =
        (r.service && r.service.toLowerCase().includes(q)) ||
        (r.hostname && r.hostname.toLowerCase().includes(q)) ||
        (r.what_happened && r.what_happened.toLowerCase().includes(q)) ||
        (r.message && r.message.toLowerCase().includes(q)) ||
        (r.description && r.description.toLowerCase().includes(q)) ||
        (r.process && r.process.toLowerCase().includes(q)) ||
        (r.timestamp && r.timestamp.toLowerCase().includes(q)) ||
        (r.simulation_scenario && r.simulation_scenario.toLowerCase().includes(q));
      if (!match) return false;
    }

    return true;
  });

  const activeScenario = scenarios.find((s) => s.id === selectedScenarioId) || scenarios[0];

  return (
    <div className="container-soc pt-28 pb-16 space-y-8">
      {/* HEADER WITH ATTACK SIMULATOR BUTTON */}
      <div className="bg-[#081225] p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <ShieldAlert className="w-6 h-6 text-[#EF4444]" />
            <h1 className="text-2xl font-black text-white tracking-tight">Threat Detection & Security Analysis</h1>
          </div>
          <p className="text-xs text-[#94A3B8] max-w-2xl">
            Unsupervised machine learning anomaly detection pipeline (Isolation Forest + One-Class SVM consensus) translated into natural-language SHAP explanations and practical security recommendations.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* ATTACK SIMULATOR TRIGGER BUTTON */}
          <button
            onClick={() => setSimulatorOpen(true)}
            className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-red-600 via-amber-600 to-amber-500 hover:from-red-500 hover:to-amber-400 text-white font-mono text-xs font-bold flex items-center gap-2 shadow-lg shadow-red-950/40 hover:shadow-red-500/25 transition-all transform hover:-translate-y-0.5 cursor-pointer"
          >
            <Zap className="w-4 h-4 text-yellow-300 animate-pulse" />
            Attack Simulator
          </button>

          {/* REFRESH BUTTON */}
          <button
            onClick={() => loadDetections()}
            disabled={loading}
            className="px-3 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300 flex items-center gap-1.5 transition-all"
            title="Refresh Detection Stream"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-[#00E5FF]' : ''}`} />
            Refresh
          </button>

          {/* CLEANUP BUTTON (if simulated records exist) */}
          {simulatedCount > 0 && (
            <button
              onClick={handleCleanupSimulations}
              disabled={isCleaning}
              className="px-3 py-2.5 rounded-xl bg-slate-900 hover:bg-red-950/40 border border-red-500/30 text-xs font-mono text-red-400 hover:text-red-300 flex items-center gap-1.5 transition-all"
              title="Remove simulated test records from database"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear Tests
            </button>
          )}
        </div>
      </div>

      {/* PASTE LOG & LIVE ANOMALY INSPECTION PANEL (Replaces static KPI cards) */}
      <div className="bg-[#081225] p-6 rounded-2xl border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3 mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-950/60 border border-cyan-500/40 text-[#00E5FF]">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-black text-white tracking-tight flex items-center gap-2">
                Paste & Inspect Log
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 font-bold uppercase tracking-wider">
                  Live ML Engine
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Paste any raw server log (syslog, auth, nginx, apache, or kernel) to run real-time Isolation Forest + One-Class SVM anomaly detection with SHAP explainability.
              </p>
            </div>
          </div>

          {/* QUICK PRESET CHIPS */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-mono text-slate-400 mr-1 flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-cyan-400" /> Presets:
            </span>
            {SAMPLE_PRESETS.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setPastedLogInput(p.log);
                  setPasteError(null);
                }}
                className={`text-[11px] font-mono font-medium px-2.5 py-1 rounded-lg border transition-all cursor-pointer ${
                  p.color === 'red'
                    ? 'bg-red-950/40 border-red-500/30 text-red-300 hover:bg-red-900/50'
                    : p.color === 'amber'
                    ? 'bg-amber-950/40 border-amber-500/30 text-amber-300 hover:bg-amber-900/50'
                    : p.color === 'purple'
                    ? 'bg-purple-950/40 border-purple-500/30 text-purple-300 hover:bg-purple-900/50'
                    : 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300 hover:bg-emerald-900/50'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* LOG INPUT TEXTAREA */}
        <div className="space-y-3">
          <div className="relative">
            <textarea
              value={pastedLogInput}
              onChange={(e) => {
                setPastedLogInput(e.target.value);
                if (pasteError) setPasteError(null);
              }}
              rows={3}
              placeholder="Paste raw server log here... (e.g. 2026-10-18T10:14:02 server sshd[4201]: Failed password for invalid user admin from 192.168.1.105 port 49201 ssh2)"
              className="w-full bg-[#050B14] border border-slate-800 focus:border-cyan-500/70 focus:ring-1 focus:ring-cyan-500/30 rounded-xl p-3.5 text-xs font-mono text-slate-200 placeholder:text-slate-600 outline-none transition-all resize-y"
            />
            {pastedLogInput && (
              <button
                type="button"
                onClick={() => {
                  setPastedLogInput('');
                  setPasteResult(null);
                  setPasteError(null);
                }}
                className="absolute top-3 right-3 text-slate-500 hover:text-slate-300 text-xs font-mono p-1 rounded hover:bg-slate-800 transition-all cursor-pointer"
                title="Clear input"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* ACTION BUTTONS & ERROR */}
          <div className="flex flex-col sm:flex-row justify-between items-stretch sm:items-center gap-3">
            <div>
              {pasteError && (
                <div className="text-xs text-red-400 font-mono flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
                  {pasteError}
                </div>
              )}
            </div>

            <div className="flex items-center gap-2 self-end">
              {pastedLogInput && (
                <button
                  type="button"
                  onClick={() => {
                    setPastedLogInput('');
                    setPasteResult(null);
                    setPasteError(null);
                  }}
                  className="px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-slate-400 hover:text-slate-200 transition-all cursor-pointer"
                >
                  Clear
                </button>
              )}
              <button
                type="button"
                onClick={handleAnalyzePastedLog}
                disabled={analyzingPastedLog || !pastedLogInput.trim()}
                className={`px-5 py-2.5 rounded-xl font-mono text-xs font-bold flex items-center gap-2 transition-all cursor-pointer shadow-lg ${
                  analyzingPastedLog || !pastedLogInput.trim()
                    ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/50'
                    : 'bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white shadow-cyan-500/20 hover:shadow-cyan-500/30 transform hover:-translate-y-0.5'
                }`}
              >
                {analyzingPastedLog ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-cyan-200" />
                    Running Pipeline...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 text-cyan-200 fill-cyan-200" />
                    Analyze Log & Explain
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* ANALYSIS RESULT CARD (Appears when log is analyzed) */}
        {pasteResult && pasteResult.top_event && (
          <div className="mt-5 pt-5 border-t border-slate-800/80 animate-fade-in">
            {/* VERDICT BANNER */}
            <div
              className={`p-4 rounded-xl border flex flex-col md:flex-row justify-between items-start md:items-center gap-4 ${
                pasteResult.top_event.is_anomaly === 1
                  ? 'bg-gradient-to-r from-red-950/50 via-rose-950/30 to-slate-900 border-red-500/40 shadow-lg shadow-red-950/30'
                  : 'bg-gradient-to-r from-emerald-950/50 via-teal-950/30 to-slate-900 border-emerald-500/40 shadow-lg shadow-emerald-950/30'
              }`}
            >
              <div className="flex items-center gap-3">
                <div
                  className={`p-3 rounded-xl border ${
                    pasteResult.top_event.is_anomaly === 1
                      ? 'bg-red-900/40 border-red-500/50 text-red-400 shadow-md glow-red'
                      : 'bg-emerald-900/40 border-emerald-500/50 text-emerald-400 shadow-md glow-green'
                  }`}
                >
                  {pasteResult.top_event.is_anomaly === 1 ? (
                    <AlertOctagon className="w-6 h-6 animate-pulse" />
                  ) : (
                    <ShieldCheck className="w-6 h-6" />
                  )}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-sm font-mono font-black uppercase tracking-wider ${
                        pasteResult.top_event.is_anomaly === 1 ? 'text-red-300' : 'text-emerald-300'
                      }`}
                    >
                      {pasteResult.top_event.is_anomaly === 1 ? 'SUSPICIOUS ANOMALY DETECTED' : 'NORMAL BASELINE EVENT'}
                    </span>
                    <span
                      className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border uppercase ${
                        pasteResult.top_event.severity === 'Critical'
                          ? 'bg-red-950/80 text-red-300 border-red-500'
                          : pasteResult.top_event.severity === 'High'
                          ? 'bg-orange-950/80 text-orange-300 border-orange-500'
                          : pasteResult.top_event.severity === 'Medium'
                          ? 'bg-yellow-950/80 text-yellow-300 border-yellow-500'
                          : 'bg-emerald-950/80 text-emerald-300 border-emerald-500'
                      }`}
                    >
                      {pasteResult.top_event.severity || 'Normal'} Severity
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-0.5">
                    {pasteResult.top_event.is_anomaly === 1
                      ? 'Isolation Forest and secondary models flagged statistically anomalous behavior in this log entry.'
                      : 'Event attributes align with standard operational background activity.'}
                  </p>
                </div>
              </div>

              {/* STATS PILLS */}
              <div className="flex flex-wrap items-center gap-3">
                <div className="bg-slate-900/90 border border-slate-700/80 rounded-xl px-3 py-1.5 text-center">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Anomaly Score</div>
                  <div
                    className={`text-base font-mono font-black ${
                      pasteResult.top_event.is_anomaly === 1 ? 'text-red-400' : 'text-emerald-400'
                    }`}
                  >
                    {pasteResult.top_event.anomaly_score?.toFixed(4) || '0.0000'}
                  </div>
                </div>

                <div className="bg-slate-900/90 border border-slate-700/80 rounded-xl px-3 py-1.5 text-center">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Threshold</div>
                  <div className="text-base font-mono font-bold text-slate-300">0.5000</div>
                </div>

                <div className="bg-slate-900/90 border border-slate-700/80 rounded-xl px-3 py-1.5 text-center">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Consensus</div>
                  <div className="text-xs font-mono font-bold text-cyan-300">
                    {pasteResult.top_event.consensus_state?.includes('agree') || pasteResult.top_event.consensus_agreement
                      ? 'Models Agree'
                      : 'Partial Agreement'}
                  </div>
                </div>
              </div>
            </div>

            {/* SHAP EXPLANATION & ACTION DETAILS */}
            <div className="mt-4 grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* WHAT HAPPENED */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-[11px] font-mono font-bold text-cyan-400 uppercase mb-1 flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5" /> What Happened
                </div>
                <p className="text-xs text-slate-200 leading-relaxed font-sans">
                  {pasteResult.top_event.what_happened || pasteResult.top_event.message || 'Log event processed.'}
                </p>
                <div className="mt-2 text-[10px] font-mono text-slate-400">
                  Service: <span className="text-slate-200">{pasteResult.top_event.service || 'unknown'}</span> • Level: <span className="text-slate-200">{pasteResult.top_event.log_level || 'INFO'}</span>
                </div>
              </div>

              {/* WHY SUSPICIOUS (SHAP) */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-[11px] font-mono font-bold text-amber-400 uppercase mb-1 flex items-center gap-1.5">
                  <Lightbulb className="w-3.5 h-3.5" /> Why Suspicious (SHAP)
                </div>
                <p className="text-xs text-slate-200 leading-relaxed font-sans">
                  {pasteResult.top_event.why_suspicious || 'No suspicious deviations detected; follows normal baseline.'}
                </p>
                {/* Top reasons if present */}
                {pasteResult.top_event.top_3_human_reasons && pasteResult.top_event.top_3_human_reasons.length > 0 && (
                  <div className="mt-2 space-y-1.5 pt-2 border-t border-slate-800">
                    <span className="text-[10px] font-mono font-bold uppercase text-amber-400 block">
                      Contributing Behavioral Factors:
                    </span>
                    {pasteResult.top_event.top_3_human_reasons.map((r, i) => {
                      const cleanR = formatFactorText(r);
                      const parts = cleanR.split(/ - | — /);
                      return (
                        <div key={i} className="text-[11px] font-mono text-amber-200/90 flex items-start gap-1.5">
                          <span className="text-amber-400 mt-0.5">•</span>
                          <div>
                            <strong className="text-white">{parts[0]}</strong>
                            {parts[1] && <span className="text-amber-300/80 block text-[10px] font-sans mt-0.5">{parts[1]}</span>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* RECOMMENDED ACTION */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
                <div className="text-[11px] font-mono font-bold text-emerald-400 uppercase mb-1 flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5" /> SOC Recommendation
                </div>
                <p className="text-xs text-slate-200 leading-relaxed font-sans">
                  {pasteResult.top_event.recommended_action || 'No action required. Continue standard operational monitoring.'}
                </p>
                <div className="mt-3">
                  <a
                    href="/analysis"
                    className="text-[11px] font-mono text-[#00E5FF] hover:underline flex items-center gap-1 cursor-pointer"
                  >
                    Explore all parsed logs in Log Analysis <ChevronRight className="w-3 h-3" />
                  </a>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* HISTORICAL LOG EXPLORER REDIRECTION BANNER */}
      <div className="p-5 rounded-2xl bg-[#081225] border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-[#00E5FF]/10 text-[#00E5FF] border border-[#00E5FF]/20">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">Full Historical Log Records Explorer</h3>
            <p className="text-xs text-slate-400 font-sans">
              Looking for the full stream of parsed historical server logs? Multi-attribute search and log-level filtering are available in the Log Analysis explorer.
            </p>
          </div>
        </div>
        <a
          href="/analysis"
          className="px-4 py-2 rounded-xl bg-slate-900 border border-slate-700 hover:border-[#00E5FF] text-xs font-mono font-bold text-[#00E5FF] flex items-center gap-2 hover:bg-[#00E5FF]/10 transition-all whitespace-nowrap"
        >
          Open Log Analysis <ChevronRight className="w-4 h-4" />
        </a>
      </div>

      {/* ACCESSIBLE ATTACK SIMULATOR MODAL */}
      {simulatorOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="simulator-title"
          className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto"
        >
          <div className="bg-[#081225] border border-slate-700 rounded-2xl w-full max-w-4xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* MODAL HEADER */}
            <div className="p-5 border-b border-slate-800 bg-[#050816] flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-red-600/20 border border-red-500/40 text-red-400">
                  <Zap className="w-5 h-5 text-amber-300" />
                </div>
                <div>
                  <h2 id="simulator-title" className="text-lg font-black text-white flex items-center gap-2">
                    Attack Simulator & Anomaly Injector
                  </h2>
                  <p className="text-xs text-slate-400 font-sans">
                    Demonstrate anomaly detection against 5 synthetic attack vectors. Models run genuine inference without modified weights or threshold tampering.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSimulatorOpen(false)}
                className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
                aria-label="Close attack simulator modal"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* MODAL BODY */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {/* SCENARIO SELECTION BUTTONS */}
              <div>
                <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-2 font-semibold">
                  1. Select Attack Scenario to Simulate:
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
                  {scenarios.map((s) => {
                    const isSelected = s.id === selectedScenarioId;
                    return (
                      <button
                        key={s.id}
                        type="button"
                        onClick={() => {
                          setSelectedScenarioId(s.id);
                          setSimFeedback(null);
                          setSimError(null);
                        }}
                        className={`p-3 rounded-xl border text-left flex flex-col justify-between transition-all ${
                          isSelected
                            ? 'bg-[#00E5FF]/15 border-[#00E5FF] shadow-lg glow-cyan text-white'
                            : 'bg-slate-900/80 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                        }`}
                      >
                        <div>
                          <div className="text-[10px] font-mono font-bold text-amber-400 mb-1 flex items-center gap-1">
                            <Terminal className="w-3 h-3" />
                            {s.category || 'Threat'}
                          </div>
                          <div className="text-xs font-bold text-slate-200 leading-snug line-clamp-2">
                            {s.name}
                          </div>
                        </div>
                        <div className="mt-3 flex items-center justify-between text-[10px] font-mono">
                          <span className={isSelected ? 'text-[#00E5FF] font-bold' : 'text-slate-500'}>
                            {isSelected ? 'SELECTED' : 'SELECT'}
                          </span>
                          <ChevronRight className={`w-3.5 h-3.5 ${isSelected ? 'text-[#00E5FF]' : 'text-slate-600'}`} />
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* ACTIVE SCENARIO DETAIL CARD */}
              {activeScenario && (
                <div className="bg-[#050816] border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
                    <div>
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30">
                        {activeScenario.category || 'Security Attack Vector'}
                      </span>
                      <h3 className="text-base font-bold text-white mt-1">{activeScenario.name}</h3>
                    </div>
                    <div className="text-right">
                      <span className="text-[10px] font-mono text-slate-400 block">Model Pipeline:</span>
                      <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1 sm:justify-end">
                        <Cpu className="w-3.5 h-3.5" /> Genuine ML Evaluation
                      </span>
                    </div>
                  </div>

                  {/* DESCRIPTION */}
                  <p className="text-xs text-slate-300 leading-relaxed font-sans">
                    {activeScenario.description}
                  </p>

                  {/* SIGNALS & FEATURES EXERCISED */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                    <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                      <span className="text-[10px] text-slate-400 uppercase font-bold flex items-center gap-1">
                        <Activity className="w-3 h-3 text-[#00E5FF]" /> Target Feature Signals:
                      </span>
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {(activeScenario.target_signals || []).map((sig) => (
                          <span key={sig} className="px-2 py-0.5 rounded bg-[#00E5FF]/10 text-[#00E5FF] border border-[#00E5FF]/30 text-[10px]">
                            {sig}
                          </span>
                        ))}
                      </div>
                      <p className="text-[11px] text-slate-400 font-sans pt-1">
                        {activeScenario.expected_signals}
                      </p>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                      <span className="text-[10px] text-slate-400 uppercase font-bold flex items-center gap-1">
                        <ShieldCheck className="w-3 h-3 text-emerald-400" /> Security Recommendation:
                      </span>
                      <p className="text-[11px] text-emerald-300/90 font-sans leading-relaxed pt-1">
                        {activeScenario.security_recommendation}
                      </p>
                    </div>
                  </div>

                  {/* SYNTHETIC LOG PREVIEW */}
                  <div className="space-y-1.5">
                    <span className="text-[10px] font-mono text-slate-400 uppercase font-bold flex items-center gap-1">
                      <Terminal className="w-3 h-3 text-amber-400" /> Synthetic Syslog Preview (Demonstration):
                    </span>
                    <pre className="p-3 rounded-lg bg-black/90 border border-slate-800 text-[11px] font-mono text-amber-300/90 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                      {activeScenario.sample_preview || 'Generating synthetic log records...'}
                    </pre>
                  </div>

                  {/* TRANSPARENCY NOTICE */}
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-[11px] font-sans text-slate-400 space-y-1">
                    <strong className="text-slate-300 block font-mono text-[10px] uppercase">
                      Pipeline Integrity Assurance:
                    </strong>
                    <p>
                      Synthetic records are marked with <code className="text-amber-400 font-mono text-[10px]">is_simulated = 1</code> in SQLite.
                      They pass through the real log parser, the 8-dimensional <code className="text-cyan-400 font-mono text-[10px]">BehavioralFeatureExtractor</code>, Isolation Forest decision function, and One-Class SVM. No scores are hardcoded.
                    </p>
                  </div>
                </div>
              )}

              {/* COMPREHENSIVE SIMULATION RESULTS & SHAP EXPLAINABILITY PANEL */}
              {simFeedback && (() => {
                const anomaliesDetected = simFeedback.detection_summary?.anomalies_detected ?? 0;
                const totalAnalyzed = simFeedback.detection_summary?.total_analyzed ?? simFeedback.events_generated ?? 0;
                const maxScore = typeof simFeedback.detection_summary?.max_anomaly_score === 'number'
                  ? simFeedback.detection_summary.max_anomaly_score
                  : parseFloat(simFeedback.detection_summary?.max_anomaly_score || 0);
                const overallIsAnomaly = anomaliesDetected > 0;
                const overallSeverityBadge = getSeverityBadge(
                  maxScore,
                  overallIsAnomaly,
                  overallIsAnomaly ? (maxScore > 0.85 ? 'Critical' : maxScore > 0.70 ? 'High' : maxScore > 0.55 ? 'Medium' : 'Low') : 'Normal'
                );

                const injectedEvents = simFeedback.injected_results || [];
                const activeSimEvent =
                  injectedEvents.find((e) => e.id === selectedSimEventId) ||
                  injectedEvents.find((e) => e.is_anomaly === 1) ||
                  injectedEvents[0] ||
                  {};

                const activeReasons =
                  activeSimEvent.top_3_human_reasons && activeSimEvent.top_3_human_reasons.length > 0
                    ? activeSimEvent.top_3_human_reasons
                    : (simFeedback.primary_shap_explanation?.top_3_human_reasons || []);

                const featContribs =
                  activeSimEvent.feature_contributions && Object.keys(activeSimEvent.feature_contributions).length > 0
                    ? activeSimEvent.feature_contributions
                    : (simFeedback.primary_shap_explanation?.feature_contributions || {});

                return (
                  <div className="p-5 rounded-2xl bg-[#050816] border border-cyan-500/40 shadow-2xl space-y-5 animate-in fade-in duration-200">
                    {/* RESULT HEADER BANNER */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl bg-slate-950/80 border border-slate-800">
                      <div className="flex items-center gap-3">
                        <div className={`p-2.5 rounded-xl border ${overallIsAnomaly ? 'bg-red-500/20 border-red-500/40 text-red-400' : 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400'}`}>
                          {overallIsAnomaly ? <ShieldAlert className="w-6 h-6 text-red-400 animate-pulse" /> : <CheckCircle className="w-6 h-6 text-emerald-400" />}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono uppercase text-slate-400 font-bold">Detection Verdict:</span>
                            <span className={`px-2.5 py-0.5 rounded text-xs font-black uppercase font-mono border ${overallIsAnomaly ? 'bg-red-500/20 text-red-300 border-red-500/50 glow-red' : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'}`}>
                              {overallIsAnomaly ? '🚨 ANOMALY DETECTED' : '✅ NORMAL BASELINE'}
                            </span>
                          </div>
                          <p className="text-xs font-sans text-slate-300 mt-0.5">
                            {overallIsAnomaly
                              ? `${anomaliesDetected} of ${totalAnalyzed} simulated events triggered Isolation Forest decision boundaries.`
                              : `All ${totalAnalyzed} events conformed to the standard learned baseline.`}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 sm:self-center">
                        <div className="text-right">
                          <span className="text-[10px] font-mono text-slate-400 block uppercase font-semibold">Severity Rating</span>
                          <span className={`px-2.5 py-0.5 rounded text-xs font-bold font-mono border inline-block ${overallSeverityBadge.bg}`}>
                            {overallSeverityBadge.label} Severity
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* 4 KEY METRICS CARDS */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs font-mono">
                      <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                        <span className="text-slate-400 block text-[10px] uppercase font-bold">Classification</span>
                        <strong className={`text-sm font-black block mt-0.5 ${overallIsAnomaly ? 'text-red-400' : 'text-emerald-400'}`}>
                          {overallIsAnomaly ? `${anomaliesDetected} / ${totalAnalyzed} Anomalies` : 'Baseline (0 Flagged)'}
                        </strong>
                        <span className="text-[10px] text-slate-500 block">Unsupervised detector</span>
                      </div>

                      <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                        <span className="text-slate-400 block text-[10px] uppercase font-bold">Peak Anomaly Score</span>
                        <strong className="text-sm font-black text-[#00E5FF] block mt-0.5">
                          {maxScore.toFixed(4)}
                        </strong>
                        <span className="text-[10px] text-slate-500 block">Threshold ~0.50</span>
                      </div>

                      <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                        <span className="text-slate-400 block text-[10px] uppercase font-bold">Severity Level</span>
                        <div className="mt-1">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold border inline-block ${overallSeverityBadge.bg}`}>
                            {overallSeverityBadge.label}
                          </span>
                        </div>
                        <span className="text-[10px] text-slate-500 block mt-1">Calculated from score</span>
                      </div>

                      <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                        <span className="text-slate-400 block text-[10px] uppercase font-bold">Model Consensus</span>
                        <strong className="text-xs font-bold text-amber-300 block mt-0.5 truncate" title={simFeedback.detection_summary?.primary_consensus || 'Evaluated'}>
                          {simFeedback.detection_summary?.primary_consensus || (overallIsAnomaly ? 'Consensus Anomaly' : 'Consensus Normal')}
                        </strong>
                        <span className="text-[10px] text-slate-500 block">Isolation Forest + One-Class SVM</span>
                      </div>
                    </div>

                    {/* SHAP EXPLAINABILITY PANEL */}
                    <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-4">
                      <div className="flex items-center justify-between pb-2 border-b border-slate-800/80">
                        <div className="flex items-center gap-2">
                          <HelpCircle className="w-4 h-4 text-[#00E5FF]" />
                          <h4 className="text-xs font-bold font-mono text-white uppercase tracking-wider">
                            SHAP Explainability & Root-Cause Insights
                          </h4>
                        </div>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                          {activeSimEvent.service ? `${activeSimEvent.service} (ID: ${activeSimEvent.id || 'N/A'})` : 'Top Threat Event'}
                        </span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                        {/* WHAT HAPPENED */}
                        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1">
                          <span className="text-[10px] text-slate-400 uppercase font-bold flex items-center gap-1 text-[#00E5FF]">
                            <Info className="w-3 h-3 text-[#00E5FF]" /> What Happened:
                          </span>
                          <p className="text-[11px] text-slate-200 font-sans leading-relaxed">
                            "{activeSimEvent.what_happened || activeSimEvent.message || simFeedback.primary_shap_explanation?.what_happened || 'Multiple anomalous syslog events occurred exceeding normal sequence baselines.'}"
                          </p>
                        </div>

                        {/* WHY IS IT SUSPICIOUS */}
                        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1">
                          <span className="text-[10px] text-slate-400 uppercase font-bold flex items-center gap-1 text-red-400">
                            <ShieldAlert className="w-3 h-3 text-red-400" /> Why is it Suspicious?
                          </span>
                          <p className="text-[11px] text-red-200/90 font-sans leading-relaxed">
                            "{activeSimEvent.why_suspicious || simFeedback.primary_shap_explanation?.why_suspicious || 'Behavioral sequence metrics and failure burst rates deviated significantly from standard operational distribution.'}"
                          </p>
                        </div>
                      </div>

                      {/* TOP 3 SHAP CONTRIBUTING REASONS */}
                      {activeReasons.length > 0 && (
                        <div className="p-3 rounded-lg bg-red-950/20 border border-red-500/20 space-y-2">
                          <span className="text-[10px] font-mono font-bold uppercase text-red-400 block">
                            Top SHAP Behavioral Contributing Factors:
                          </span>
                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                            {activeReasons.map((reason, idx) => {
                              const cleanReason = formatFactorText(reason);
                              const parts = cleanReason.split(/ - | — /);
                              const title = parts[0] || cleanReason;
                              const subtitle = parts.slice(1).join(' - ');
                              return (
                                <div key={idx} className="p-2.5 rounded bg-slate-900 border border-red-500/30 text-[11px] font-mono text-red-200">
                                  <span className="text-slate-500 block text-[9px] uppercase tracking-wider font-bold">FACTOR #{idx + 1}</span>
                                  <span className="font-semibold text-white block mt-0.5">{title}</span>
                                  {subtitle && <span className="text-[10px] text-red-300/80 block mt-0.5 font-sans leading-tight">{subtitle}</span>}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {/* FEATURE SHAP CONTRIBUTION METERS */}
                      {featContribs && Object.keys(featContribs).length > 0 && (
                        <div className="space-y-1.5 pt-1">
                          <span className="text-[10px] font-mono text-slate-400 uppercase font-bold block">
                            Behavioral Feature Impact toward Anomaly:
                          </span>
                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                            {Object.entries(featContribs).slice(0, 4).map(([fName, fVal]) => {
                              const numVal = typeof fVal === 'number' ? fVal : parseFloat(fVal || 0);
                              const isPositive = numVal >= 0;
                              const humanLabel = FEATURE_NAME_HUMAN[fName] || fName;
                              return (
                                <div key={fName} className="p-2 rounded bg-slate-900/90 border border-slate-800 text-[10px] font-mono">
                                  <div className="flex justify-between items-center text-slate-400 mb-1">
                                    <span className="truncate text-white font-medium" title={fName}>{humanLabel}</span>
                                    <span className={isPositive ? 'text-red-400 font-bold' : 'text-emerald-400 font-bold'}>
                                      {isPositive ? `+${numVal.toFixed(3)}` : numVal.toFixed(3)}
                                    </span>
                                  </div>
                                  <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                                    <div
                                      className={`h-full ${isPositive ? 'bg-red-400' : 'bg-emerald-400'}`}
                                      style={{ width: `${Math.min(Math.abs(numVal) * 100, 100)}%` }}
                                    />
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {/* RECOMMENDED SOC ACTION */}
                      <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-500/30 space-y-1">
                        <span className="text-[10px] text-emerald-400 uppercase font-bold flex items-center gap-1">
                          <Lightbulb className="w-3.5 h-3.5 text-emerald-400" /> Recommended SOC Mitigation:
                        </span>
                        <p className="text-[11px] text-emerald-200/90 font-sans leading-relaxed">
                          "{activeSimEvent.recommended_action || simFeedback.primary_shap_explanation?.recommended_action || activeScenario.security_recommendation}"
                        </p>
                      </div>
                    </div>

                    {/* JUMP TO MAIN THREAT CARD ACTION */}
                    <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3">
                      <span className="text-[11px] font-mono text-slate-400">
                        Demonstration results for <strong className="text-white font-bold">{simFeedback.scenario_name || activeScenario.name}</strong>.
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          if (activeSimEvent && activeSimEvent.id) {
                            setSelectedEvent(activeSimEvent);
                          }
                          setSimulatorOpen(false);
                        }}
                        className="px-4 py-2 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-bold flex items-center gap-1.5 transition-all shadow-md cursor-pointer"
                      >
                        Inspect in Main Security Analysis Card →
                      </button>
                    </div>
                  </div>
                );
              })()}

              {/* SIMULATION ERROR ALERT */}
              {simError && (
                <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/50 text-xs font-mono text-red-300 flex items-center gap-2">
                  <AlertOctagon className="w-4 h-4 text-red-400 shrink-0" />
                  <span>{simError}</span>
                </div>
              )}
            </div>

            {/* MODAL FOOTER */}
            <div className="p-4 border-t border-slate-800 bg-[#050816] flex flex-col sm:flex-row items-center justify-between gap-3">
              <span className="text-[11px] font-mono text-slate-500">
                Safe demonstration sandbox: only synthetic telemetry is produced.
              </span>
              <div className="flex items-center gap-2 w-full sm:w-auto">
                <button
                  type="button"
                  onClick={() => setSimulatorOpen(false)}
                  className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300 transition-colors w-full sm:w-auto"
                >
                  Close
                </button>
                <button
                  type="button"
                  disabled={injecting}
                  onClick={() => handleInjectScenario(selectedScenarioId)}
                  className="px-5 py-2 rounded-xl bg-gradient-to-r from-red-600 via-amber-600 to-amber-500 hover:from-red-500 hover:to-amber-400 disabled:opacity-50 text-white text-xs font-mono font-bold flex items-center justify-center gap-2 shadow-lg shadow-red-950/40 transition-all cursor-pointer w-full sm:w-auto"
                >
                  {injecting ? (
                    <>
                      <Activity className="w-4 h-4 animate-spin text-yellow-300" />
                      Injecting & Running ML Pipeline...
                    </>
                  ) : (
                    <>
                      <Zap className="w-4 h-4 text-yellow-300" />
                      Inject & Analyze Scenario
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AnomalyDetectionPage;
