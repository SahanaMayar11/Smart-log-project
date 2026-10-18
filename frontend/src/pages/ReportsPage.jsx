import React, { useState, useEffect } from 'react';
import { Download, FileText, Printer, CheckCircle, ShieldAlert, Activity, Info, ArrowUpRight, Shield, Lightbulb, HelpCircle } from 'lucide-react';
import GlassCard from '../components/ui/GlassCard';
import { fetchReportSummary, fetchDashboardStats, fetchDetectionResults, fetchShapExplanations } from '../services/api';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';

// Chart.js
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement
} from 'chart.js';
import { Pie, Bar } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement);

const ReportsPage = () => {
  const [summary, setSummary] = useState(null);
  const [stats, setStats] = useState(null);
  const [detections, setDetections] = useState([]);
  const [shapExplanations, setShapExplanations] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAllReportData();
  }, []);

  const loadAllReportData = async () => {
    try {
      const [sumData, statData, detData, shapData] = await Promise.all([
        fetchReportSummary().catch(() => null),
        fetchDashboardStats().catch(() => null),
        fetchDetectionResults().catch(() => []),
        fetchShapExplanations().catch(() => [])
      ]);

      setSummary(sumData);
      setStats(statData);
      setDetections(detData);
      setShapExplanations(shapData);
    } catch (err) {
      console.error('Error loading report data:', err);
    } finally {
      setLoading(false);
    }
  };

  // Dynamic calculations from backend APIs
  const totalLogs = stats?.total_logs || summary?.total_parsed_logs || detections.length || 0;
  const normalLogs = stats?.normal_logs || summary?.normal_count || detections.filter((d) => d.is_anomaly === 0).length || 0;
  const anomalyLogs = stats?.anomaly_logs || summary?.anomaly_count || detections.filter((d) => d.is_anomaly === 1).length || 0;
  
  // Severity Counts
  const highSeverityCount = detections.filter((d) => d.severity === 'High' || d.severity === 'Critical' || (d.is_anomaly === 1 && d.anomaly_score > 0.7)).length;
  const mediumSeverityCount = detections.filter((d) => d.severity === 'Medium' || d.severity === 'Warning' || (d.is_anomaly === 1 && d.anomaly_score <= 0.7 && d.anomaly_score > 0.55)).length;
  const lowSeverityCount = detections.filter((d) => d.severity === 'Low' || (d.is_anomaly === 1 && d.anomaly_score <= 0.55)).length;

  const anomalyRate = totalLogs ? ((anomalyLogs / totalLogs) * 100).toFixed(2) : '0.00';
  const numRate = parseFloat(anomalyRate);

  // Dynamic Overall System Status
  let overallStatus = 'NORMAL';
  let overallStatusColor = 'text-emerald-500 bg-emerald-50 border-emerald-300';
  if (numRate > 30 || highSeverityCount > 3) {
    overallStatus = 'HIGH RISK';
    overallStatusColor = 'text-red-600 bg-red-50 border-red-300';
  } else if (numRate > 0 || anomalyLogs > 0) {
    overallStatus = 'SUSPICIOUS';
    overallStatusColor = 'text-amber-600 bg-amber-50 border-amber-300';
  }

  // Aggregate SHAP Feature Rankings
  const aggregateFeatureImportance = () => {
    const totals = {};
    shapExplanations.forEach((item) => {
      const contribs = item.feature_contributions || {};
      Object.keys(contribs).forEach((feat) => {
        totals[feat] = (totals[feat] || 0) + Math.abs(contribs[feat]);
      });
    });
    const sorted = Object.entries(totals).sort((a, b) => b[1] - a[1]);
    return sorted.map(([name, val]) => ({ name, val: val.toFixed(4) }));
  };

  const topShapFeatures = aggregateFeatureImportance();

  // SHAP Human Explanations for Section 5
  const getShapFeatureExplanation = (featureName) => {
    const name = featureName.toLowerCase();
    if (name.includes('failed') || name.includes('login')) {
      return 'Unusually high authentication failure attempts detected.';
    }
    if (name.includes('frequency') || name.includes('rate')) {
      return 'Event surge frequency significantly exceeded normal baseline.';
    }
    if (name.includes('error') && name.includes('count')) {
      return 'Rapid accumulation of system error messages in short timeframe.';
    }
    if (name.includes('error') && name.includes('pattern')) {
      return 'Repetitive error execution loops or privilege denial spikes.';
    }
    if (name.includes('warning')) {
      return 'Multiple concurrent system warning indicators generated.';
    }
    if (name.includes('sequence')) {
      return 'Atypical sequential event chain structure.';
    }
    return 'Observed metric deviated significantly from learned baseline.';
  };

  // Dynamic Security Recommendation for Section 7
  const getDynamicRecommendations = () => {
    if (anomalyLogs === 0) {
      return ['No significant abnormal activity detected. Continue normal baseline monitoring.'];
    }
    const recs = [];
    const topFeature = topShapFeatures[0]?.name || '';
    if (topFeature.toLowerCase().includes('failed') || topFeature.toLowerCase().includes('login')) {
      recs.push('Multiple failed login attempts detected. Review authentication activity and verify whether login attempts were authorized.');
    } else {
      recs.push('Review authentication logs and enforce multi-factor authentication (MFA) across active server accounts.');
    }
    if (highSeverityCount > 0) {
      recs.push(`Investigate ${highSeverityCount} high-severity anomaly events and isolate affected system services.`);
    }
    recs.push('Repeated application or system errors were detected. Check the affected service configuration.');
    return recs;
  };

  const securityRecommendations = getDynamicRecommendations();

  // Primary Important Anomalies for Section 4 (Top 3)
  const importantAnomalies = detections.filter((d) => d.is_anomaly === 1).slice(0, 3);

  // Trigger Browser Print (window.print())
  const handlePrintReport = () => {
    window.print();
  };

  // Export 1-Page A4 PDF function via html2canvas & jsPDF targeting #print-report
  const exportPDF = async () => {
    const reportNode = document.getElementById('print-report');
    if (!reportNode) return;

    try {
      const canvas = await html2canvas(reportNode, {
        scale: 2,
        useCORS: true,
        backgroundColor: '#ffffff',
        scrollX: 0,
        scrollY: 0,
      });
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF({
        orientation: 'p',
        unit: 'mm',
        format: 'a4',
        compress: true
      });
      pdf.addImage(imgData, 'PNG', 0, 0, 210, 297);
      pdf.save(`Smart-Log-Security-Report_${new Date().toISOString().slice(0, 10)}.pdf`);
    } catch (err) {
      window.print();
    }
  };

  // Export CSV Data
  const exportCSV = () => {
    if (!detections.length) return;
    const headers = ['Log ID', 'Timestamp', 'Hostname', 'Service', 'Anomaly Status', 'Anomaly Score', 'Severity', 'What Happened', 'Recommended Action'];
    const rows = detections.map((a) => [
      a.log_id || a.id,
      `"${a.timestamp}"`,
      `"${a.hostname || 'Rocky'}"`,
      `"${a.service}"`,
      a.is_anomaly === 1 ? 'ANOMALY' : 'NORMAL',
      a.anomaly_score,
      `"${a.severity || 'Medium'}"`,
      `"${a.what_happened || a.message}"`,
      `"${a.recommended_action || 'No action required'}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `Smart-Log-Security-Anomalies_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Chart Data for Report (Section 6)
  const pieData = {
    labels: ['Normal Events', 'Anomalies'],
    datasets: [
      {
        data: [normalLogs, anomalyLogs],
        backgroundColor: ['#10B981', '#EF4444'],
        borderColor: ['#059669', '#DC2626'],
        borderWidth: 1,
      },
    ],
  };

  const severityBarData = {
    labels: ['Low', 'Medium', 'High'],
    datasets: [
      {
        label: 'Event Count',
        data: [lowSeverityCount, mediumSeverityCount, highSeverityCount],
        backgroundColor: ['#EAB308', '#F97316', '#EF4444'],
        borderRadius: 4,
      },
    ],
  };

  const chartOpts = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#475569', font: { size: 9 } }, grid: { display: false } },
      y: { ticks: { color: '#475569', font: { size: 9 } }, grid: { color: '#E2E8F0' } }
    }
  };

  if (loading) {
    return (
      <div className="container-soc pt-32 pb-16 min-h-[70vh] flex flex-col items-center justify-center text-[#00E5FF] font-mono space-y-3">
        <Activity className="w-8 h-8 animate-spin" />
        <span className="text-sm">Compiling Smart-Log Security Report...</span>
      </div>
    );
  }

  return (
    <div className="container-soc pt-28 pb-16 space-y-8">
      {/* ON-SCREEN TOOLBAR / BUTTONS (HIDDEN IN PRINT VIA no-print) */}
      <div className="bg-[#081225] p-6 rounded-2xl border border-slate-800 backdrop-blur-xl flex flex-col md:flex-row justify-between items-start md:items-center gap-4 no-print">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <FileText className="w-5 h-5 text-[#00E5FF]" />
            <h1 className="text-2xl font-black text-white">FINAL ANOMALY ANALYSIS REPORT</h1>
            <span className="px-2.5 py-0.5 rounded-full bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/30 text-[10px] font-mono font-bold">
              Analysis Complete ✓
            </span>
          </div>
          <p className="text-xs text-[#94A3B8]">
            Click <strong className="text-white">"Print Report"</strong> to generate a clean, 1-page A4 printable security analysis report.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={exportCSV}
            className="h-11 px-4 rounded-xl bg-slate-900 border border-slate-700 text-xs font-bold text-slate-200 hover:text-[#00E5FF] hover:border-[#00E5FF] transition-all flex items-center gap-2"
          >
            <Download className="w-4 h-4 text-[#00E5FF]" />
            <span>Export CSV</span>
          </button>

          <button
            onClick={handlePrintReport}
            className="h-11 px-5 rounded-xl bg-gradient-to-r from-[#00E5FF] to-[#2563EB] text-slate-950 text-xs font-black uppercase tracking-wider flex items-center gap-2 glow-cyan hover:scale-105 transition-all"
          >
            <Printer className="w-4 h-4" />
            <span>Print Report</span>
          </button>

          <button
            onClick={exportPDF}
            className="h-11 px-4 rounded-xl bg-slate-900 border border-slate-700 text-xs font-bold text-slate-200 hover:text-[#00E5FF] hover:border-[#00E5FF] transition-all flex items-center gap-2"
          >
            <Download className="w-4 h-4 text-[#00E5FF]" />
            <span>Download PDF</span>
          </button>
        </div>
      </div>

      {/* DEDICATED PRINT REPORT CONTAINER (#print-report) */}
      <div className="flex justify-center">
        <div
          id="print-report"
          className="w-[794px] min-h-[1120px] bg-white text-slate-900 p-8 rounded-2xl border border-slate-300 space-y-4 shadow-2xl font-sans text-xs box-border overflow-hidden"
        >
          {/* SECTION 1: REPORT HEADER */}
          <div className="border-b-2 border-slate-900 pb-3 flex justify-between items-start">
            <div>
              <div className="flex items-center gap-2">
                <Shield className="w-6 h-6 text-slate-900" />
                <h1 className="text-2xl font-black tracking-tight text-slate-900 uppercase">SMART-LOG</h1>
              </div>
              <p className="text-xs font-bold text-slate-700 mt-0.5">Automated Syslog & System Anomaly Detection Report</p>
            </div>

            <div className="text-right font-mono text-[11px] text-slate-600 space-y-0.5">
              <div><strong className="text-slate-900">Analysis Date:</strong> {new Date().toLocaleString()}</div>
              <div><strong className="text-slate-900">System Host:</strong> {stats?.latest_file ? `Windows OS (${stats?.recent_alerts?.[0]?.hostname || 'Rocky'})` : 'Local Server System'}</div>
              <div><strong className="text-slate-900">Detection Model:</strong> Isolation Forest + SHAP XAI</div>
            </div>
          </div>

          {/* SECTION 2 & 3: ANALYSIS SUMMARY & FINAL RESULT */}
          <div className="grid grid-cols-3 gap-4">
            {/* ANALYSIS SUMMARY GRID */}
            <div className="col-span-2 p-3 rounded-lg border border-slate-300 bg-slate-50 space-y-2">
              <h2 className="text-xs font-bold text-slate-900 uppercase tracking-wider border-b border-slate-200 pb-1">
                ANALYSIS SUMMARY
              </h2>
              <div className="grid grid-cols-3 gap-2 text-center font-mono text-xs">
                <div className="p-1.5 rounded bg-white border border-slate-200">
                  <span className="text-[10px] text-slate-500 block">Total Logs Analyzed</span>
                  <strong className="text-slate-900 text-sm">{totalLogs}</strong>
                </div>
                <div className="p-1.5 rounded bg-white border border-slate-200">
                  <span className="text-[10px] text-slate-500 block">Normal Events</span>
                  <strong className="text-emerald-600 text-sm">{normalLogs}</strong>
                </div>
                <div className="p-1.5 rounded bg-white border border-slate-200">
                  <span className="text-[10px] text-slate-500 block">Anomalies Detected</span>
                  <strong className="text-red-600 text-sm">{anomalyLogs}</strong>
                </div>
                <div className="p-1.5 rounded bg-white border border-slate-200">
                  <span className="text-[10px] text-slate-500 block">High Severity</span>
                  <strong className="text-red-600 text-sm">{highSeverityCount}</strong>
                </div>
                <div className="p-1.5 rounded bg-white border border-slate-200">
                  <span className="text-[10px] text-slate-500 block">Medium Severity</span>
                  <strong className="text-amber-600 text-sm">{mediumSeverityCount}</strong>
                </div>
                <div className="p-1.5 rounded bg-white border border-slate-200">
                  <span className="text-[10px] text-slate-500 block">Low Severity</span>
                  <strong className="text-yellow-600 text-sm">{lowSeverityCount}</strong>
                </div>
              </div>
            </div>

            {/* FINAL RESULT CARD */}
            <div className={`col-span-1 p-3 rounded-lg border flex flex-col items-center justify-center text-center ${overallStatusColor}`}>
              <span className="text-[10px] font-mono uppercase font-bold text-slate-600">OVERALL SYSTEM STATUS</span>
              <strong className="text-base font-black tracking-wide mt-1 uppercase">{overallStatus}</strong>
              <span className="text-[10px] text-slate-600 mt-1">
                {overallStatus === 'NORMAL' ? 'Baseline system operations' : 'Suspicious deviations detected'}
              </span>
            </div>
          </div>

          {/* SECTION 4: ANOMALY SUMMARY */}
          {anomalyLogs > 0 && (
            <div className="space-y-2">
              <h2 className="text-xs font-bold text-slate-900 uppercase tracking-wider border-b border-slate-300 pb-1">
                ANOMALIES DETECTED
              </h2>

              <div className="space-y-2">
                {importantAnomalies.map((a, idx) => (
                  <div key={idx} className="p-3 rounded-lg border border-red-200 bg-red-50/40 text-xs space-y-1.5">
                    <div className="flex justify-between items-center border-b border-red-200 pb-1 font-mono">
                      <span className="font-bold text-red-700 text-xs">Event: {a.service || 'System Activity'}</span>
                      <div className="flex items-center gap-2 text-[11px]">
                        <span className="text-slate-600">Time: {a.timestamp}</span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-100 text-red-800 border border-red-300">
                          Severity: {a.severity || 'High'}
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div>
                        <strong className="text-slate-900 block">What happened:</strong>
                        <p className="text-slate-700">{a.what_happened || a.message}</p>
                      </div>
                      <div>
                        <strong className="text-slate-900 block">Why it was detected:</strong>
                        <p className="text-slate-700">{a.why_suspicious || a.natural_explanation}</p>
                      </div>
                    </div>

                    {a.top_3_human_reasons && a.top_3_human_reasons.length > 0 && (
                      <div className="text-[11px] pt-1 border-t border-red-200">
                        <strong className="text-slate-900">Main contributing factors:</strong>
                        <ul className="list-disc list-inside text-slate-700 pl-1">
                          {a.top_3_human_reasons.map((reason, rIdx) => (
                            <li key={rIdx}>{reason}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div className="text-[11px] pt-1 text-emerald-800 font-semibold">
                      <strong>Recommended action:</strong> {a.recommended_action || 'Review event logs & verify process origin.'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* SECTION 5: SHAP MODEL EXPLANATION */}
          <div className="space-y-2">
            <h2 className="text-xs font-bold text-slate-900 uppercase tracking-wider border-b border-slate-300 pb-1">
              MODEL EXPLANATION (SHAP) — "Why did the model flag this activity?"
            </h2>
            <div className="grid grid-cols-3 gap-2">
              {topShapFeatures.slice(0, 3).map((f, idx) => (
                <div key={idx} className="p-2.5 rounded-lg border border-slate-200 bg-slate-50 text-xs space-y-1">
                  <div className="flex justify-between items-center font-mono">
                    <strong className="text-slate-900 text-[11px]">{f.name}</strong>
                    <span className="text-xs font-bold text-red-600">High Contribution</span>
                  </div>
                  <p className="text-[10.5px] text-slate-600 leading-snug">
                    {getShapFeatureExplanation(f.name)}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* SECTION 6: CHARTS (COMPACT 2-COLUMN GRID) */}
          <div className="grid grid-cols-2 gap-4">
            <div className="p-3 rounded-lg border border-slate-200 bg-slate-50">
              <h3 className="text-[11px] font-bold text-slate-900 uppercase mb-1">Normal vs Anomaly Distribution</h3>
              <div className="h-[90px] relative flex items-center justify-center">
                <Pie data={pieData} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: true, position: 'right', labels: { font: { size: 9 } } } } }} />
              </div>
            </div>

            <div className="p-3 rounded-lg border border-slate-200 bg-slate-50">
              <h3 className="text-[11px] font-bold text-slate-900 uppercase mb-1">Severity Distribution</h3>
              <div className="h-[90px]">
                <Bar data={severityBarData} options={chartOpts} />
              </div>
            </div>
          </div>

          {/* SECTION 7: FINAL SECURITY RECOMMENDATION */}
          <div className="p-3 rounded-lg border border-slate-300 bg-slate-50 space-y-1">
            <h2 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
              <Lightbulb className="w-4 h-4 text-amber-600" /> SECURITY RECOMMENDATIONS
            </h2>
            <ul className="list-disc list-inside space-y-1 text-slate-700 text-xs">
              {securityRecommendations.map((rec, rIdx) => (
                <li key={rIdx}>{rec}</li>
              ))}
            </ul>
          </div>

          {/* SECTION 8: REPORT FOOTER */}
          <div className="pt-2 border-t border-slate-300 flex justify-between items-center text-[10px] font-mono text-slate-500">
            <span>Smart-Log SOC • Department of Computer Science & Engineering</span>
            <span>BIET Davanagere - 577004 (VTU)</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportsPage;
