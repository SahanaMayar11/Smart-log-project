import React from 'react';

const Footer = () => {
  return (
    <footer className="py-4 px-6 border-t border-slate-800 bg-slate-950/60 text-xs text-slate-400 flex flex-col md:flex-row justify-between items-center gap-2">
      <div>
        <span className="font-semibold text-cyan-400">Smart-Log</span> — Automated Syslog Anomaly Detection for Server Security
      </div>
      <div className="font-mono text-slate-400 text-[11px]">
        Department of Computer Science & Engineering | Major Project Phase-I 2025–2026
      </div>
    </footer>
  );
};

export default Footer;
