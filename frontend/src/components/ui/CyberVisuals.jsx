import React from 'react';
import { motion } from 'framer-motion';
import { Server, ShieldCheck, Cpu, Activity, FileText, Layers, Lock, Sparkles } from 'lucide-react';

export const ServerRackVisual = () => (
  <div className="relative p-6 rounded-2xl bg-[#080D1C]/90 border border-cyan-500/30 glass-panel shadow-[0_0_30px_rgba(34,211,238,0.15)] flex flex-col items-center justify-center">
    <div className="w-full space-y-3">
      {[1, 2, 3].map((slot) => (
        <div key={slot} className="flex items-center justify-between p-3 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="flex items-center gap-3">
            <Server className="w-5 h-5 text-cyan-400" />
            <div>
              <p className="text-xs font-bold text-slate-100 font-mono">SYS-SERVER-NODE-0{slot}</p>
              <p className="text-[10px] text-slate-400 font-mono">Syslog Daemon Active • 10.0.0.1{slot}</p>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          </div>
        </div>
      ))}
    </div>
  </div>
);

export const SecurityShieldVisual = () => (
  <div className="relative flex items-center justify-center p-8">
    <div className="absolute w-48 h-48 bg-cyan-500/20 rounded-full blur-2xl animate-pulse" />
    <motion.div 
      animate={{ scale: [1, 1.03, 1] }} 
      transition={{ duration: 3, repeat: Infinity }}
      className="p-6 rounded-3xl bg-cyan-500/10 border-2 border-cyan-400/50 shadow-[0_0_30px_rgba(34,211,238,0.3)] text-cyan-400 relative z-10"
    >
      <ShieldCheck className="w-16 h-16" />
    </motion.div>
  </div>
);

export const ArchitectureFlowVisual = () => {
  const steps = [
    { title: 'SERVER LOGS', icon: FileText, color: 'text-cyan-400', border: 'border-cyan-500/40' },
    { title: 'LOG PARSER', icon: Layers, color: 'text-blue-400', border: 'border-blue-500/40' },
    { title: 'DATA CLEANING', icon: Sparkles, color: 'text-indigo-400', border: 'border-indigo-500/40' },
    { title: '8 FEATURES', icon: Cpu, color: 'text-purple-400', border: 'border-purple-500/40' },
    { title: 'ISOLATION FOREST', icon: Activity, color: 'text-pink-400', border: 'border-pink-500/40' },
    { title: 'ANOMALY DETECTION', icon: Lock, color: 'text-red-400', border: 'border-red-500/40' },
    { title: 'SHAP XAI', icon: Sparkles, color: 'text-cyan-300', border: 'border-cyan-400/40' },
    { title: 'SECURITY REPORT', icon: FileText, color: 'text-emerald-400', border: 'border-emerald-500/40' }
  ];

  return (
    <div className="p-6 rounded-2xl bg-[#080D1C]/90 border border-slate-800 space-y-4">
      <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-widest flex items-center gap-2">
        <Activity className="w-4 h-4 text-cyan-400" />
        Connected End-to-End System Architecture Workflow
      </h4>
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 relative">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          return (
            <motion.div
              key={idx}
              initial={{ opacity: 0, y: 15 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.08 }}
              className={`p-4 rounded-xl glass-panel border ${step.border} flex flex-col items-center text-center relative z-10 group hover:border-cyan-400 transition-all`}
            >
              <div className="p-2.5 rounded-xl bg-slate-900/90 border border-slate-800 mb-2">
                <Icon className={`w-5 h-5 ${step.color}`} />
              </div>
              <span className="text-[10px] font-mono text-slate-500 font-bold mb-1">STAGE 0{idx + 1}</span>
              <h5 className="text-xs font-bold text-slate-100">{step.title}</h5>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
};
