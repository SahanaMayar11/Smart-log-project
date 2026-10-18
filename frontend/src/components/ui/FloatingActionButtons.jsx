import React from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { UploadCloud, LayoutDashboard, ShieldAlert, Activity, ArrowUp } from 'lucide-react';

const FloatingActionButtons = () => {
  const navigate = useNavigate();

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="fixed right-6 bottom-8 z-40 flex flex-col gap-3 items-center">
      {/* Quick Upload Floating Button */}
      <motion.button
        whileHover={{ scale: 1.1 }}
        whileTap={{ scale: 0.95 }}
        onClick={() => navigate('/upload')}
        className="w-12 h-12 rounded-full bg-cyan-500 text-slate-950 flex items-center justify-center shadow-[0_0_20px_rgba(34,211,238,0.4)] hover:shadow-[0_0_30px_rgba(34,211,238,0.6)] transition-all group relative"
        title="Quick Upload Log Stream"
      >
        <UploadCloud className="w-5 h-5 font-bold" />
        <span className="absolute right-14 bg-slate-900 text-cyan-300 text-xs font-mono px-3 py-1 rounded-lg border border-slate-800 opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none shadow-lg">
          Upload Logs
        </span>
      </motion.button>

      {/* SOC Dashboard Floating Button */}
      <motion.button
        whileHover={{ scale: 1.1 }}
        whileTap={{ scale: 0.95 }}
        onClick={() => navigate('/dashboard')}
        className="w-12 h-12 rounded-full bg-slate-900 border border-cyan-500/40 text-cyan-400 flex items-center justify-center shadow-lg hover:border-cyan-400 transition-all group relative"
        title="SOC Security Operations Center"
      >
        <LayoutDashboard className="w-5 h-5" />
        <span className="absolute right-14 bg-slate-900 text-slate-200 text-xs font-mono px-3 py-1 rounded-lg border border-slate-800 opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none shadow-lg">
          SOC Dashboard
        </span>
      </motion.button>

      {/* Threat Detection Floating Button */}
      <motion.button
        whileHover={{ scale: 1.1 }}
        whileTap={{ scale: 0.95 }}
        onClick={() => navigate('/detection')}
        className="w-12 h-12 rounded-full bg-slate-900 border border-purple-500/40 text-purple-400 flex items-center justify-center shadow-lg hover:border-purple-400 transition-all group relative"
        title="Threat Detection Console"
      >
        <ShieldAlert className="w-5 h-5" />
        <span className="absolute right-14 bg-slate-900 text-purple-300 text-xs font-mono px-3 py-1 rounded-lg border border-slate-800 opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none shadow-lg">
          Threat Console
        </span>
      </motion.button>

      {/* Scroll to top */}
      <motion.button
        whileHover={{ scale: 1.1 }}
        whileTap={{ scale: 0.95 }}
        onClick={scrollToTop}
        className="w-10 h-10 rounded-full bg-slate-950/80 border border-slate-800 text-slate-400 flex items-center justify-center hover:text-slate-200 transition-all"
        title="Scroll to Top"
      >
        <ArrowUp className="w-4 h-4" />
      </motion.button>
    </div>
  );
};

export default FloatingActionButtons;
