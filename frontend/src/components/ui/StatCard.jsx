import React from 'react';
import { motion } from 'framer-motion';

const StatCard = ({ title, value, subtext, icon: Icon, color = 'cyan' }) => {
  const colorMap = {
    cyan: {
      bg: 'bg-cyan-500/10',
      border: 'border-cyan-500/30',
      text: 'text-cyan-400',
      shadow: 'shadow-cyan-950/20'
    },
    purple: {
      bg: 'bg-purple-500/10',
      border: 'border-purple-500/30',
      text: 'text-purple-400',
      shadow: 'shadow-purple-950/20'
    },
    red: {
      bg: 'bg-red-500/10',
      border: 'border-red-500/30',
      text: 'text-red-400',
      shadow: 'shadow-red-950/20'
    },
    emerald: {
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/30',
      text: 'text-emerald-400',
      shadow: 'shadow-emerald-950/20'
    }
  };

  const currentTheme = colorMap[color] || colorMap.cyan;

  return (
    <motion.div
      whileHover={{ y: -3, transition: { duration: 0.2 } }}
      className={`glass-card p-5 border ${currentTheme.border} ${currentTheme.shadow} shadow-lg relative overflow-hidden`}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs font-semibold text-slate-200 uppercase tracking-wider">{title}</p>
          <h4 className="text-2xl font-black text-white mt-1">{value}</h4>
          {subtext && <p className="text-xs text-slate-300 mt-1 font-mono">{subtext}</p>}
        </div>
        {Icon && (
          <div className={`p-3 rounded-xl ${currentTheme.bg} ${currentTheme.text} border ${currentTheme.border}`}>
            <Icon className="w-6 h-6" />
          </div>
        )}
      </div>
    </motion.div>
  );
};

export default StatCard;
