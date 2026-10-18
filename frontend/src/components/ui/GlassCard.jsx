import React from 'react';
import { motion } from 'framer-motion';

const GlassCard = ({ children, className = '', hoverEffect = true, title = null, icon: Icon = null, action = null }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className={`glass-card p-6 ${hoverEffect ? 'glass-card-hover' : ''} ${className}`}
    >
      {(title || Icon || action) && (
        <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-700/50">
          <div className="flex items-center gap-3">
            {Icon && (
              <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Icon className="w-5 h-5" />
              </div>
            )}
            {title && <h3 className="text-lg font-bold text-white tracking-wide">{title}</h3>}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      {children}
    </motion.div>
  );
};

export default GlassCard;
