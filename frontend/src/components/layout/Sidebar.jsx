import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { motion } from 'framer-motion';
import { 
  LayoutDashboard, 
  UploadCloud, 
  Search, 
  Cpu, 
  ShieldAlert, 
  PieChart, 
  FileText, 
  Info, 
  ChevronLeft,
  ChevronRight,
  Shield
} from 'lucide-react';

const Sidebar = () => {
  const [collapsed, setCollapsed] = useState(false);

  const navItems = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'System Log Monitor', path: '/upload', icon: UploadCloud },
    { name: 'Log Analysis', path: '/analysis', icon: Search },
    { name: 'Behavioral Features', path: '/features', icon: Cpu },
    { name: 'Anomaly Detection', path: '/detection', icon: ShieldAlert },
    { name: 'SHAP Explainability', path: '/shap', icon: PieChart },
    { name: 'Reports', path: '/reports', icon: FileText },
    { name: 'About Project', path: '/about', icon: Info },
  ];


  return (
    <motion.aside 
      animate={{ width: collapsed ? '4.5rem' : '16rem' }}
      transition={{ duration: 0.3, ease: 'easeInOut' }}
      className="bg-[#0B1220]/90 backdrop-blur-xl border-r border-slate-800/80 flex flex-col justify-between h-[calc(100vh-4rem)] sticky top-16 z-20 shrink-0"
    >
      {/* Collapse Toggle Button */}
      <button 
        onClick={() => setCollapsed(!collapsed)}
        className="absolute -right-3 top-6 bg-slate-900 border border-slate-700 text-slate-300 hover:text-cyan-400 p-1 rounded-full shadow-lg z-30 transition-all"
        title={collapsed ? "Expand Sidebar" : "Collapse Sidebar"}
      >
        {collapsed ? <ChevronRight className="w-3.5 h-3.5" /> : <ChevronLeft className="w-3.5 h-3.5" />}
      </button>

      <div className="py-6 px-3 space-y-1 overflow-y-auto overflow-x-hidden">
        {!collapsed && (
          <div className="px-3 mb-4">
            <p className="text-[10px] font-bold text-cyan-400/80 uppercase tracking-widest flex items-center gap-1.5">
              <Shield className="w-3 h-3 text-cyan-400" />
              <span>SOC Analytics Console</span>
            </p>
          </div>
        )}

        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              title={collapsed ? item.name : undefined}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-200 group ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-lg shadow-cyan-950/40'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60'
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0 transition-transform group-hover:scale-110" />
              {!collapsed && (
                <span className="truncate">{item.name}</span>
              )}
            </NavLink>
          );
        })}
      </div>

    </motion.aside>
  );
};

export default Sidebar;
