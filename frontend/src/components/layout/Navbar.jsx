import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Shield, Menu, X, ArrowRight } from 'lucide-react';

const Navbar = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 30) {
        setScrolled(true);
      } else {
        setScrolled(false);
      }
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const navLinks = [
    { name: 'Dashboard', path: '/dashboard' },
    { name: 'System Log Monitor', path: '/upload' },
    { name: 'Detection', path: '/detection' },
    { name: 'SHAP Explainability', path: '/shap' },
    { name: 'Reports', path: '/reports' },
    { name: 'About', path: '/about' },
  ];


  return (
    <nav className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${scrolled ? 'glass-navbar-scrolled h-14' : 'glass-navbar h-16'} flex items-center`}>
      <div className="w-full px-4 sm:px-6 md:px-8 flex items-center justify-between">
        {/* Left: Shield Icon + SMART-LOG Brand + Subtitle aligned with Sidebar */}
        <div 
          onClick={() => navigate('/dashboard')}
          className="flex items-center gap-3 cursor-pointer group shrink-0 pl-1 sm:pl-2"
        >
          <div className="p-2 rounded-xl bg-[#00E5FF]/10 border border-[#00E5FF]/30 text-[#00E5FF] group-hover:scale-105 transition-transform flex items-center justify-center">
            <Shield className="w-5 h-5 animate-pulse" />
          </div>
          <div className="flex flex-col justify-center">
            <div className="flex items-center gap-2">
              <span className="text-lg font-black tracking-wider text-white leading-none">SMART-LOG</span>
              <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-[#00E5FF]/15 text-[#00E5FF] border border-[#00E5FF]/40 font-mono font-bold leading-none">
                SOC
              </span>
            </div>
            <p className="text-[10px] text-[#94A3B8] font-mono leading-tight mt-0.5">Automated Server Security</p>
          </div>
        </div>

        {/* Right: Analyze System Logs Action Button */}
        <div className="flex items-center gap-4 shrink-0">
          <button
            onClick={() => navigate('/upload')}
            className="h-10 px-5 rounded-xl text-xs font-black uppercase tracking-wider bg-gradient-to-r from-[#00E5FF] to-[#2563EB] text-slate-950 hover:scale-105 transition-all glow-cyan flex items-center justify-center gap-2 shrink-0 cursor-pointer"
          >
            <span>Analyze System Logs</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
