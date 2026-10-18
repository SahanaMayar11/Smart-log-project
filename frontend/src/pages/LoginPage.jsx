import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, User, Key, ArrowRight, AlertCircle, Eye, EyeOff, CheckCircle2 } from 'lucide-react';
import { loginAdmin } from '../services/api';
import heroBg from '../assets/hero_bg.jpg';

const LoginPage = () => {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  React.useEffect(() => {
    if (localStorage.getItem('smartlog_token')) {
      navigate('/dashboard');
    }
  }, [navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await loginAdmin(username, password);
      if (res.status === 'success' || res.token) {
        const token = res.token || 'smartlog_admin_sec_token_v1_2026';
        localStorage.setItem('smartlog_token', token);
        navigate('/dashboard');
      } else {
        setError(res.message || 'Invalid admin credentials');
      }
    } catch (err) {
      setError('Connection to backend server failed. Make sure Flask backend is running on port 5000.');
    } finally {
      setLoading(false);
    }
  };

  const handleDemoFill = () => {
    setUsername('admin');
    setPassword('admin123');
  };

  return (
    <div className="min-h-screen bg-[#050816] text-[#F8FAFC] flex items-center justify-center p-6 relative overflow-hidden">
      {/* Full-screen Cybersecurity Background Image */}
      <img
        src={heroBg}
        alt="Cybersecurity Background"
        className="absolute inset-0 w-full h-full object-cover opacity-30 filter brightness-90 contrast-125 mix-blend-luminosity"
      />

      {/* Dark Overlay */}
      <div className="absolute inset-0 bg-gradient-to-b from-[#050816]/85 via-[#050816]/75 to-[#050816]/95 z-0" />

      {/* Glowing Sphere behind card */}
      <div className="absolute w-[500px] h-[500px] bg-[#00E5FF]/15 rounded-full blur-[140px] z-0 pointer-events-none" />

      {/* Centered Glass Login Card (padding: 32px / p-8, max-w-md, input height: h-12) */}
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-md p-8 rounded-2xl glass-panel border border-[#00E5FF]/40 glow-cyan relative z-10 space-y-6"
      >
        <div className="text-center space-y-2">
          <div className="inline-flex p-3.5 rounded-2xl bg-[#00E5FF]/10 border border-[#00E5FF]/30 text-[#00E5FF] mb-1">
            <Shield className="w-8 h-8 animate-pulse" />
          </div>
          <h1 className="text-3xl font-black tracking-wider text-white">SMART-LOG</h1>
          <p className="text-xs text-[#00E5FF] font-mono uppercase tracking-widest font-semibold">Security Operations Center</p>
        </div>

        {error && (
          <div className="p-3.5 rounded-xl bg-red-500/15 border border-red-500/30 text-red-400 text-xs flex items-center gap-2 font-mono">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-[#94A3B8] mb-2 font-mono">Username</label>
            <div className="relative">
              <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-4" />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                className="w-full h-12 pl-10 pr-4 rounded-xl bg-slate-900/90 border border-slate-700 text-white text-sm focus:border-[#00E5FF] focus:outline-none transition-all font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-[#94A3B8] mb-2 font-mono">Password</label>
            <div className="relative">
              <Key className="w-4 h-4 text-slate-500 absolute left-3.5 top-4" />
              <input
                type={showPassword ? "text" : "password"}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                className="w-full h-12 pl-10 pr-10 rounded-xl bg-slate-900/90 border border-slate-700 text-white text-sm focus:border-[#00E5FF] focus:outline-none transition-all font-mono"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3.5 top-4 text-slate-500 hover:text-slate-300"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full h-12 rounded-xl bg-gradient-to-r from-[#00E5FF] to-[#2563EB] text-slate-950 font-black text-sm uppercase tracking-wider flex items-center justify-center gap-2 glow-cyan hover:scale-[1.01] transition-all disabled:opacity-50"
          >
            {loading ? 'Authenticating...' : 'SIGN IN'}
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        <div className="pt-4 border-t border-slate-800 flex justify-between items-center text-xs font-mono">
          <span className="text-[#94A3B8]">Admin Credentials</span>
          <button
            onClick={handleDemoFill}
            className="text-[#00E5FF] hover:underline flex items-center gap-1 font-bold"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            Auto-fill Demo
          </button>
        </div>
      </motion.div>
    </div>
  );
};

export default LoginPage;
