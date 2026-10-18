import React from 'react';
import { 
  Shield, 
  Target, 
  Layers, 
  Cpu, 
  Workflow, 
  Code, 
  Globe, 
  Compass, 
  Users, 
  UserCheck 
} from 'lucide-react';
import GlassCard from '../components/ui/GlassCard';
import { ArchitectureFlowVisual } from '../components/ui/CyberVisuals';

const AboutPage = () => {
  const teamMembers = [
    { name: 'Pallavi R', usn: '4BD23CS128' },
    { name: 'Pradeep Sunkad', usn: '4BD23CS134' },
    { name: 'Sahana O M', usn: '4BD23CS178' },
    { name: 'Pramod P Jain', usn: '4BD24CS409' },
  ];

  const futureScopeList = [
    'Real-Time Log Streaming & Live System Monitoring',
    'Support Multiple Server Log Standards (Nginx, Apache, Kubernetes, Windows Event Logs)',
    'Cloud Native Microservices Deployment (Docker & Kubernetes)',
    'Automated Email & Telegram Incident Alert System',
    'Integration with Advanced Deep Learning Transformer Models'
  ];

  return (
    <div className="container-soc pt-28 pb-16 space-y-8">
      {/* Banner */}
      <div className="bg-[#081225] p-6 rounded-2xl border border-[#00E5FF]/30 glass-panel flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-2xl font-black text-white tracking-wide">About Smart-Log Project</h1>
          <p className="text-xs text-[#94A3B8] mt-1">VTU Major Project Phase-I Presentation | Department of Computer Science & Engineering</p>
        </div>
        <div className="px-4 py-2 rounded-xl bg-[#00E5FF]/10 border border-[#00E5FF]/30 text-[#00E5FF] text-xs font-mono font-bold">
          BIET Davanagere - 577004
        </div>
      </div>

      {/* Grid: Problem Statement & Objectives */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <GlassCard title="1. Problem Statement" icon={Shield}>
          <p className="text-xs text-slate-300 leading-relaxed font-sans">
            Providing explanations and detecting unknown attacks in large volumes of server logs is a major challenge in modern server security systems. Existing anomaly detection methods mainly rely on rule-based or signature-based techniques. These approaches fail to identify unknown or zero-day attacks and function as black-box systems without interpretability.
          </p>
        </GlassCard>

        <GlassCard title="2. Project Objectives" icon={Target}>
          <ul className="text-xs text-slate-300 space-y-2 list-disc list-inside font-sans">
            <li>To preprocess log datasets by handling missing values and selecting relevant attributes.</li>
            <li>To design and develop a behavior-based anomaly detection system using the Isolation Forest algorithm.</li>
            <li>To integrate SHAP (SHapley Additive Explanations) for clear, transparent anomaly reasoning.</li>
            <li>To build an enterprise Security Operations Center (SOC) dashboard.</li>
          </ul>
        </GlassCard>
      </div>

      {/* Grid: Existing vs Proposed System */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <GlassCard title="3. Existing System" icon={Layers}>
          <p className="text-xs text-slate-300 leading-relaxed font-sans">
            Traditional intrusion detection systems rely on static rule sets and predefined signatures. They struggle to detect evolving zero-day cyber threats, generate excessive false positive alerts, and do not analyze temporal user or system behavioral changes.
          </p>
        </GlassCard>

        <GlassCard title="4. Proposed System" icon={Cpu}>
          <p className="text-xs text-slate-300 leading-relaxed font-sans">
            Smart-Log introduces an intelligent unsupervised behavioral anomaly detection framework powered by Isolation Forest. It extracts 8 key behavioral feature metrics from raw syslog streams and utilizes SHAP explainability to provide natural language reasoning for every flagged threat.
          </p>
        </GlassCard>
      </div>

      {/* Architecture Flow Visual Component */}
      <ArchitectureFlowVisual />

      {/* Grid: Technologies & Applications */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <GlassCard title="6. Technologies Used" icon={Code}>
          <div className="grid grid-cols-2 gap-2.5 text-xs font-mono">
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800"><span className="text-[#94A3B8] block text-[10px]">Frontend:</span> React.js + Vite</div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800"><span className="text-[#94A3B8] block text-[10px]">Styling:</span> Tailwind CSS + Framer Motion</div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800"><span className="text-[#94A3B8] block text-[10px]">Backend:</span> Python Flask REST API</div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800"><span className="text-[#94A3B8] block text-[10px]">Machine Learning:</span> Isolation Forest (scikit-learn)</div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800"><span className="text-[#94A3B8] block text-[10px]">Explainable AI:</span> SHAP</div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800"><span className="text-[#94A3B8] block text-[10px]">Database:</span> SQLite (smartlog.db)</div>
          </div>
        </GlassCard>

        <GlassCard title="7. Applications" icon={Globe}>
          <ul className="text-xs text-slate-300 space-y-2 list-disc list-inside font-sans">
            <li>Enterprise Data Center & Web Server Security Operations Centers (SOC).</li>
            <li>Cloud System Administration & Automated Intrusion Monitoring.</li>
            <li>SSH Brute-Force & Unauthorized Access Detection.</li>
            <li>Compliance & Security Incident Response Audit Logging.</li>
          </ul>
        </GlassCard>
      </div>

      {/* Future Scope */}
      <GlassCard title="8. Future Scope" icon={Compass}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-sans">
          {futureScopeList.map((item, idx) => (
            <div key={idx} className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center gap-2.5 text-slate-300">
              <span className="w-2 h-2 rounded-full bg-[#00E5FF] shrink-0" />
              <span>{item}</span>
            </div>
          ))}
        </div>
      </GlassCard>

      {/* Grid: Team Members & Guide Details */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <GlassCard title="9. Project Associates (Team Members)" icon={Users}>
          <div className="space-y-2.5">
            {teamMembers.map((m) => (
              <div key={m.usn} className="flex justify-between items-center p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 text-xs">
                <span className="font-semibold text-white">{m.name}</span>
                <span className="font-mono text-[#00E5FF] font-bold">{m.usn}</span>
              </div>
            ))}
          </div>
        </GlassCard>

        <GlassCard title="10. Project Guide & Leadership" icon={UserCheck}>
          <div className="space-y-3 text-xs font-sans">
            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-[10px] text-[#94A3B8] uppercase tracking-wider block font-mono">Project Guide</span>
              <p className="font-bold text-white text-sm mt-0.5">Prof. Archana T Chawhan <span className="text-xs text-slate-400 font-normal">M.Tech.</span></p>
              <p className="text-[#00E5FF] font-mono text-[11px]">Assistant Professor, Dept. of CS&E</p>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800">
              <span className="text-[10px] text-[#94A3B8] uppercase tracking-wider block font-mono">Department & Institution</span>
              <p className="font-semibold text-white">Department of Computer Science & Engineering</p>
              <p className="text-slate-400 text-[11px]">Bapuji Institute of Engineering & Technology, Davanagere - 577004</p>
            </div>
          </div>
        </GlassCard>
      </div>
    </div>
  );
};

export default AboutPage;
