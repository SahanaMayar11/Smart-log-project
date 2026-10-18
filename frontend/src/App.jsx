import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';

// Layout & Background
import Navbar from './components/layout/Navbar';
import Sidebar from './components/layout/Sidebar';
import Footer from './components/layout/Footer';
import CyberBackground from './components/ui/CyberBackground';

// Pages
import LandingPage from './pages/LandingPage';
import DashboardPage from './pages/DashboardPage';
import UploadLogsPage from './pages/UploadLogsPage';
import LogAnalysisPage from './pages/LogAnalysisPage';
import BehavioralFeaturePage from './pages/BehavioralFeaturePage';
import AnomalyDetectionPage from './pages/AnomalyDetectionPage';
import ShapPage from './pages/ShapPage';
import ReportsPage from './pages/ReportsPage';
import AboutPage from './pages/AboutPage';


// Layout Container Wrapper for Pages
const MainLayout = ({ children }) => {
  return (
    <div className="min-h-screen bg-[#070B14] text-slate-100 flex flex-col justify-between relative selection:bg-cyan-500/30 selection:text-cyan-300">
      <CyberBackground />
      <Navbar />
      <div className="flex flex-1 relative z-10">
        <Sidebar />
        <main className="flex-1 p-6 md:p-8 overflow-y-auto max-w-7xl">
          {children}
        </main>
      </div>
      <Footer />
    </div>
  );
};

function App() {
  return (
    <Router>
      <Routes>
        {/* App Start: Root route opens dashboard directly */}
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/login" element={<Navigate to="/dashboard" replace />} />
        <Route path="/landing" element={<LandingPage />} />

        {/* Dashboard Routes */}
        <Route path="/dashboard" element={<MainLayout><DashboardPage /></MainLayout>} />
        <Route path="/upload" element={<MainLayout><UploadLogsPage /></MainLayout>} />
        <Route path="/analysis" element={<MainLayout><LogAnalysisPage /></MainLayout>} />

        <Route path="/features" element={<MainLayout><BehavioralFeaturePage /></MainLayout>} />
        <Route path="/detection" element={<MainLayout><AnomalyDetectionPage /></MainLayout>} />
        <Route path="/shap" element={<MainLayout><ShapPage /></MainLayout>} />
        <Route path="/reports" element={<MainLayout><ReportsPage /></MainLayout>} />
        <Route path="/about" element={<MainLayout><AboutPage /></MainLayout>} />

        {/* Fallback route */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
