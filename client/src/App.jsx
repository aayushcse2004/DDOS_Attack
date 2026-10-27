import React, { useState } from 'react';
import { SecurityProvider } from './context/SecurityContext';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { Toast } from './components/Toast';

import { Dashboard } from './pages/Dashboard';
import { Traffic } from './pages/Traffic';
import { Alerts } from './pages/Alerts';
import { Incidents } from './pages/Incidents';
import { Analytics } from './pages/Analytics';
import { Mitigation } from './pages/Mitigation';
import { HowItWorks } from './pages/HowItWorks';
import { About } from './pages/About';

export function AppContent() {
  const [activeTab, setActiveTab] = useState('dashboard');

  const renderActivePage = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard setActiveTab={setActiveTab} />;
      case 'traffic':
        return <Traffic />;
      case 'alerts':
        return <Alerts />;
      case 'incidents':
        return <Incidents />;
      case 'analytics':
        return <Analytics />;
      case 'mitigation':
        return <Mitigation />;
      case 'how-it-works':
        return <HowItWorks />;
      case 'about':
        return <About />;
      default:
        return <Dashboard setActiveTab={setActiveTab} />;
    }
  };

  return (
    <div className="min-h-screen flex flex-col lg:flex-row bg-[#080C14] text-slate-100">
      
      {/* Fixed/Responsive Sidebar */}
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <Header />

        <main className="flex-1 p-4 lg:p-8 max-w-7xl w-full mx-auto">
          {renderActivePage()}
        </main>
      </div>

      {/* Floating Toast Alerts */}
      <Toast />
    </div>
  );
}

export default function App() {
  return (
    <SecurityProvider>
      <AppContent />
    </SecurityProvider>
  );
}
