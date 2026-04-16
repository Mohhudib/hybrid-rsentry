import React, { useState, useCallback } from 'react';
import Sidebar from './components/Sidebar';
import Overview from './pages/Overview';
import AlertsPage from './pages/AlertsPage';
import HostsPage from './pages/HostsPage';
import ReportsPage from './pages/ReportsPage';
import FilesystemPage from './pages/FilesystemPage';
import AIAnalystPage from './pages/AIAnalystPage';
import { useWebSocket } from './hooks/useWebSocket';

export default function App() {
  const [page, setPage] = useState('dashboard');
  const [liveAlert, setLiveAlert] = useState(null);
  const [liveEvent, setLiveEvent] = useState(null);
  const [liveAi, setLiveAi]       = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'new_alert')     setLiveAlert(msg);
    if (msg.type === 'new_event')     setLiveEvent(msg);
    if (msg.type === 'ai_analysis' || msg.type === 'health_analysis') setLiveAi(msg);
  }, []);

  const { connected } = useWebSocket(handleWsMessage);

  const renderPage = () => {
    switch (page) {
      case 'dashboard':  return <Overview liveAlert={liveAlert} liveEvent={liveEvent} connected={connected} />;
      case 'alerts':     return <AlertsPage newAlert={liveAlert} />;
      case 'hosts':      return <HostsPage />;
      case 'filesystem': return <FilesystemPage newEvent={liveEvent} connected={connected} />;
      case 'ai':         return <AIAnalystPage liveAi={liveAi} connected={connected} />;
      case 'reports':    return <ReportsPage />;
      default:           return <Overview liveAlert={liveAlert} liveEvent={liveEvent} connected={connected} />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 flex">
      <Sidebar activePage={page} onNavigate={setPage} connected={connected} collapsed={!sidebarOpen} onToggle={() => setSidebarOpen(o => !o)} />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {renderPage()}
      </div>
    </div>
  );
}
