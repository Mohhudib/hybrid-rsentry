import React, { useState, useCallback } from 'react';
import Sidebar from './components/Sidebar';
import Overview from './pages/Overview';
import AlertsPage from './pages/AlertsPage';
import HostsPage from './pages/HostsPage';
import ReportsPage from './pages/ReportsPage';
import { useWebSocket } from './hooks/useWebSocket';

export default function App() {
  const [page, setPage] = useState('dashboard');
  const [liveAlert, setLiveAlert] = useState(null);

  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'new_alert') setLiveAlert(msg);
  }, []);

  const { connected } = useWebSocket(handleWsMessage);

  const renderPage = () => {
    switch (page) {
      case 'dashboard': return <Overview liveAlert={liveAlert} />;
      case 'alerts':    return <AlertsPage newAlert={liveAlert} />;
      case 'hosts':     return <HostsPage />;
      case 'reports':   return <ReportsPage />;
      default:          return <Overview liveAlert={liveAlert} />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 flex">
      <Sidebar activePage={page} onNavigate={setPage} connected={connected} />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {renderPage()}
      </div>
    </div>
  );
}
