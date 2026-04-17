import React, { useState, useCallback, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Overview from './pages/Overview';
import AlertsPage from './pages/AlertsPage';
import HostsPage from './pages/HostsPage';
import ReportsPage from './pages/ReportsPage';
import FilesystemPage from './pages/FilesystemPage';
import AIAnalystPage from './pages/AIAnalystPage';
import { useWebSocket } from './hooks/useWebSocket';

const AI_EXPIRY_MS = 4 * 60 * 1000; // 4 minutes
const AI_PENDING_TIMEOUT_MS = 45 * 1000; // 45 seconds — drop pending if no AI result arrives
const AI_TRIGGER_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM']);

export default function App() {
  const [page, setPage] = useState('dashboard');
  const [liveAlert, setLiveAlert] = useState(null);
  const [liveEvent, setLiveEvent] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(true);

  // AI state lifted here so it persists across page navigation
  const [aiAnalyses, setAiAnalyses] = useState([]);
  const [aiHealth, setAiHealth] = useState(null);
  const [aiNewIds, setAiNewIds] = useState(new Set());
  const [aiTimestamps, setAiTimestamps] = useState({});
  // Pending events waiting for AI analysis result (event_id → event info + _addedAt)
  const [aiPendingEvents, setAiPendingEvents] = useState({});

  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'new_alert') setLiveAlert(msg);
    if (msg.type === 'new_event') {
      setLiveEvent(msg);
      // Show pending card immediately for events that will be analyzed
      if (AI_TRIGGER_SEVERITIES.has(msg.severity)) {
        setAiPendingEvents(prev => ({
          ...prev,
          [msg.event_id]: {
            event_id: msg.event_id,
            event_type: msg.event_type,
            severity: msg.severity,
            file_path: msg.file_path,
            process_name: msg.process_name,
            host_id: msg.host_id,
            _addedAt: Date.now(),
          },
        }));
      }
    }

    if (msg.type === 'ai_analysis' && msg.event_id) {
      // Remove from pending — analysis arrived (real or Markov pre-built)
      setAiPendingEvents(prev => {
        const next = { ...prev };
        delete next[msg.event_id];
        return next;
      });
      setAiAnalyses(prev => {
        if (prev.find(a => a.event_id === msg.event_id)) return prev;
        return [msg, ...prev].slice(0, 100);
      });
      setAiNewIds(prev => new Set([...prev, msg.event_id]));
      setAiTimestamps(prev => ({ ...prev, [msg.event_id]: new Date().toISOString() }));
      setTimeout(() => setAiNewIds(prev => {
        const n = new Set(prev); n.delete(msg.event_id); return n;
      }), 10000);
    }

    if (msg.type === 'health_analysis') {
      setAiHealth({ ...msg, timestamp: new Date().toISOString() });
    }
  }, []);

  // Expire AI analyses older than 4 minutes + expire stale pending cards
  useEffect(() => {
    const t = setInterval(() => {
      const cutoff = Date.now() - AI_EXPIRY_MS;
      setAiAnalyses(prev => prev.filter(a => {
        const ts = aiTimestamps[a.event_id];
        return ts ? new Date(ts).getTime() > cutoff : true;
      }));
      // Drop pending events whose AI analysis never arrived (NVIDIA failed silently)
      const pendingCutoff = Date.now() - AI_PENDING_TIMEOUT_MS;
      setAiPendingEvents(prev => {
        const next = { ...prev };
        Object.keys(next).forEach(id => {
          if (next[id]._addedAt < pendingCutoff) delete next[id];
        });
        return next;
      });
    }, 15000);
    return () => clearInterval(t);
  }, [aiTimestamps]);

  const { connected } = useWebSocket(handleWsMessage);

  const renderPage = () => {
    switch (page) {
      case 'dashboard':  return <Overview liveAlert={liveAlert} liveEvent={liveEvent} connected={connected} />;
      case 'alerts':     return <AlertsPage newAlert={liveAlert} />;
      case 'hosts':      return <HostsPage />;
      case 'filesystem': return <FilesystemPage newEvent={liveEvent} connected={connected} />;
      case 'ai':         return (
        <AIAnalystPage
          connected={connected}
          analyses={aiAnalyses}
          health={aiHealth}
          newIds={aiNewIds}
          timestamps={aiTimestamps}
          pendingEvents={aiPendingEvents}
          onHealthUpdate={setAiHealth}
        />
      );
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
