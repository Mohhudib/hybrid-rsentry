import React, { useState, useCallback, useEffect, useRef } from 'react';
import TopBar from './components/TopBar';
import StatusBar from './components/StatusBar';
import Overview from './pages/Overview';
import AlertsPage from './pages/AlertsPage';
import HostsPage from './pages/HostsPage';
import ReportsPage from './pages/ReportsPage';
import FilesystemPage from './pages/FilesystemPage';
import AIAnalystPage from './pages/AIAnalystPage';
import ExceptionsPage from './pages/ExceptionsPage';
import { useWebSocket } from './hooks/useWebSocket';
import api from './api/client';

const AI_EXPIRY_MS = 4 * 60 * 1000;
const AI_PENDING_TIMEOUT_MS = 45 * 1000;
const AI_TRIGGER_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM']);

function _beep() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.type = 'sine';
    osc.frequency.setValueAtTime(880, ctx.currentTime);
    gain.gain.setValueAtTime(0.3, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.4);
  } catch (_) {}
}

export default function App() {
  const [page, setPage] = useState('dashboard');
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem('rsentry-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    return saved;
  });

  const toggleTheme = useCallback(() => {
    setTheme(prev => {
      const next = prev === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('rsentry-theme', next);
      return next;
    });
  }, []);
  const [alertBadgeCount, setAlertBadgeCount] = useState(0);
  const [liveAlert, setLiveAlert] = useState(null);
  const [liveEvent, setLiveEvent] = useState(null);

  // Seed the badge with the real unacknowledged count on mount
  useEffect(() => {
    api.get('/api/alerts/counts')
      .then(r => setAlertBadgeCount(r.data.TOTAL ?? 0))
      .catch(() => {});
  }, []);

  // AI state lifted here so it persists across page navigation
  const [aiAnalyses, setAiAnalyses] = useState([]);
  const [aiHealth, setAiHealth] = useState(null);
  const [aiNewIds, setAiNewIds] = useState(new Set());
  const [aiTimestamps, setAiTimestamps] = useState({});
  // Ref mirror of aiTimestamps — lets the expiry interval read current values
  // without being listed as a dependency (avoids restarting the interval every analysis)
  const aiTimestampsRef = useRef({});
  const [aiPendingEvents, setAiPendingEvents] = useState({});

  // Latest AI result — passed to AlertsPage so it can react immediately
  const [latestAiResult, setLatestAiResult] = useState(null);

  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'new_alert') {
      setLiveAlert(msg);
      setAlertBadgeCount(n => n + 1);
      if (msg.severity === 'CRITICAL') _beep();
    }
    if (msg.type === 'new_event') {
      setLiveEvent(msg);
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

    if ((msg.type === 'ai_analysis' || msg.type === 'ai_analysis_update') && msg.event_id) {
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
      const ts = new Date().toISOString();
      aiTimestampsRef.current[msg.event_id] = ts;
      setAiTimestamps(prev => ({ ...prev, [msg.event_id]: ts }));
      // Notify AlertsPage of the new result so it can refresh immediately
      setLatestAiResult({ ...msg, _receivedAt: Date.now() });
      setTimeout(() => setAiNewIds(prev => {
        const n = new Set(prev); n.delete(msg.event_id); return n;
      }), 10000);
    }

    if (msg.type === 'health_analysis') {
      setAiHealth({ ...msg, timestamp: new Date().toISOString() });
    }
  }, []);

  // Expire AI analyses older than 4 minutes + expire stale pending cards.
  // Uses aiTimestampsRef so the interval is created once and never restarted.
  useEffect(() => {
    const t = setInterval(() => {
      const cutoff = Date.now() - AI_EXPIRY_MS;
      setAiAnalyses(prev => prev.filter(a => {
        const ts = aiTimestampsRef.current[a.event_id];
        return ts ? new Date(ts).getTime() > cutoff : true;
      }));
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
  }, []);

  const { connected } = useWebSocket(handleWsMessage);

  const renderPage = () => {
    switch (page) {
      case 'dashboard':  return <Overview liveAlert={liveAlert} liveEvent={liveEvent} connected={connected} />;
      case 'alerts':     return <AlertsPage newAlert={liveAlert} liveAiResult={latestAiResult} liveEvent={liveEvent} />;
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
      case 'exceptions': return <ExceptionsPage />;
      default:           return <Overview liveAlert={liveAlert} liveEvent={liveEvent} connected={connected} />;
    }
  };

  const handleNavigate = useCallback((p) => {
    setPage(p);
    if (p === 'alerts') setAlertBadgeCount(0);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', background: 'var(--bg)', overflow: 'hidden' }}>
      <TopBar activePage={page} onNavigate={handleNavigate} connected={connected} alertCount={alertBadgeCount} theme={theme} onThemeToggle={toggleTheme} />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' }}>
        {renderPage()}
      </div>
      <StatusBar connected={connected} />
    </div>
  );
}
