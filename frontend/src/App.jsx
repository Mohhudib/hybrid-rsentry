import React, { useState, useCallback } from 'react';
import AlertFeed from './components/AlertFeed';
import HostRiskPanel from './components/HostRiskPanel';
import EventChart from './components/EventChart';
import ForensicExport from './components/ForensicExport';
import StatusBar from './components/StatusBar';
import { useWebSocket } from './hooks/useWebSocket';

export default function App() {
  const [liveAlert, setLiveAlert] = useState(null);
  const [selectedAlertId, setSelectedAlertId] = useState('');

  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'new_alert') {
      setLiveAlert(msg);
    }
  }, []);

  const { connected } = useWebSocket(handleWsMessage);

  return (
    <div className="min-h-screen bg-gray-950 flex flex-col">
      {/* Top bar */}
      <header className="bg-gray-900 border-b border-gray-800 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-red-600 rounded-lg flex items-center justify-center">
            <span className="text-white text-xs font-bold">RS</span>
          </div>
          <div>
            <h1 className="text-white font-semibold text-sm">Hybrid R-Sentry</h1>
            <p className="text-gray-500 text-xs">Ransomware Detection &amp; Response</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <span>Forensic Export:</span>
            <input
              type="text"
              placeholder="paste alert UUID…"
              value={selectedAlertId}
              onChange={(e) => setSelectedAlertId(e.target.value.trim())}
              className="bg-gray-800 text-gray-300 border border-gray-700 rounded px-2 py-1 text-xs w-56 font-mono"
            />
            <ForensicExport alertId={selectedAlertId || null} />
          </div>
        </div>
      </header>

      <StatusBar connected={connected} />

      {/* Main grid */}
      <main className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Alert Feed — spans 2 cols */}
        <div className="lg:col-span-2 flex flex-col gap-6">
          <EventChart />
          <div className="flex-1">
            <AlertFeed newAlert={liveAlert} />
          </div>
        </div>

        {/* Host Risk Panel */}
        <div>
          <HostRiskPanel />
        </div>
      </main>
    </div>
  );
}
