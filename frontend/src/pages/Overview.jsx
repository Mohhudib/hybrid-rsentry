import React from 'react';
import StatsBar from '../components/StatsBar';
import EventChart from '../components/EventChart';
import AlertFeed from '../components/AlertFeed';
import HostRiskPanel from '../components/HostRiskPanel';
import TacticalResponseLog from '../components/TacticalResponseLog';

export default function Overview({ liveAlert, liveEvent, connected }) {
  return (
    <div className="flex-1 overflow-auto p-6">
      {/* Header with live indicator */}
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-white text-xl font-semibold">Overview</h2>
          <p className="text-gray-500 text-sm">Real-time ransomware detection status</p>
        </div>
        <div className={`flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-medium ${
          connected
            ? 'bg-green-900/30 border-green-700 text-green-400'
            : 'bg-red-900/30 border-red-800 text-red-400'
        }`}>
          <span className={`w-2.5 h-2.5 rounded-full ${connected ? 'bg-green-400 animate-pulse' : 'bg-red-500'}`} />
          {connected ? 'LIVE' : 'DISCONNECTED'}
        </div>
      </div>

      <StatsBar liveAlert={liveAlert} />

      {/* Event chart — full width */}
      <div className="mb-6">
        <EventChart />
      </div>

      {/* 3-col grid: Tactical | Alerts | Hosts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6" style={{ minHeight: 420 }}>
        <div className="overflow-hidden" style={{ maxHeight: 560 }}>
          <TacticalResponseLog liveEvent={liveEvent} />
        </div>
        <div className="overflow-hidden" style={{ maxHeight: 560 }}>
          <AlertFeed newAlert={liveAlert} />
        </div>
        <div>
          <HostRiskPanel />
        </div>
      </div>
    </div>
  );
}
