import React from 'react';
import StatsBar from '../components/StatsBar';
import EventChart from '../components/EventChart';
import AlertFeed from '../components/AlertFeed';
import HostRiskPanel from '../components/HostRiskPanel';
import FileSystemTree from '../components/FileSystemTree';

export default function Overview({ liveAlert, connected }) {
  return (
    <div className="flex-1 overflow-auto p-6">
      {/* Page header with live indicator */}
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

      <StatsBar />

      {/* Main grid: tree left, chart+alerts center, hosts right */}
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        {/* Filesystem tree — 1 col */}
        <div className="xl:col-span-1 min-h-96" style={{ maxHeight: '75vh' }}>
          <FileSystemTree newEvent={liveAlert} />
        </div>

        {/* Chart + alert feed — 2 cols */}
        <div className="xl:col-span-2 flex flex-col gap-6">
          <EventChart />
          <AlertFeed newAlert={liveAlert} />
        </div>

        {/* Host risk — 1 col */}
        <div className="xl:col-span-1">
          <HostRiskPanel />
        </div>
      </div>
    </div>
  );
}
