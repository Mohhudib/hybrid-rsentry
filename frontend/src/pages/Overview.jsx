import React from 'react';
import StatsBar from '../components/StatsBar';
import EventChart from '../components/EventChart';
import AlertFeed from '../components/AlertFeed';
import HostRiskPanel from '../components/HostRiskPanel';

export default function Overview({ liveAlert }) {
  return (
    <div className="flex-1 overflow-auto p-6">
      <div className="mb-2">
        <h2 className="text-white text-xl font-semibold">Overview</h2>
        <p className="text-gray-500 text-sm">Real-time ransomware detection status</p>
      </div>

      <div className="mt-4">
        <StatsBar />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 flex flex-col gap-6">
          <EventChart />
          <AlertFeed newAlert={liveAlert} />
        </div>
        <div>
          <HostRiskPanel />
        </div>
      </div>
    </div>
  );
}
