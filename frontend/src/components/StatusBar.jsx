import React from 'react';

export default function StatusBar({ connected }) {
  return (
    <div className="flex items-center gap-2 px-4 py-1.5 bg-gray-800 text-xs text-gray-400 border-b border-gray-700">
      <span
        className={`w-2 h-2 rounded-full ${connected ? 'bg-green-400' : 'bg-red-500'}`}
      />
      <span>{connected ? 'Live — WebSocket connected' : 'Disconnected — reconnecting…'}</span>
      <span className="ml-auto">Hybrid R-Sentry v1.0.0</span>
    </div>
  );
}
