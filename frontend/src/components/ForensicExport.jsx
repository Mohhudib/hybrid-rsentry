import React, { useState } from 'react';
import { forensicExport } from '../api/client';

export default function ForensicExport({ alertId }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleExport = async () => {
    if (!alertId) return;
    setLoading(true);
    setError(null);
    try {
      const { data } = await forensicExport(alertId);
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `forensic_${alertId.slice(0, 8)}_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.response?.data?.detail || 'Export failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="inline-flex flex-col items-start gap-1">
      <button
        onClick={handleExport}
        disabled={loading || !alertId}
        className={`text-xs px-3 py-1.5 rounded font-medium transition-colors ${
          alertId
            ? 'bg-indigo-600 hover:bg-indigo-500 text-white'
            : 'bg-gray-700 text-gray-500 cursor-not-allowed'
        }`}
      >
        {loading ? 'Exporting…' : 'Export JSON'}
      </button>
      {error && <p className="text-red-400 text-xs">{error}</p>}
    </div>
  );
}
