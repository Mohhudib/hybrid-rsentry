import React, { useEffect, useState } from 'react';
import { getHosts, getHostRisk, containHost, releaseHost } from '../api/client';
import { RadialBarChart, RadialBar, Tooltip, ResponsiveContainer } from 'recharts';

const RISK_COLOR = (score) => {
  if (score >= 80) return '#ef4444'; // red
  if (score >= 50) return '#f97316'; // orange
  if (score >= 25) return '#eab308'; // yellow
  return '#22c55e'; // green
};

export default function HostRiskPanel() {
  const [hosts, setHosts] = useState([]);
  const [riskMap, setRiskMap] = useState({});
  const [loading, setLoading] = useState(true);

  const fetchAll = async () => {
    try {
      const { data: hostList } = await getHosts({ limit: 20 });
      setHosts(hostList);
      const riskResults = await Promise.allSettled(
        hostList.map((h) => getHostRisk(h.host_id))
      );
      const map = {};
      hostList.forEach((h, i) => {
        if (riskResults[i].status === 'fulfilled') {
          map[h.host_id] = riskResults[i].value.data;
        }
      });
      setRiskMap(map);
    } catch (err) {
      console.error('HostRiskPanel error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleContain = async (hostId, isContained) => {
    try {
      isContained ? await releaseHost(hostId) : await containHost(hostId);
      fetchAll();
    } catch (err) {
      console.error('Containment action failed:', err);
    }
  };

  if (loading) {
    return (
      <div className="bg-gray-900 rounded-xl p-4">
        <p className="text-gray-400 text-sm">Loading hosts...</p>
      </div>
    );
  }

  if (hosts.length === 0) {
    return (
      <div className="bg-gray-900 rounded-xl p-4">
        <h2 className="text-white text-lg font-semibold mb-2">Host Risk Panel</h2>
        <p className="text-gray-500 text-sm italic">No hosts registered yet.</p>
      </div>
    );
  }

  return (
    <div className="bg-gray-900 rounded-xl p-4">
      <h2 className="text-white text-lg font-semibold mb-4">Host Risk Panel</h2>
      <div className="space-y-4">
        {hosts.map((host) => {
          const risk = riskMap[host.host_id];
          const score = risk?.risk_score ?? host.risk_score ?? 0;
          const color = RISK_COLOR(score);

          return (
            <div
              key={host.host_id}
              className="flex items-center gap-4 p-3 rounded-lg border border-gray-700"
              style={{ backgroundColor: '#1e2130' }}
            >
              {/* Radial gauge */}
              <div style={{ width: 64, height: 64 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <RadialBarChart
                    cx="50%" cy="50%"
                    innerRadius="60%" outerRadius="100%"
                    data={[{ value: score, fill: color }]}
                    startAngle={90} endAngle={-270}
                  >
                    <RadialBar dataKey="value" background={{ fill: '#374151' }} />
                  </RadialBarChart>
                </ResponsiveContainer>
              </div>

              {/* Host info */}
              <div className="flex-1 min-w-0">
                <p className="text-white text-sm font-mono truncate">{host.host_id}</p>
                <p className="text-gray-400 text-xs">
                  Risk: <span style={{ color }}>{score.toFixed(0)}</span>/100
                </p>
                {host.is_contained && (
                  <span className="text-xs bg-red-800 text-red-200 px-2 py-0.5 rounded mt-1 inline-block">
                    CONTAINED
                  </span>
                )}
              </div>

              {/* Containment control */}
              <button
                onClick={() => handleContain(host.host_id, host.is_contained)}
                className={`text-xs px-3 py-1.5 rounded font-medium transition-colors ${
                  host.is_contained
                    ? 'bg-green-700 hover:bg-green-600 text-white'
                    : 'bg-red-700 hover:bg-red-600 text-white'
                }`}
              >
                {host.is_contained ? 'Release' : 'Contain'}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
