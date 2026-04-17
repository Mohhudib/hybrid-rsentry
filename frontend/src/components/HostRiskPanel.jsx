import React, { useEffect, useState } from 'react';
import { getHosts, getHostRisk } from '../api/client';
import { RadialBarChart, RadialBar, ResponsiveContainer } from 'recharts';

const RISK_COLOR = (score) => {
  if (score >= 80) return '#ef4444';
  if (score >= 50) return '#f97316';
  if (score >= 25) return '#eab308';
  return '#22c55e';
};

const RISK_LABEL = (score) => {
  if (score >= 80) return { label: 'CRITICAL', cls: 'text-red-400' };
  if (score >= 50) return { label: 'HIGH', cls: 'text-orange-400' };
  if (score >= 25) return { label: 'MEDIUM', cls: 'text-yellow-400' };
  return { label: 'LOW', cls: 'text-green-400' };
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

  if (loading) {
    return (
      <div className="bg-gray-900 rounded-xl p-4 h-full">
        <p className="text-gray-400 text-sm">Loading hosts…</p>
      </div>
    );
  }

  if (hosts.length === 0) {
    return (
      <div className="bg-gray-900 rounded-xl p-4 h-full">
        <h2 className="text-white text-base font-semibold mb-2">Host Risk</h2>
        <p className="text-gray-500 text-sm italic">No hosts registered yet.</p>
      </div>
    );
  }

  return (
    <div className="bg-gray-900 rounded-xl p-4 h-full overflow-y-auto">
      <h2 className="text-white text-base font-semibold mb-3">Host Risk</h2>
      <div className="space-y-3">
        {hosts.map((host) => {
          const risk = riskMap[host.host_id];
          const score = risk?.risk_score ?? host.risk_score ?? 0;
          const color = RISK_COLOR(score);
          const { label, cls } = RISK_LABEL(score);

          return (
            <div
              key={host.host_id}
              className={`flex items-center gap-3 p-3 rounded-lg border ${
                host.is_contained ? 'border-red-800 bg-red-950/20' : 'border-gray-700'
              }`}
              style={{ backgroundColor: host.is_contained ? undefined : '#1e2130' }}
            >
              {/* Radial gauge */}
              <div style={{ width: 52, height: 52, flexShrink: 0 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <RadialBarChart
                    cx="50%" cy="50%"
                    innerRadius="55%" outerRadius="100%"
                    data={[{ value: score, fill: color }]}
                    startAngle={90} endAngle={-270}
                  >
                    <RadialBar dataKey="value" background={{ fill: '#374151' }} />
                  </RadialBarChart>
                </ResponsiveContainer>
              </div>

              {/* Host info */}
              <div className="flex-1 min-w-0">
                <p className="text-white text-xs font-mono truncate">{host.host_id}</p>
                <p className={`text-xs font-bold ${cls}`}>{label}</p>
                <p className="text-gray-500 text-xs">
                  <span style={{ color }}>{score.toFixed(0)}</span>
                  <span className="text-gray-600">/100</span>
                </p>
                {host.is_contained && (
                  <span className="text-[10px] bg-red-900 text-red-300 px-1.5 py-0.5 rounded mt-0.5 inline-block">
                    CONTAINED
                  </span>
                )}
              </div>

              {/* Alert / event counts */}
              <div className="text-right shrink-0">
                <p className="text-gray-500 text-[10px]">Alerts</p>
                <p className="text-white text-sm font-bold">{risk?.alert_count ?? '—'}</p>
              </div>
            </div>
          );
        })}
      </div>
      <p className="text-gray-700 text-xs mt-3 text-center">
        Manage hosts → <span className="text-gray-500">Hosts page</span>
      </p>
    </div>
  );
}
