import React, { useEffect, useState } from 'react';
import { getHosts, getHostRisk, containHost, releaseHost } from '../api/client';
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

export default function HostsPage() {
  const [hosts, setHosts] = useState([]);
  const [riskMap, setRiskMap] = useState({});
  const [loading, setLoading] = useState(true);

  const fetchAll = async () => {
    try {
      const { data: hostList } = await getHosts({ limit: 50 });
      setHosts(hostList);
      const results = await Promise.allSettled(hostList.map((h) => getHostRisk(h.host_id)));
      const map = {};
      hostList.forEach((h, i) => {
        if (results[i].status === 'fulfilled') map[h.host_id] = results[i].value.data;
      });
      setRiskMap(map);
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    fetchAll();
    const t = setInterval(fetchAll, 15000);
    return () => clearInterval(t);
  }, []);

  const handleContain = async (hostId, isContained) => {
    try {
      isContained ? await releaseHost(hostId) : await containHost(hostId);
      fetchAll();
    } catch (err) { console.error(err); }
  };

  return (
    <div className="flex-1 overflow-auto p-6">
      <div className="mb-6">
        <h2 className="text-white text-xl font-semibold">Hosts</h2>
        <p className="text-gray-500 text-sm">Monitored endpoints and risk status</p>
      </div>

      {loading ? (
        <p className="text-gray-400 text-sm">Loading hosts…</p>
      ) : hosts.length === 0 ? (
        <div className="bg-gray-900 rounded-xl p-8 text-center">
          <p className="text-gray-500">No hosts registered yet. Start the agent to register a host.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {hosts.map((host) => {
            const risk = riskMap[host.host_id];
            const score = risk?.risk_score ?? host.risk_score ?? 0;
            const color = RISK_COLOR(score);
            const { label, cls } = RISK_LABEL(score);

            return (
              <div
                key={host.host_id}
                className={`bg-gray-900 border rounded-xl p-5 ${host.is_contained ? 'border-red-700' : 'border-gray-800'}`}
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="min-w-0">
                    <p className="text-white font-mono text-sm font-semibold truncate">{host.host_id}</p>
                    {host.is_contained && (
                      <span className="inline-block mt-1 text-xs bg-red-900 text-red-300 px-2 py-0.5 rounded">
                        CONTAINED
                      </span>
                    )}
                  </div>
                  <span className={`text-xs font-bold ${cls}`}>{label}</span>
                </div>

                <div className="flex items-center gap-4">
                  <div style={{ width: 80, height: 80 }}>
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
                  <div className="flex-1">
                    <p className="text-gray-500 text-xs">Risk Score</p>
                    <p className="text-3xl font-bold" style={{ color }}>{score.toFixed(0)}</p>
                    <p className="text-gray-600 text-xs">out of 100</p>
                  </div>
                </div>

                <div className="mt-4 grid grid-cols-2 gap-2 text-xs text-gray-500 border-t border-gray-800 pt-3">
                  <div>
                    <p className="text-gray-600">Events</p>
                    <p className="text-white">{risk?.event_count ?? '—'}</p>
                  </div>
                  <div>
                    <p className="text-gray-600">Alerts</p>
                    <p className="text-white">{risk?.alert_count ?? '—'}</p>
                  </div>
                </div>

                <button
                  onClick={() => handleContain(host.host_id, host.is_contained)}
                  className={`mt-4 w-full text-xs py-2 rounded-lg font-medium transition-colors ${
                    host.is_contained
                      ? 'bg-green-800 hover:bg-green-700 text-green-200'
                      : 'bg-red-800 hover:bg-red-700 text-red-200'
                  }`}
                >
                  {host.is_contained ? 'Release Host' : 'Contain Host'}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
