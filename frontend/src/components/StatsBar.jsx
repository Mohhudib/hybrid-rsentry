import React, { useEffect, useState } from 'react';
import { getAlerts, getHosts } from '../api/client';

function StatCard({ label, value, color, sub }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4 flex-1 min-w-0">
      <p className="text-gray-500 text-xs uppercase tracking-wider mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      {sub && <p className="text-gray-600 text-xs mt-0.5">{sub}</p>}
    </div>
  );
}

export default function StatsBar() {
  const [stats, setStats] = useState({
    total: '-', critical: '-', high: '-', hosts: '-', contained: '-',
  });

  const fetch = async () => {
    try {
      const [alertsRes, hostsRes] = await Promise.all([
        getAlerts({ limit: 500, acknowledged: false }),
        getHosts({ limit: 100 }),
      ]);
      const alerts = alertsRes.data;
      const hosts = hostsRes.data;
      setStats({
        total: alerts.length,
        critical: alerts.filter((a) => a.severity === 'CRITICAL').length,
        high: alerts.filter((a) => a.severity === 'HIGH').length,
        hosts: hosts.length,
        contained: hosts.filter((h) => h.is_contained).length,
      });
    } catch (_) {}
  };

  useEffect(() => {
    fetch();
    const t = setInterval(fetch, 15000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="flex gap-4 mb-6">
      <StatCard label="Active Alerts" value={stats.total} color="text-white" sub="unacknowledged" />
      <StatCard label="Critical" value={stats.critical} color="text-red-400" sub="needs immediate action" />
      <StatCard label="High" value={stats.high} color="text-orange-400" />
      <StatCard label="Active Hosts" value={stats.hosts} color="text-indigo-400" />
      <StatCard
        label="Contained"
        value={stats.contained}
        color={stats.contained > 0 ? 'text-red-400' : 'text-green-400'}
        sub={stats.contained > 0 ? 'hosts isolated' : 'all hosts free'}
      />
    </div>
  );
}
