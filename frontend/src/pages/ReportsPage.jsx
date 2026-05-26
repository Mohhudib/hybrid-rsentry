import React, { useEffect, useState, useCallback } from 'react';
import { getAlerts, forensicExport } from '../api/client';
import { format } from 'date-fns';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

// ─── Constants & helpers ────────────────────────────────────────────────
const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-400 text-gray-900',
  LOW: 'bg-blue-400 text-white',
};

const SEV_RGB = {
  CRITICAL: [220, 38, 38],
  HIGH: [234, 88, 12],
  MEDIUM: [202, 138, 4],
  LOW: [37, 99, 235],
};

const EVENT_TYPE_LABEL = {
  CANARY_TOUCHED: 'Canary Touched',
  ENTROPY_SPIKE: 'Entropy Spike',
  PROCESS_ANOMALY: 'Process Anomaly',
  COMBINED_ALERT: 'Combined Alert',
  CONTAINMENT_TRIGGERED: 'Containment Triggered',
  CONTAINMENT_COMPLETE: 'Containment Complete',
  HEARTBEAT: 'Heartbeat',
};

const truncatePath = (p, max = 60) => {
  if (!p) return '—';
  return p.length <= max ? p : '...' + p.slice(-(max - 3));
};

const fmtNum = (n, dp = 2) =>
  (n === null || n === undefined || Number.isNaN(n)) ? '—' : Number(n).toFixed(dp);

// Show first N chars of a host UUID for compact display in tables.
const shortHost = (h, n = 8) => (h ? String(h).slice(0, n) : '—');

// Keys we already render explicitly in the drill-down; everything else gets
// dumped as "More details" so new metadata appears automatically without
// requiring a frontend change.
const KNOWN_DETAIL_KEYS = new Set([
  'sub_type', 'dest', 'original_event', 'lineage_reasons',
  'ancestors', 'sha256', 'combined_score',
]);

async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── Data fetching ──────────────────────────────────────────────────────
async function fetchAlertsWithEvents(params) {
  const q = new URLSearchParams();
  q.set('limit', '500');
  if (params.severity && params.severity !== 'ALL') q.set('severity', params.severity);
  if (params.acknowledged !== undefined) q.set('acknowledged', String(params.acknowledged));
  if (params.dateFrom) q.set('date_from', new Date(params.dateFrom).toISOString());
  if (params.dateTo) q.set('date_to', new Date(params.dateTo + 'T23:59:59').toISOString());
  const res = await fetch(`/api/alerts/with-events?${q.toString()}`);
  if (!res.ok) throw new Error(`Fetch failed: ${res.status} ${res.statusText}`);
  return res.json();
}

// ─── PDF generation ─────────────────────────────────────────────────────
async function exportAsPDF(filterParams) {
  const rich = await fetchAlertsWithEvents(filterParams);

  const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });
  const W = doc.internal.pageSize.width;
  const H = doc.internal.pageSize.height;

  // ── Page 1: Executive summary ──
  doc.setFontSize(18);
  doc.setTextColor(20);
  doc.text('Hybrid R-Sentry — Incident Report', 14, 16);

  doc.setFontSize(10);
  doc.setTextColor(100);
  const now = format(new Date(), 'MMM d yyyy HH:mm:ss');
  const uniqueHosts = new Set(rich.map(a => a.host_id)).size;
  doc.text(`Generated: ${now}`, 14, 22);
  doc.text(`Scope: ${rich.length} alerts in report  •  Hosts affected: ${uniqueHosts}`, 14, 27);

  const filterLine = [
    `Severity: ${filterParams.severity || 'ALL'}`,
    `Status: ${filterParams.ackLabel}`,
    filterParams.dateFrom ? `From: ${filterParams.dateFrom}` : null,
    filterParams.dateTo ? `To: ${filterParams.dateTo}` : null,
  ].filter(Boolean).join('   |   ');
  doc.setFontSize(8);
  doc.setTextColor(140);
  doc.text(`Filters → ${filterLine}`, 14, 32);

  // Stat cards (correctly labeled)
  const total = rich.length;
  const open = rich.filter(a => !a.acknowledged).length;
  const acked = total - open;
  const bySev = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => ({
    sev: s,
    total: rich.filter(a => a.severity === s).length,
    open: rich.filter(a => a.severity === s && !a.acknowledged).length,
  }));

  const cards = [
    { label: 'Total', value: total, color: [60, 60, 60] },
    { label: 'Open', value: open, color: [220, 38, 38] },
    { label: 'Acknowledged', value: acked, color: [22, 163, 74] },
    { label: 'Critical (Open)', value: bySev.find(s => s.sev === 'CRITICAL').open, color: [185, 28, 28] },
    { label: 'High (Open)', value: bySev.find(s => s.sev === 'HIGH').open, color: [234, 88, 12] },
  ];
  const cardW = 50, cardH = 22, cardY = 38;
  cards.forEach((c, i) => {
    const x = 14 + i * (cardW + 4);
    doc.setFillColor(245, 245, 245);
    doc.rect(x, cardY, cardW, cardH, 'F');
    doc.setFillColor(c.color[0], c.color[1], c.color[2]);
    doc.rect(x, cardY, 3, cardH, 'F');
    doc.setFontSize(7);
    doc.setTextColor(110);
    doc.text(c.label.toUpperCase(), x + 6, cardY + 6);
    doc.setFontSize(16);
    doc.setTextColor(c.color[0], c.color[1], c.color[2]);
    doc.text(String(c.value), x + 6, cardY + 16);
  });

  // Severity breakdown table (left)
  autoTable(doc, {
    startY: cardY + cardH + 6,
    head: [['Severity', 'Total', 'Open', 'Acknowledged']],
    body: bySev.map(s => [s.sev, s.total, s.open, s.total - s.open]),
    styles: { fontSize: 9 },
    headStyles: { fillColor: [55, 65, 81] },
    margin: { left: 14 },
    tableWidth: 100,
  });
  const sevEndY = doc.lastAutoTable.finalY;

  // Event type distribution (right)
  const evCounts = {};
  rich.forEach(a => {
    const et = a.event?.event_type || 'UNKNOWN';
    evCounts[et] = (evCounts[et] || 0) + 1;
  });
  autoTable(doc, {
    startY: cardY + cardH + 6,
    head: [['Event Type', 'Count']],
    body: Object.entries(evCounts)
      .sort((a, b) => b[1] - a[1])
      .map(([et, n]) => [EVENT_TYPE_LABEL[et] || et, n]),
    styles: { fontSize: 9 },
    headStyles: { fillColor: [55, 65, 81] },
    margin: { left: 120 },
    tableWidth: 80,
  });
  const evEndY = doc.lastAutoTable.finalY;

  // ── NEW: Hosts Overview ──
  // Aggregate per-host severity counts and last-alert timestamp so the
  // operator can immediately see which endpoint is most affected.
  const byHost = {};
  rich.forEach(a => {
    const h = a.host_id || 'unknown';
    if (!byHost[h]) {
      byHost[h] = {
        total: 0, open: 0,
        CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0,
        last: '',
      };
    }
    byHost[h].total += 1;
    if (byHost[h][a.severity] !== undefined) byHost[h][a.severity] += 1;
    if (!a.acknowledged) byHost[h].open += 1;
    if (a.created_at && a.created_at > byHost[h].last) byHost[h].last = a.created_at;
  });

  const hostsHeadingY = Math.max(sevEndY, evEndY) + 8;
  doc.setFontSize(11);
  doc.setTextColor(20);
  doc.text('Hosts Overview', 14, hostsHeadingY);

  autoTable(doc, {
    startY: hostsHeadingY + 3,
    head: [['Host (short)', 'Total', 'Open', 'CRIT', 'HIGH', 'MED', 'LOW', 'Last Alert']],
    body: Object.entries(byHost)
      .sort((a, b) => b[1].total - a[1].total)
      .map(([h, c]) => [
        shortHost(h),
        c.total, c.open,
        c.CRITICAL, c.HIGH, c.MEDIUM, c.LOW,
        c.last ? format(new Date(c.last), 'MM/dd HH:mm:ss') : '—',
      ]),
    styles: { fontSize: 8, cellPadding: 1.5 },
    headStyles: { fillColor: [55, 65, 81], textColor: 255 },
    alternateRowStyles: { fillColor: [248, 250, 252] },
    columnStyles: {
      0: { font: 'courier', fontStyle: 'bold', cellWidth: 28 },
      1: { halign: 'center', cellWidth: 18 },
      2: { halign: 'center', cellWidth: 18 },
      3: { halign: 'center', cellWidth: 18, textColor: SEV_RGB.CRITICAL, fontStyle: 'bold' },
      4: { halign: 'center', cellWidth: 18, textColor: SEV_RGB.HIGH, fontStyle: 'bold' },
      5: { halign: 'center', cellWidth: 18, textColor: SEV_RGB.MEDIUM },
      6: { halign: 'center', cellWidth: 18, textColor: SEV_RGB.LOW },
      7: { halign: 'center', cellWidth: 40 },
    },
    margin: { left: 14 },
  });

  // ── Main alerts log ──
  doc.addPage();
  doc.setFontSize(14);
  doc.setTextColor(20);
  doc.text('Alerts Log', 14, 16);

  autoTable(doc, {
    startY: 22,
    head: [['Time (UTC)', 'Sev', 'Event Type', 'Host', 'Process', 'File', 'ΔH', 'Lineage', 'Combined', 'Canary', 'Status']],
    body: rich.map(a => {
      const ev = a.event || {};
      const score = ev.details?.combined_score;
      const proc = ev.process_name && ev.process_name !== 'unknown'
        ? `${ev.process_name}[${ev.pid}]` : '—';
      return [
        format(new Date(a.created_at), 'MM/dd HH:mm:ss'),
        a.severity,
        EVENT_TYPE_LABEL[ev.event_type] || ev.event_type || '—',
        shortHost(a.host_id),
        proc,
        truncatePath(ev.file_path, 38),
        fmtNum(ev.entropy_delta, 2),
        fmtNum(ev.lineage_score, 1),
        fmtNum(score, 1),
        ev.canary_hit ? 'YES' : '—',
        a.acknowledged ? 'ACK' : 'PENDING',
      ];
    }),
    styles: { fontSize: 7, cellPadding: 1.5, overflow: 'linebreak' },
    headStyles: { fillColor: [79, 70, 229], textColor: 255, fontSize: 7 },
    alternateRowStyles: { fillColor: [248, 250, 252] },
    columnStyles: {
      3: { font: 'courier' },  // host column — monospace for readability
    },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 1) {
        const c = SEV_RGB[data.cell.raw];
        if (c) {
          data.cell.styles.fillColor = c;
          data.cell.styles.textColor = 255;
          data.cell.styles.fontStyle = 'bold';
        }
      }
    },
    margin: { left: 8, right: 8 },
  });

  // ── Per-incident drill-down for CRITICAL & HIGH ──
  const drill = rich.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH');
  if (drill.length > 0) {
    doc.addPage();
    doc.setFontSize(14);
    doc.setTextColor(20);
    doc.text(`Critical & High Incidents — Drill-down (${drill.length})`, 14, 16);

    let y = 24;
    const CARD_H = 60;   // bumped from 52 to fit extra metadata lines
    drill.forEach((a, idx) => {
      const ev = a.event || {};
      const d = ev.details || {};

      if (y + CARD_H > H - 12) { doc.addPage(); y = 16; }

      const c = SEV_RGB[a.severity] || [100, 100, 100];
      doc.setFillColor(c[0], c[1], c[2]);
      doc.rect(14, y, 4, CARD_H - 4, 'F');
      doc.setFillColor(252, 252, 252);
      doc.rect(18, y, W - 32, CARD_H - 4, 'F');

      // Left column
      doc.setFontSize(10);
      doc.setTextColor(c[0], c[1], c[2]);
      doc.text(`#${idx + 1}  ${a.severity}  •  ${EVENT_TYPE_LABEL[ev.event_type] || ev.event_type}`, 22, y + 6);

      doc.setFontSize(7);
      doc.setTextColor(120);
      doc.text(`Alert ID:  ${a.id}`, 22, y + 11);
      doc.text(`Event ID:  ${a.event_id}`, 22, y + 15);
      doc.text(`Created:   ${format(new Date(a.created_at), 'yyyy-MM-dd HH:mm:ss')} UTC`, 22, y + 19);
      if (a.acknowledged && a.resolved_at) {
        doc.text(`Acked:     ${format(new Date(a.resolved_at), 'yyyy-MM-dd HH:mm:ss')} UTC`, 22, y + 23);
      }

      // Right column: detection metrics — host_id rendered in full + short
      const cx = 150;
      doc.setTextColor(80);
      doc.setFont('courier', 'normal');
      doc.text(`Host:    ${a.host_id || '—'}`, cx, y + 6);
      doc.setFont('helvetica', 'normal');
      doc.text(`Process:         ${ev.process_name || '—'}${ev.pid ? `  [PID ${ev.pid}]` : ''}`, cx, y + 10);
      doc.text(`Entropy delta:   ${fmtNum(ev.entropy_delta, 4)}`, cx, y + 14);
      doc.text(`Lineage score:   ${fmtNum(ev.lineage_score, 2)}`, cx, y + 18);
      doc.text(`Canary hit:      ${ev.canary_hit ? 'YES' : 'no'}`, cx, y + 22);
      doc.text(`Combined score:  ${fmtNum(d.combined_score, 2)}`, cx, y + 26);

      // File path (full)
      doc.setTextColor(50);
      doc.text(`File: ${ev.file_path || '—'}`, 22, y + 28);

      // Event-specific details (existing behavior preserved)
      let yOff = 32;
      if (ev.event_type === 'CANARY_TOUCHED') {
        if (d.sub_type) {
          doc.text(`Action: ${d.sub_type}${d.dest ? `   →   ${d.dest}` : ''}`, 22, y + yOff);
          yOff += 4;
        }
      } else if (ev.event_type === 'ENTROPY_SPIKE') {
        if (d.original_event) {
          doc.text(`File op: ${d.original_event}`, 22, y + yOff);
          yOff += 4;
        }
        if (d.lineage_reasons?.length) {
          doc.text(`Lineage reasons: ${d.lineage_reasons.join(', ')}`, 22, y + yOff);
          yOff += 4;
        }
        if (d.ancestors?.length) {
          doc.text(`Ancestors: ${d.ancestors.slice(0, 3).join(' → ')}`, 22, y + yOff);
          yOff += 4;
        }
      }

      // NEW: Dump any other interesting fields from details so future schema
      // additions show up automatically. Wraps to at most 2 lines.
      const extras = Object.entries(d).filter(([k, v]) => {
        if (KNOWN_DETAIL_KEYS.has(k)) return false;
        if (v === null || v === undefined || v === '') return false;
        if (typeof v === 'object' && !Array.isArray(v)) return false;
        if (Array.isArray(v) && v.length === 0) return false;
        return true;
      });
      if (extras.length > 0) {
        const extraStr = extras
          .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('|') : v}`)
          .join('   ');
        const lines = doc.splitTextToSize(`More: ${extraStr}`, W - 44).slice(0, 2);
        lines.forEach(line => {
          doc.text(line, 22, y + yOff);
          yOff += 4;
        });
      }

      if (d.sha256) {
        doc.setFont('courier', 'normal');
        doc.text(`SHA-256: ${d.sha256}`, 22, y + yOff);
        doc.setFont('helvetica', 'normal');
      }

      y += CARD_H;
    });
  }

  // ── Footer + integrity hash on every page ──
  const contentForHash = JSON.stringify(
    rich.map(a => ({ id: a.id, event_id: a.event_id, created_at: a.created_at, severity: a.severity }))
  );
  const reportHash = await sha256Hex(contentForHash);
  const totalPages = doc.internal.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(6);
    doc.setTextColor(140);
    doc.setFont('courier', 'normal');
    doc.text(`Hybrid R-Sentry  •  SHA-256(content)= ${reportHash}`, 14, H - 6);
    doc.setFont('helvetica', 'normal');
    doc.text(`Page ${i} of ${totalPages}`, W - 24, H - 6);
  }

  doc.save(`rsentry_report_${Date.now()}.pdf`);
}

function exportAllAsJSON(alerts) {
  const blob = new Blob([JSON.stringify(alerts, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `rsentry_report_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Component ──────────────────────────────────────────────────────────
export default function ReportsPage() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(new Set());
  const [exporting, setExporting] = useState(null);
  const [pdfBuilding, setPdfBuilding] = useState(false);
  const [filterSev, setFilterSev] = useState('ALL');
  const [filterAck, setFilterAck] = useState('ALL');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  const fetchAlerts = useCallback(async () => {
    try {
      const { data } = await getAlerts({ limit: 500 });
      setAlerts(data);
    } catch (err) { console.error(err); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchAlerts(); }, [fetchAlerts]);

  const handleExportOne = async (id) => {
    setExporting(id);
    try {
      const { data } = await forensicExport(id);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `forensic_${id.slice(0, 8)}_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) { console.error(err); }
    finally { setExporting(null); }
  };

  const handleExportSelected = async () => {
    for (const id of [...selected]) await handleExportOne(id);
  };

  const handleExportPDF = async () => {
    setPdfBuilding(true);
    try {
      await exportAsPDF({
        severity: filterSev,
        acknowledged: filterAck === 'ACKED' ? true : filterAck === 'PENDING' ? false : undefined,
        ackLabel: filterAck,
        dateFrom,
        dateTo,
      });
    } catch (err) {
      console.error(err);
      alert(`PDF export failed: ${err.message}`);
    } finally {
      setPdfBuilding(false);
    }
  };

  const toggleSelect = (id) => setSelected((prev) => {
    const next = new Set(prev);
    next.has(id) ? next.delete(id) : next.add(id);
    return next;
  });

  const toggleAll = () => setSelected(
    selected.size === filtered.length ? new Set() : new Set(filtered.map(a => a.id))
  );

  const filtered = alerts
    .filter((a) => filterSev === 'ALL' || a.severity === filterSev)
    .filter((a) => {
      if (filterAck === 'PENDING') return !a.acknowledged;
      if (filterAck === 'ACKED') return a.acknowledged;
      return true;
    })
    .filter((a) => {
      if (dateFrom && new Date(a.created_at) < new Date(dateFrom)) return false;
      if (dateTo && new Date(a.created_at) > new Date(dateTo + 'T23:59:59')) return false;
      return true;
    });

  const activeAlerts = alerts.filter(a => !a.acknowledged);
  const activeCritical = activeAlerts.filter(a => a.severity === 'CRITICAL').length;
  const activeHigh = activeAlerts.filter(a => a.severity === 'HIGH').length;

  return (
    <div className="flex-1 overflow-auto p-6">
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h2 className="text-white text-xl font-semibold">Reports</h2>
          <p className="text-gray-500 text-sm">Export forensic data for alerts and incidents</p>
        </div>
        <div className="flex gap-2">
          {selected.size > 0 && (
            <button onClick={handleExportSelected}
              className="px-4 py-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-medium transition-colors">
              Export Selected ({selected.size})
            </button>
          )}
          <button onClick={handleExportPDF} disabled={pdfBuilding}
            className="px-4 py-2 text-sm bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white rounded-lg font-medium transition-colors">
            {pdfBuilding ? 'Building PDF…' : 'Export PDF'}
          </button>
          <button onClick={() => exportAllAsJSON(filtered)}
            className="px-4 py-2 text-sm bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium transition-colors">
            Export All as JSON
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4">
          <p className="text-gray-500 text-xs uppercase tracking-wider">Active Alerts</p>
          <p className="text-2xl font-bold text-white mt-1">{activeAlerts.length}</p>
          <p className="text-gray-600 text-xs mt-0.5">unacknowledged</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4">
          <p className="text-gray-500 text-xs uppercase tracking-wider">Active Critical</p>
          <p className="text-2xl font-bold text-red-400 mt-1">{activeCritical}</p>
          <p className="text-gray-600 text-xs mt-0.5">immediate action</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4">
          <p className="text-gray-500 text-xs uppercase tracking-wider">Active High</p>
          <p className="text-2xl font-bold text-orange-400 mt-1">{activeHigh}</p>
          <p className="text-gray-600 text-xs mt-0.5">investigate now</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-4">
          <p className="text-gray-500 text-xs uppercase tracking-wider">Total (All-Time)</p>
          <p className="text-2xl font-bold text-gray-400 mt-1">{alerts.length}</p>
          <p className="text-gray-600 text-xs mt-0.5">incl. acknowledged</p>
        </div>
      </div>

      <div className="flex items-center gap-3 mb-4 flex-wrap">
        <div className="flex gap-1">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
            <button key={s} onClick={() => setFilterSev(s)}
              className={`px-3 py-1.5 text-xs rounded-lg font-medium transition-all ${filterSev === s ? 'bg-indigo-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}>
              {s}
            </button>
          ))}
        </div>
        <div className="flex gap-1 ml-4">
          {['ALL', 'PENDING', 'ACKED'].map((s) => (
            <button key={s} onClick={() => setFilterAck(s)}
              className={`px-3 py-1.5 text-xs rounded-lg font-medium transition-all ${filterAck === s ? 'bg-gray-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}>
              {s}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 ml-auto">
          <input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)}
            className="bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded-lg border border-gray-700" />
          <span className="text-gray-500 text-xs">to</span>
          <input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)}
            className="bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded-lg border border-gray-700" />
          {(dateFrom || dateTo) && (
            <button onClick={() => { setDateFrom(''); setDateTo(''); }}
              className="text-xs text-gray-500 hover:text-white">Clear</button>
          )}
        </div>
        <p className="text-xs text-gray-500">{filtered.length} alerts</p>
      </div>

      {loading ? (
        <p className="text-gray-400 text-sm">Loading…</p>
      ) : filtered.length === 0 ? (
        <div className="bg-gray-900 rounded-xl p-8 text-center">
          <p className="text-gray-500">No alerts match the current filter.</p>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-4 px-4 py-2 border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
            <input type="checkbox"
              checked={selected.size === filtered.length && filtered.length > 0}
              onChange={toggleAll} className="rounded" />
            <span>Alert ID / Host</span>
            <span>Severity</span>
            <span>Status</span>
            <span>Time</span>
            <span>Export</span>
          </div>
          <div className="divide-y divide-gray-800">
            {filtered.map((alert) => (
              <div key={alert.id}
                className={`grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-4 px-4 py-3 items-center text-sm ${alert.acknowledged ? 'opacity-50' : ''}`}>
                <input type="checkbox" checked={selected.has(alert.id)}
                  onChange={() => toggleSelect(alert.id)} className="rounded" />
                <div className="min-w-0">
                  <p className="text-white font-mono text-xs">{alert.id}</p>
                  <p className="text-gray-500 text-xs mt-0.5">{alert.host_id}</p>
                </div>
                <span className={`text-xs font-bold px-2 py-1 rounded ${SEVERITY_COLORS[alert.severity]}`}>
                  {alert.severity}
                </span>
                <span className={`text-xs ${alert.acknowledged ? 'text-green-500' : 'text-yellow-500'}`}>
                  {alert.acknowledged ? 'ACK' : 'PENDING'}
                </span>
                <span className="text-gray-500 text-xs whitespace-nowrap">
                  {format(new Date(alert.created_at), 'MMM d, HH:mm:ss')}
                </span>
                <button onClick={() => handleExportOne(alert.id)} disabled={exporting === alert.id}
                  className="text-xs bg-gray-800 hover:bg-indigo-700 text-gray-300 hover:text-white px-3 py-1.5 rounded-lg transition-colors whitespace-nowrap">
                  {exporting === alert.id ? 'Exporting…' : 'Export JSON'}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
