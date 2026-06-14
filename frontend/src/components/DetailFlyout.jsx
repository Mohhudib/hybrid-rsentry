import React, { useEffect, useState, useCallback } from 'react';
import { acknowledgeAlert, analyzeAlert, containHost, getAlertEvidence, getHost } from '../api/client';
import FileSystemGraph from './FileSystemGraph';
import { RULE_NAME, MITRE } from '../constants/eventTypes';

const SEV_COLOR = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)' };
const SEV_BG    = { CRITICAL: 'var(--crit-bg)', HIGH: 'var(--high-bg)', MEDIUM: 'var(--med-bg)', LOW: 'var(--low-bg)' };

function KV({ label, value, isLink }) {
  return (
    <>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 11.5, color: 'var(--muted)' }}>{label}</span>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 11.5, color: isLink ? 'var(--accent)' : 'var(--text)', wordBreak: 'break-all' }}>{value || '—'}</span>
    </>
  );
}

function Section({ icon, title, children }) {
  return (
    <div style={{ borderBottom: '1px solid var(--border-soft)', padding: '13px 16px' }}>
      <div style={{ fontSize: 11, color: 'var(--muted)', letterSpacing: '0.04em', textTransform: 'uppercase', marginBottom: 11, display: 'flex', alignItems: 'center', gap: 7 }}>
        <i className={`fa-solid ${icon}`} style={{ fontSize: 10 }} />
        {title}
      </div>
      {children}
    </div>
  );
}

export default function DetailFlyout({ alert, liveEvent, liveAiResult, onClose, onRefresh }) {
  const [evidence, setEvidence] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [containing, setContaining] = useState(false);
  const [isContained, setIsContained] = useState(false);
  const [acking, setAcking] = useState(false);
  const [fsExpanded, setFsExpanded] = useState(false);
  const [aiResult, setAiResult] = useState(null);

  useEffect(() => {
    if (!alert) { setEvidence(null); setIsContained(false); setAiResult(null); return; }
    setEvidence(null);
    setIsContained(false);
    setAiResult(null);
    setAnalyzing(false);
    const controller = new AbortController();
    getAlertEvidence(alert.id, controller.signal)
      .then(r => setEvidence(r.data))
      .catch(err => { if (!controller.signal.aborted) setEvidence([]); });
    getHost(alert.host_id, controller.signal)
      .then(r => { if (!controller.signal.aborted) setIsContained(r.data.is_contained); })
      .catch(() => {});
    return () => controller.abort();
  }, [alert?.id]);

  // Match incoming WebSocket AI result to this alert
  useEffect(() => {
    if (!liveAiResult || !alert || liveAiResult.risk_level === 'PENDING') return;
    const matchesEvent = liveAiResult.event_id && liveAiResult.event_id === String(alert.event_id);
    const matchesAlert = liveAiResult.alert_id && liveAiResult.alert_id === String(alert.id);
    if (matchesEvent || matchesAlert) {
      setAiResult(liveAiResult);
      setAnalyzing(false);
    }
  }, [liveAiResult, alert?.id, alert?.event_id]);

  if (!alert) {
    return (
      <aside style={{ width: 400, flexShrink: 0, background: 'var(--panel)', borderLeft: '1px solid var(--border)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--muted)', fontSize: 13, textAlign: 'center', padding: 30 }}>
        <i className="fa-regular fa-hand-pointer" style={{ fontSize: 26, display: 'block', marginBottom: 12, color: 'var(--faint)' }} />
        Select an alert to inspect
        <span style={{ fontSize: 11, display: 'block', marginTop: 4 }}>filesystem tree, AI analysis &amp; raw event</span>
      </aside>
    );
  }

  const ev = evidence?.[0] || null;
  const filePath  = ev?.file_path || null;
  const proc      = ev?.process_name || alert.process_name || null;
  const techList  = MITRE[ev?.event_type || ''] || [];
  const ruleName  = RULE_NAME[ev?.event_type || ''] || 'Detection Alert';
  const ai        = aiResult || alert.ai_analysis || null;

  async function handleAck() {
    setAcking(true);
    try { await acknowledgeAlert(alert.id); onRefresh?.(); } finally { setAcking(false); }
  }
  async function handleAnalyze() {
    setAnalyzing(true);
    try {
      await analyzeAlert(alert.id);
      // spinner stays until liveAiResult arrives via WebSocket
    } catch {
      setAnalyzing(false);
    }
  }
  async function handleContain() {
    setContaining(true);
    try {
      await containHost(alert.host_id);
      setIsContained(true);
      onRefresh?.();
    } catch (err) {
      console.error('Containment failed:', err.response?.data?.detail || err.message);
    } finally {
      setContaining(false);
    }
  }

  const rawJson = JSON.stringify({
    alert_id: alert.id,
    host_id: alert.host_id,
    severity: alert.severity,
    created_at: alert.created_at,
    acknowledged: alert.acknowledged,
    ...(ev ? {
      event_type: ev.event_type,
      file_path: ev.file_path,
      entropy_delta: ev.entropy_delta,
      canary_hit: ev.canary_hit,
      process_name: ev.process_name,
      details: ev.details,
    } : {}),
    ai_analysis: ai,
  }, null, 2);

  return (
    <aside style={{ width: 400, flexShrink: 0, background: 'var(--panel)', borderLeft: '1px solid var(--border)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ padding: '14px 16px 12px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontFamily: 'var(--mono)', fontSize: 10.5, padding: '2px 8px', borderRadius: 4, fontWeight: 500, background: SEV_BG[alert.severity], color: SEV_COLOR[alert.severity] }}>
            {alert.severity}
          </span>
          <span style={{ fontSize: 11, display: 'inline-flex', alignItems: 'center', gap: 6, fontFamily: 'var(--mono)', color: alert.acknowledged ? 'var(--muted)' : 'var(--text)' }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: alert.acknowledged ? 'var(--muted)' : 'var(--crit)', display: 'inline-block' }} />
            {alert.acknowledged ? 'Acknowledged' : 'Open'}
          </span>
          <button onClick={onClose} style={{ marginLeft: 'auto', width: 26, height: 26, display: 'grid', placeItems: 'center', borderRadius: 5, cursor: 'pointer', color: 'var(--muted)', border: '1px solid transparent', background: 'transparent' }}
            onMouseEnter={e => { e.currentTarget.style.background = 'var(--panel-2)'; e.currentTarget.style.color = 'var(--text)'; e.currentTarget.style.borderColor = 'var(--border)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--muted)'; e.currentTarget.style.borderColor = 'transparent'; }}>
            <i className="fa-solid fa-xmark" />
          </button>
        </div>
        <div style={{ fontSize: 14, fontWeight: 600, marginTop: 9, lineHeight: 1.35, letterSpacing: '-0.01em', color: 'var(--text)' }}>{ruleName}</div>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--muted)', marginTop: 5 }}>
          {alert.id} · detected {new Date(alert.created_at).toLocaleString()}
        </div>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: 8, padding: '12px 16px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        <button
          className={`siem-dt-btn ${isContained ? '' : 'danger'}`}
          onClick={handleContain}
          disabled={containing || isContained}
        >
          <i className="fa-solid fa-plug-circle-xmark" style={{ fontSize: 11 }} />
          {isContained ? 'Isolated ✓' : containing ? 'Isolating…' : 'Isolate host'}
        </button>
        <button className="siem-dt-btn" onClick={handleAnalyze} disabled={analyzing}>
          <i className="fa-solid fa-brain" style={{ fontSize: 11 }} />
          {analyzing ? 'Analyzing…' : 'AI Analyze'}
        </button>
        <button
          className="siem-dt-btn"
          onClick={!alert.acknowledged ? handleAck : undefined}
          disabled={acking || alert.acknowledged}
          style={alert.acknowledged ? { opacity: 0.5, cursor: 'default' } : {}}
        >
          <i className={`fa-solid ${alert.acknowledged ? 'fa-check-double' : 'fa-check'}`} style={{ fontSize: 11 }} />
          {alert.acknowledged ? 'Acknowledged' : acking ? '…' : 'ACK'}
        </button>
      </div>

      {/* Scrollable body */}
      <div style={{ flex: 1, overflowY: 'auto' }}>

        {/* Summary */}
        <Section icon="fa-circle-info" title="Summary">
          {analyzing && !ai && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--accent)', fontSize: 12, marginBottom: 8 }}>
              <div style={{ width: 12, height: 12, borderRadius: '50%', border: '2px solid var(--accent)', borderTopColor: 'transparent', animation: 'spin 0.8s linear infinite' }} />
              AI analysis in progress…
            </div>
          )}
          <div style={{ fontSize: 12.5, lineHeight: 1.6, color: 'var(--text-2)' }}>
            {ai?.behavior_summary || ai?.summary || (ev ? `${ev.event_type} detected on ${alert.host_id}` : 'No summary available.')}
          </div>
          {ai?.risk_level && (
            <div style={{ marginTop: 8, fontSize: 11, fontFamily: 'var(--mono)', color: SEV_COLOR[ai.risk_level] || 'var(--text-2)' }}>
              AI Risk: {ai.risk_level}
            </div>
          )}
          {ai?.recommendations?.length > 0 && (
            <ul style={{ marginTop: 8, paddingLeft: 16, fontSize: 11.5, color: 'var(--text-2)', lineHeight: 1.7 }}>
              {ai.recommendations.slice(0, 3).map((r, i) => <li key={i}>{r}</li>)}
            </ul>
          )}
        </Section>

        {/* Entity */}
        <Section icon="fa-server" title="Entity">
          <div style={{ display: 'grid', gridTemplateColumns: '116px 1fr', gap: '6px 10px' }}>
            <KV label="host.id"      value={alert.host_id} isLink />
            <KV label="severity"     value={alert.severity} />
            <KV label="file_path"    value={filePath} />
            <KV label="process"      value={proc} />
            {ev?.entropy_delta > 0 && <KV label="entropy_delta" value={ev.entropy_delta?.toFixed(4)} />}
            {ev?.canary_hit && <KV label="canary_hit" value="true" />}
          </div>
        </Section>

        {/* MITRE ATT&CK */}
        {techList.length > 0 && (
          <Section icon="fa-crosshairs" title="MITRE ATT&CK">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {techList.map(t => (
                <div key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--accent)', width: 78, flexShrink: 0 }}>{t.id}</span>
                  <span style={{ fontSize: 12, color: 'var(--text)', flex: 1 }}>{t.name}</span>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--muted)' }}>{t.tac}</span>
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* Filesystem */}
        <Section icon="fa-folder-tree" title="Filesystem">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--muted)' }}>
              host: <span style={{ color: 'var(--accent)' }}>{alert.host_id}</span>
            </span>
            {filePath ? (
              <span style={{ fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--muted)', wordBreak: 'break-all' }}>
                · <span style={{ color: 'var(--text-2)' }}>{filePath}</span>
              </span>
            ) : (
              <span style={{ fontSize: 11, color: 'var(--muted)' }}>· full tree</span>
            )}
          </div>
          <div
            style={{ border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden', background: 'var(--bg)', height: fsExpanded ? 560 : 320, transition: 'height 0.2s' }}
          >
            <FileSystemGraph
              newEvent={liveEvent}
              highlightPath={filePath}
              hostId={alert.host_id}
            />
          </div>
          <button
            onClick={() => setFsExpanded(x => !x)}
            style={{ marginTop: 6, fontSize: 11, color: 'var(--accent)', background: 'transparent', border: 'none', cursor: 'pointer', padding: 0, fontFamily: 'var(--sans)' }}
          >
            {fsExpanded ? '▲ Collapse' : '▼ Expand'}
          </button>
        </Section>

        {/* Raw event */}
        <Section icon="fa-code" title="Raw event">
          <pre style={{ fontFamily: 'var(--mono)', fontSize: 11, lineHeight: 1.6, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '11px 12px', color: 'var(--text-2)', overflowX: 'auto', whiteSpace: 'pre', margin: 0 }}>
            {rawJson}
          </pre>
        </Section>

      </div>
    </aside>
  );
}
