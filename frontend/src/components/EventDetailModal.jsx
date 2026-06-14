import React, { useEffect, useState } from 'react';
import FileSystemGraph from './FileSystemGraph';
import { RULE_NAME, MITRE } from '../constants/eventTypes';
import { containHost, getHost } from '../api/client';

const SEV_COLOR = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)' };
const SEV_BG    = { CRITICAL: 'var(--crit-bg)', HIGH: 'var(--high-bg)', MEDIUM: 'var(--med-bg)', LOW: 'var(--low-bg)' };

const PROC_ICONS = {
  CANARY_TOUCHED:        'fa-shield-halved',
  ENTROPY_SPIKE:         'fa-chart-line',
  PROCESS_ANOMALY:       'fa-magnifying-glass',
  COMBINED_ALERT:        'fa-bolt',
  CONTAINMENT_TRIGGERED: 'fa-plug-circle-xmark',
  CONTAINMENT_COMPLETE:  'fa-circle-check',
  MARKOV_REPOSITION:     'fa-arrows-rotate',
  HEARTBEAT:             'fa-heart-pulse',
};

function Section({ icon, title, children }) {
  return (
    <div style={{ borderBottom: '1px solid var(--border-soft)', padding: '13px 20px' }}>
      <div style={{ fontSize: 11, color: 'var(--muted)', letterSpacing: '0.04em', textTransform: 'uppercase', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 7 }}>
        <i className={`fa-solid ${icon}`} style={{ fontSize: 10 }} />
        {title}
      </div>
      {children}
    </div>
  );
}

function KV({ label, value }) {
  if (!value && value !== 0) return null;
  return (
    <>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 11.5, color: 'var(--muted)' }}>{label}</span>
      <span style={{ fontFamily: 'var(--mono)', fontSize: 11.5, color: 'var(--text)', wordBreak: 'break-all' }}>{String(value)}</span>
    </>
  );
}

export default function EventDetailModal({ event, onClose }) {
  const [isContained, setIsContained] = useState(false);
  const [containing, setContaining] = useState(false);

  useEffect(() => {
    if (!event?.host_id) return;
    setIsContained(false);
    const controller = new AbortController();
    getHost(event.host_id, controller.signal)
      .then(r => { if (!controller.signal.aborted) setIsContained(r.data.is_contained); })
      .catch(() => {});
    return () => controller.abort();
  }, [event?.host_id]);

  async function handleContain() {
    setContaining(true);
    try {
      await containHost(event.host_id);
      setIsContained(true);
    } catch (err) {
      console.error('Containment failed:', err.response?.data?.detail || err.message);
    } finally {
      setContaining(false);
    }
  }

  if (!event) return null;

  const isMov    = event.event_type === 'HEARTBEAT' && event.details?.sub_type === 'MARKOV_REPOSITION';
  const eventKey = isMov ? 'MARKOV_REPOSITION' : event.event_type;
  const techList = MITRE[eventKey] || [];
  const ruleName = RULE_NAME[eventKey] || event.event_type;
  const icon     = PROC_ICONS[eventKey] || 'fa-circle-dot';
  const sevColor = SEV_COLOR[event.severity] || 'var(--muted)';
  const sevBg    = SEV_BG[event.severity]    || 'rgba(107,114,128,0.13)';

  const rawJson = JSON.stringify({
    id:           event.id,
    host_id:      event.host_id,
    event_type:   event.event_type,
    severity:     event.severity,
    file_path:    event.file_path,
    entropy_delta:event.entropy_delta,
    canary_hit:   event.canary_hit,
    process_name: event.process_name,
    details:      event.details,
    timestamp:    event.timestamp,
  }, null, 2);

  return (
    /* Backdrop */
    <div
      onClick={onClose}
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
    >
      {/* Modal panel */}
      <div
        onClick={e => e.stopPropagation()}
        style={{ width: 680, maxHeight: '88vh', background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 24px 64px rgba(0,0,0,0.6)' }}
      >
        {/* Header */}
        <div style={{ padding: '14px 20px 12px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 10.5, padding: '2px 8px', borderRadius: 4, fontWeight: 500, background: sevBg, color: sevColor }}>
              {event.severity || 'INFO'}
            </span>
            <span style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--muted)' }}>
              {new Date(event.timestamp).toLocaleString()}
            </span>
            <button
              className={`siem-dt-btn ${isContained ? '' : 'danger'}`}
              onClick={handleContain}
              disabled={containing || isContained}
              style={{ marginLeft: 'auto' }}
            >
              <i className="fa-solid fa-plug-circle-xmark" style={{ fontSize: 11 }} />
              {isContained ? 'Isolated ✓' : containing ? 'Isolating…' : 'Isolate host'}
            </button>
            <button
              onClick={onClose}
              style={{ width: 26, height: 26, display: 'grid', placeItems: 'center', borderRadius: 5, cursor: 'pointer', color: 'var(--muted)', border: '1px solid transparent', background: 'transparent' }}
              onMouseEnter={e => { e.currentTarget.style.background = 'var(--panel-2)'; e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text)'; }}
              onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.borderColor = 'transparent'; e.currentTarget.style.color = 'var(--muted)'; }}
            >
              <i className="fa-solid fa-xmark" />
            </button>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 9 }}>
            <span style={{ width: 32, height: 32, borderRadius: 7, background: 'var(--panel-2)', border: '1px solid var(--border)', display: 'grid', placeItems: 'center', color: sevColor, fontSize: 14, flexShrink: 0 }}>
              <i className={`fa-solid ${icon}`} />
            </span>
            <div>
              <div style={{ fontSize: 14, fontWeight: 600, letterSpacing: '-0.01em', color: 'var(--text)', lineHeight: 1.3 }}>{ruleName}</div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--muted)', marginTop: 3 }}>
                {event.host_id} · event #{event.id}
              </div>
            </div>
          </div>
        </div>

        {/* Scrollable body — 2-column grid layout */}
        <div style={{ flex: 1, overflowY: 'auto', display: 'grid', gridTemplateColumns: '1fr 1fr', gridAutoRows: 'min-content' }}>

          {/* Entity — left */}
          <Section icon="fa-server" title="Entity">
            <div style={{ display: 'grid', gridTemplateColumns: '110px 1fr', gap: '5px 8px' }}>
              <KV label="host_id"       value={event.host_id} />
              <KV label="event_type"    value={event.event_type} />
              <KV label="file_path"     value={event.file_path} />
              <KV label="process"       value={event.process_name !== 'unknown' ? event.process_name : null} />
              {event.entropy_delta > 0 && <KV label="entropy" value={event.entropy_delta?.toFixed(4)} />}
              {event.canary_hit && <KV label="canary_hit" value="true" />}
            </div>
          </Section>

          {/* MITRE ATT&CK — right */}
          <Section icon="fa-crosshairs" title="MITRE ATT&CK">
            {techList.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {techList.map(t => (
                  <div key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--accent)', width: 70, flexShrink: 0 }}>{t.id}</span>
                    <span style={{ fontSize: 12, color: 'var(--text)', flex: 1 }}>{t.name}</span>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--muted)' }}>{t.tac}</span>
                  </div>
                ))}
              </div>
            ) : (
              <span style={{ fontSize: 12, color: 'var(--muted)' }}>No technique mapping for this event type.</span>
            )}
          </Section>

          {/* Filesystem — full width */}
          {event.file_path && (
            <div style={{ gridColumn: '1 / -1', borderBottom: '1px solid var(--border-soft)', padding: '13px 20px' }}>
              <div style={{ fontSize: 11, color: 'var(--muted)', letterSpacing: '0.04em', textTransform: 'uppercase', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 7 }}>
                <i className="fa-solid fa-folder-tree" style={{ fontSize: 10 }} />
                Filesystem
                <span style={{ marginLeft: 4, fontFamily: 'var(--mono)', fontSize: 10.5, color: 'var(--accent)', textTransform: 'none', letterSpacing: 0 }}>
                  {event.file_path}
                </span>
              </div>
              <div style={{ border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden', background: 'var(--bg)', height: 280 }}>
                <FileSystemGraph highlightPath={event.file_path} hostId={event.host_id} />
              </div>
            </div>
          )}

          {/* Raw event — full width */}
          <div style={{ gridColumn: '1 / -1', padding: '13px 20px' }}>
            <div style={{ fontSize: 11, color: 'var(--muted)', letterSpacing: '0.04em', textTransform: 'uppercase', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 7 }}>
              <i className="fa-solid fa-code" style={{ fontSize: 10 }} />
              Raw event
            </div>
            <pre style={{ fontFamily: 'var(--mono)', fontSize: 11, lineHeight: 1.6, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '10px 12px', color: 'var(--text-2)', overflowX: 'auto', whiteSpace: 'pre', margin: 0 }}>
              {rawJson}
            </pre>
          </div>

        </div>
      </div>
    </div>
  );
}
