import { useEffect, useRef, useState } from 'react';
import { api } from './api';
import { ArrowUpRight, Database, ShieldAlert, X } from 'lucide-react';

export const number = value => new Intl.NumberFormat('en-US').format(value ?? 0);
export const clock = value => new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', timeZone: 'UTC', hour12: false });
export const bytes = value => value >= 1e6 ? `${(value / 1e6).toFixed(1)} MB` : `${(value / 1e3).toFixed(1)} KB`;

export function Badge({ children, tone = 'neutral' }) { return <span className={`badge ${tone}`}><span className="badge-dot" />{children}</span>; }
export function Panel({ title, subtitle, action, children, className = '' }) { return <section className={`panel ${className}`}><div className="panel-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</div>{children}</section>; }
export function Empty({ title = 'No traffic to display', children }) { return <div className="empty"><Database size={30} /><h3>{title}</h3><p>{children || 'Import a PCAP in Network Traffic or enable sample mode in Settings.'}</p></div>; }
export function Skeleton() { return <div className="skeleton-layout" aria-label="Loading dashboard" role="status"><div className="skeleton h-28" /><div className="skeleton h-28" /><div className="skeleton h-28" /><div className="skeleton h-28" /><div className="skeleton skeleton-wide h-80" /></div>; }
export function PhaseNote({ phase, title, children }) { return <div className="phase-note"><div className="phase-icon"><ShieldAlert size={22} /></div><div><span className="eyebrow">DATA NOTICE · PHASE {phase}</span><h3>{title}</h3><p>{children}</p></div></div>; }
export function TextLink({ to, children }) { return <a className="text-link" href={`#/${to}`}>{children}<ArrowUpRight size={14} /></a>; }

const advice = {
  'DDoS': 'Check traffic volume and affected services; apply rate limits or upstream filtering after validation.',
  'DoS': 'Review service capacity and request patterns; rate limit the affected endpoint if confirmed.',
  'Port scan': 'Verify whether scanning was authorized, then review exposed ports and firewall policy.',
  'Brute force': 'Review authentication logs, enable multi-factor authentication, and limit repeated attempts.',
  'Botnet': 'Investigate the host and its outbound connections; isolate it if compromise is confirmed.',
};

export function FlowDialog({ flow, close }) {
  const ref = useRef(null);
  const [analysis, setAnalysis] = useState(null);
  const [error, setError] = useState('');
  useEffect(() => { const el = ref.current; el.showModal(); return () => el.close(); }, []);
  useEffect(() => { if (flow.is_demo !== false) return; let live = true; api(`/flows/${flow.id}/analysis`).then(data => { if (live) setAnalysis(data); }).catch(e => { if (live) setError(e.message); }); return () => { live = false; }; }, [flow.id, flow.is_demo]);
  const actual = analysis?.flow || flow;
  const detection = analysis?.detection;
  return <dialog ref={ref} className="flow-dialog" aria-labelledby="flow-dialog-title" onCancel={close} onClick={e => { if (e.target === e.currentTarget) close(); }}><div className="panel-heading"><div><span className="eyebrow">{flow.is_demo !== false ? 'SAMPLE FLOW' : 'IMPORTED PCAP FLOW'} · FT-{String(flow.id).padStart(4, '0')}</span><h2 id="flow-dialog-title">Connection details</h2></div><button onClick={close} className="icon-button" aria-label="Close flow details" autoFocus><X size={20}/></button></div>{flow.is_demo !== false && <div className="sample-callout">Illustrative fixture. This is not a captured packet or an AI prediction.</div>}{error && <div className="error-message" role="alert">{error}</div>}<dl className="detail-grid">{Object.entries({ Source: `${actual.source}:${actual.source_port ?? 0}`, Destination: `${actual.destination}:${actual.destination_port ?? 0}`, Protocol: actual.protocol || '—', Timestamp: actual.timestamp ? `${new Date(actual.timestamp).toISOString()} (UTC)` : '—', Packets: number(actual.packets), Transferred: bytes(actual.bytes || 0), Duration: `${actual.duration_ms ?? '—'} ms`, [flow.is_demo !== false ? 'Example label' : 'Model category']: actual.category || '—' }).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}</dl>{analysis && <div className="analysis-section"><h3>Measured flow features</h3><div className="feature-grid">{Object.entries({ 'Forward packets': analysis.statistics.forward_packets, 'Backward packets': analysis.statistics.backward_packets, 'Forward bytes': analysis.statistics.forward_bytes, 'Backward bytes': analysis.statistics.backward_bytes, 'Packet size mean': `${analysis.statistics.packet_size_mean.toFixed(1)} B`, 'Packet rate': `${analysis.statistics.flow_packets_per_second.toFixed(1)}/s`, 'Inter-arrival mean': `${analysis.statistics.iat_mean_us.toFixed(1)} μs`, 'TCP flags': Object.entries(analysis.statistics.tcp_flags).map(([key,value]) => `${key}: ${value}`).join(' · ') || 'None' }).map(([name,value]) => <div key={name}><span>{name}</span><strong>{value}</strong></div>)}</div>{detection ? <><h3>Why the model voted {detection.category}</h3><p className="context-note">These are local changes in the forest's class probability along its decision paths. They describe the model's vote, not proof of an attack.</p><div className="contribution-list">{detection.explanation.map(item => <div key={item.feature}><span>{item.feature} · {number(item.value)}</span><strong className={item.contribution > 0 ? 'malicious' : 'benign'}>{item.contribution > 0 ? '+' : ''}{(item.contribution * 100).toFixed(1)} pp</strong></div>)}</div>{detection.category !== 'Benign' && <><h3>Security implications and next step</h3><p className="context-note">{advice[detection.category] || 'Investigate the host, correlate with logs, and confirm the activity before taking action.'}</p></>}</> : <p className="context-note">No trained model was available when this capture was imported. The packet-derived features remain available for inspection.</p>}</div>}<div className="dialog-footer"><Badge tone={actual.classification}>{actual.classification}</Badge><span>{flow.is_demo !== false ? 'Model confidence: unavailable' : detection ? `Model confidence: ${(detection.confidence * 100).toFixed(1)}%` : 'Model confidence: unavailable'}</span></div></dialog>;
}
