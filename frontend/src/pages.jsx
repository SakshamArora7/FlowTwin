import { useEffect, useState } from 'react';
import { ArrowRight, Check, ChevronLeft, ChevronRight, Database, Search, SlidersHorizontal, UploadCloud } from 'lucide-react';
import { api } from './api';
import { Badge, bytes, clock, Empty, number, Panel, PhaseNote } from './components';

function CaptureTools({ revision, onImported }) {
  const [captures, setCaptures] = useState([]);
  const [selected, setSelected] = useState('');
  const [packets, setPackets] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  useEffect(() => { let live = true; api('/captures').then(rows => { if (live) { setCaptures(rows); setSelected(current => current || String(rows[0]?.id || '')); } }).catch(e => { if (live) setError(e.message); }); return () => { live = false; }; }, [revision]);
  useEffect(() => { if (!selected) { setPackets(null); return; } let live = true; api(`/captures/${selected}/packets?page_size=25`).then(data => { if (live) setPackets(data); }).catch(e => { if (live) setError(e.message); }); return () => { live = false; }; }, [selected, revision]);
  async function upload(event) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const file = formElement.elements.namedItem('capture')?.files?.[0];
    if (!file) { setError('Choose a PCAP file first.'); return; }
    setUploading(true); setError(''); setMessage('');
    try {
      const form = new FormData(); form.append('file', file);
      const result = await api('/captures', { method: 'POST', body: form, signal: AbortSignal.timeout(600000) });
      setMessage(`Imported ${result.packet_count} packets and ${result.flow_count} flows. ${result.detected_flow_count ? `${result.detected_flow_count} flows classified by the model.` : 'No model was available; flows remain unanalyzed.'}`);
      setSelected(String(result.id)); onImported?.(); formElement.reset();
    } catch (e) { setError(e.message); } finally { setUploading(false); }
  }
  async function rerunModel() {
    setUploading(true); setError(''); setMessage('');
    try { const response = await api(`/captures/${selected}/analyze`, { method: 'POST', signal: AbortSignal.timeout(600000) }); setMessage(`Model classified ${response.classified_flow_count} imported flows.`); onImported?.(); } catch (e) { setError(e.message); } finally { setUploading(false); }
  }
  return <><Panel title="Import network capture" subtitle="PCAP or PCAPNG · 25 MB, 50,000 packets and 5,000 flows maximum"><form className="upload-form" onSubmit={upload}><label className="upload-drop"><UploadCloud size={25}/><span>Choose a packet capture</span><small>Only analyze traffic you are authorized to inspect. Packet payloads are not executed.</small><input type="file" name="capture" accept=".pcap,.pcapng,.cap" aria-label="PCAP file" required/></label><button type="submit" className="button primary" disabled={uploading}>{uploading ? 'Analyzing capture…' : 'Import and analyze'}</button></form>{message && <p className="success-message" role="status">{message}</p>}{error && <p className="error-message" role="alert">{error}</p>}</Panel><Panel title="Captured packet details" subtitle="Structured headers from the selected PCAP or live session"><div className="capture-select"><select aria-label="Selected capture" value={selected} onChange={e => setSelected(e.target.value)}><option value="">Select a capture</option>{captures.map(c => <option key={c.id} value={c.id}>{c.filename} · {c.packet_count} packets</option>)}</select><button className="button" disabled={!selected || uploading} onClick={rerunModel}>Run trained model on capture</button></div>{!packets?.items.length ? <Empty title="No packet records">Import a capture to inspect source, destination, ports, protocol, size, flags, and timestamp.</Empty> : <div className="table-scroll"><table><thead><tr>{['Time (UTC)', 'Source', 'Destination', 'Protocol', 'Size', 'TCP flags', 'Direction'].map(label => <th key={label}>{label}</th>)}</tr></thead><tbody>{packets.items.map(p => <tr key={p.id}><td className="mono">{clock(p.timestamp)}</td><td className="mono">{p.source}:{p.source_port}</td><td className="mono">{p.destination}:{p.destination_port}</td><td><span className="protocol-pill">{p.protocol}</span></td><td>{number(p.size)} B</td><td className="mono">{p.flags || '—'}</td><td>{p.direction}</td></tr>)}</tbody></table></div>}<div className="table-pagination"><span>{packets?.total ?? 0} packets · first 25 shown</span></div></Panel></>;
}

export function TrafficPage({ revision, demoMode, inspect, onImported }) {
  const [query, setQuery] = useState('');
  const [protocol, setProtocol] = useState('all');
  const [classification, setClassification] = useState('all');
  const [page, setPage] = useState(1);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    const timer = setTimeout(() => api(`/flows?${new URLSearchParams({ q: query, protocol, classification, page })}`).then(data => { if (!cancelled) { setResult(data); setError(''); } }).catch(e => { if (!cancelled) { setError(e.message); setResult(null); } }).finally(() => { if (!cancelled) setLoading(false); }), 180);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [query, protocol, classification, page, revision, demoMode]);
  function filter(setter, value) { setter(value); setPage(1); }
  return <>{demoMode ? <PhaseNote phase="1" title="These flow records are illustrative">Turn off sample mode in Settings to import and analyze a PCAP file.</PhaseNote> : <CaptureTools revision={revision} onImported={onImported}/>}<Panel title="Network flows" subtitle={demoMode ? 'Fixed illustrative sample window' : 'Measured bidirectional flows from imported captures'} action={<Badge tone="cyan">{result?.total ?? '—'} flows</Badge>}><div className="table-toolbar"><label className="search-input"><Search size={16}/><input value={query} onChange={e => filter(setQuery, e.target.value)} placeholder="Search IP, category, or flow ID…" aria-label="Search flows" maxLength={100}/></label><div className="table-filters"><SlidersHorizontal size={16}/><select aria-label="Protocol filter" value={protocol} onChange={e => filter(setProtocol, e.target.value)}><option value="all">All protocols</option>{['TCP','UDP','ICMP'].map(p => <option key={p}>{p}</option>)}</select><select aria-label="Classification filter" value={classification} onChange={e => filter(setClassification, e.target.value)}><option value="all">All classifications</option>{['benign','suspicious','malicious','unanalyzed'].map(p => <option key={p}>{p}</option>)}</select></div></div>{error ? <div className="empty" role="alert">{error}</div> : loading ? <div className="table-loading" role="status">Loading flow records…</div> : !result?.items.length ? <Empty title="No matching flows">{demoMode ? 'Try a different search or reset the filters.' : 'Import a PCAP or change the search filters.'}</Empty> : <div className="table-scroll"><table><thead><tr>{['Flow / time (UTC)', 'Source', 'Destination', 'Protocol', 'Packets', 'Transfer', demoMode ? 'Sample label' : 'Model result', ''].map((h,i) => <th key={i}>{h}</th>)}</tr></thead><tbody>{result.items.map(f => <tr key={f.id}><td><strong className="mono">FT-{String(f.id).padStart(4, '0')}</strong><small>{clock(f.timestamp)} / {f.traffic_source || (demoMode ? 'sample' : 'pcap')}</small></td><td className="mono">{f.source}<small>Port {f.source_port}</small></td><td className="mono">{f.destination}<small>Port {f.destination_port}</small></td><td><span className="protocol-pill">{f.protocol}</span></td><td className="mono">{number(f.packets)}</td><td className="mono">{bytes(f.bytes)}</td><td><Badge tone={f.classification}>{f.classification}</Badge></td><td><button className="icon-button" onClick={() => inspect(f)} aria-label={`Inspect flow ${f.id}`}><ArrowRight size={16}/></button></td></tr>)}</tbody></table></div>}<div className="table-pagination"><span>{loading ? 'Fetching records' : `${result?.total ?? 0} matching flows`} · {demoMode ? 'Sample fixture' : 'Live capture / imported PCAP'}</span><div><button className="icon-button" aria-label="Previous page" disabled={page === 1 || loading} onClick={() => setPage(p => p - 1)}><ChevronLeft size={16}/></button><span>Page {page} of {Math.max(1, Math.ceil((result?.total || 0) / 10))}</span><button className="icon-button" aria-label="Next page" disabled={!result || page * 10 >= result.total || loading} onClick={() => setPage(p => p + 1)}><ChevronRight size={16}/></button></div></div></Panel></>;
}

export function SettingsPage({ settings, onSaved, health }) {
  const [draft, setDraft] = useState(settings);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  useEffect(() => { setDraft(settings); }, [settings.demo_mode, settings.refresh_seconds]);
  async function save(e) { e.preventDefault(); setSaving(true); setMessage(''); setError(''); try { await api('/settings', { method: 'PUT', body: JSON.stringify(draft) }); setMessage('Workspace preferences saved.'); onSaved(); } catch (e) { setError(e.message); } finally { setSaving(false); } }
  return <><Panel title="Data & display" subtitle="Preferences are persisted in the local SQLite database"><form onSubmit={save}><div className="setting-row"><div><h3>Sample data mode</h3><p>Explore deterministic example flows. These records are not captured traffic or AI predictions.</p></div><button type="button" className={`toggle ${draft.demo_mode ? 'on' : ''}`} role="switch" aria-checked={draft.demo_mode} aria-label="Sample data mode" onClick={() => setDraft({ ...draft, demo_mode: !draft.demo_mode })}><span/></button></div><div className="setting-row"><div><h3>Refresh interval</h3><p>How often the dashboard fetches current API data. Sample records remain static.</p></div><select aria-label="Refresh interval" value={draft.refresh_seconds} onChange={e => setDraft({ ...draft, refresh_seconds: Number(e.target.value) })}>{[10, 30, 60, 300].map(n => <option key={n} value={n}>{n} seconds</option>)}</select></div><div className="settings-footer"><span className="muted">Changes apply when you save.</span><button className="button primary" disabled={saving} type="submit"><Check size={16}/>{saving ? 'Saving…' : 'Save preferences'}</button></div>{message && <p className="success-message" role="status">{message}</p>}{error && <p className="error-message" role="alert">{error}</p>}</form></Panel><Panel title="System information" subtitle="Local development environment"><dl className="system-grid">{Object.entries({ 'Application version': '1.0 · Integrated', 'Backend': `FastAPI · ${health.status}`, Database: `SQLite · ${health.database}`, 'AI model': health.model === 'trained' ? 'Trained and ready' : 'Not trained', 'Traffic input': 'Live interface capture and PCAP import', 'Live view': 'Live capture and saved-PCAP replay', 'Data retention': 'Local SQLite and uploaded PCAP files' }).map(([key,value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}</dl></Panel><div className="workspace-note"><div><Database size={18}/><span>Sample records remain isolated from imported PCAP traffic and never enter model training.</span></div></div></>;
}
