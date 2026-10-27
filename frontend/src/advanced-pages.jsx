import { useEffect, useState } from 'react';
import { Activity, ArrowRight, BrainCircuit, CheckCircle2, Download, FileBarChart2, Play, Radio, ShieldAlert, Wifi } from 'lucide-react';
import { api } from './api';
import { Badge, clock, Empty, number, Panel, PhaseNote } from './components';
import { HorizontalChart, ProtocolChart, Timeline } from './charts';

function useEndpoint(path, enabled = true, revision = 0) {
  const [state, setState] = useState({ data: null, error: '', loading: true });
  useEffect(() => {
    if (!enabled) { setState({ data: null, error: '', loading: false }); return; }
    let live = true;
    setState(previous => ({ ...previous, loading: true }));
    api(path).then(data => { if (live) setState({ data, error: '', loading: false }); }).catch(error => { if (live) setState({ data: null, error: error.message, loading: false }); });
    return () => { live = false; };
  }, [path, enabled, revision]);
  return state;
}

function Loading({ state, children }) { return state.loading ? <div className="inline-state">Loading…</div> : state.error ? <div className="inline-state error-message" role="alert">{state.error}</div> : children; }

export function DetectionPage({ demoMode, revision, inspect }) {
  const [refresh, setRefresh] = useState(0);
  const [captureId, setCaptureId] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const model = useEndpoint('/model', true, revision + refresh);
  const detections = useEndpoint('/detections', !demoMode, revision + refresh);
  const capturesState = useEndpoint('/captures', !demoMode, revision);
  const captures = { ...capturesState, data: capturesState.data?.filter(c => c.flow_count > 0) };
  async function analyze() {
    setBusy(true); setError(''); setMessage('');
    try {
      const result = await api(`/captures/${captureId || captures.data?.[0]?.id}/analyze`, { method: 'POST', signal: AbortSignal.timeout(600000) });
      setMessage(`Analyzed ${result.classified_flow_count} flows.`);
      setRefresh(value => value + 1);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }
  const metrics = model.data?.metrics;
  return <>
    <Panel title="Classifier readiness" subtitle="Measured results from the installed model"><Loading state={model}>{model.data?.status !== 'trained' ? <div className="readiness"><BrainCircuit size={42}/><h3>No trained model is installed</h3><p>Run the documented CIC-IDS2017 training command to activate predictions. Imported flows will stay marked unanalyzed until a model is available.</p><Badge>Unavailable</Badge>{model.data?.error && <p role="alert">{model.data.error}</p>}</div> : !metrics ? <div className="inline-state">Trained model ready. Evaluation metrics unavailable.</div> : <div className="model-summary"><div><span>Random Forest · {metrics.schema_version}</span><strong>{metrics.classes.join(' · ')}</strong></div><div className="metric-strip">{[['Accuracy', metrics.accuracy], ['Precision', metrics.precision_weighted], ['Recall', metrics.recall_weighted], ['F1', metrics.f1_weighted]].map(([name, value]) => <div key={name}><span>{name}</span><b>{(value * 100).toFixed(1)}%</b></div>)}</div><p>{metrics.evaluation_note}</p></div>}</Loading></Panel>
    {!demoMode && <Panel title="Analyze saved traffic" subtitle="Classify completed live sessions or imported PCAP flows"><Loading state={captures}><div className="replay-controls"><select aria-label="Analysis capture" value={captureId} onChange={e => setCaptureId(e.target.value)}><option value="">{captures.data?.length ? 'Latest capture' : 'No captures'}</option>{captures.data?.map(c => <option key={c.id} value={c.id}>{c.filename} · {c.source} · {c.flow_count} flows</option>)}</select><button className="button primary" disabled={busy || model.data?.status !== 'trained' || !captures.data?.length} onClick={analyze}>{busy ? 'Analyzing…' : 'Analyze capture'}</button></div></Loading>{message && <p role="status">{message}</p>}{error && <p className="error-message" role="alert">{error}</p>}</Panel>}
    {demoMode ? <PhaseNote phase="3" title="Sample mode is separate from model inference">Turn off sample mode and import a PCAP to see classifications computed from its measured flow features.</PhaseNote> : <Panel title="Recent AI detections" subtitle="Measured captured flows classified by the installed model"><Loading state={detections}>{!detections.data?.length ? <Empty title="No AI detections">Analyze a saved capture above, import a PCAP, or start live monitoring to generate predictions.</Empty> : <div className="detection-list">{detections.data.map(d => <button key={d.id} className="detection-item" onClick={() => inspect(d.flow)}><div><strong>{d.category}</strong><span className="mono">{d.flow.source} → {d.flow.destination}</span></div><Badge tone={d.severity === 'High' ? 'malicious' : d.severity === 'Medium' ? 'suspicious' : 'benign'}>{d.severity}</Badge><b>{(d.confidence * 100).toFixed(1)}%</b><ArrowRight size={16}/></button>)}</div>}</Loading></Panel>}
    {metrics && <Panel title="Model feature importance" subtitle="Global forest importance, computed during training"><HorizontalChart data={Object.entries(metrics.feature_importance).map(([name, value]) => ({ name, value: Math.round(value * 1000) })).sort((a, b) => b.value - a.value)} color="#ad8bf5"/></Panel>}
  </>;
}

export function ReplayPage({ demoMode, revision }) {
  const capturesState = useEndpoint('/captures', !demoMode, revision);
  const captures = { ...capturesState, data: capturesState.data?.filter(c => c.source === 'pcap') };
  const [captureId, setCaptureId] = useState('');
  const [events, setEvents] = useState([]);
  const [recentPackets, setRecentPackets] = useState([]);
  const [connected, setConnected] = useState(false);
  const [connectionError, setConnectionError] = useState('');
  const [state, setState] = useState({ active: false, processed: 0, total: 0 });
  const [error, setError] = useState('');
  useEffect(() => {
    if (demoMode) return;
    const url = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/ws/monitor`;
    let disposed = false, timer, ws, attempt = 0;
    function connect() {
      ws = new WebSocket(url);
      ws.onopen = () => { attempt = 0; setConnected(true); setConnectionError(''); };
      ws.onerror = () => setConnectionError('Replay stream disconnected. Reconnecting…');
      ws.onclose = () => {
        if (disposed) return;
        setConnected(false);
        setConnectionError('Replay stream disconnected. Reconnecting…');
        timer = setTimeout(connect, Math.min(1000 * 2 ** attempt++, 10000));
      };
      ws.onmessage = event => {
        let data;
        try { data = JSON.parse(event.data); } catch { return; }
        if (data.type === 'connected') setState(data.replay);
        if (data.type === 'replay_started') { setEvents([]); setRecentPackets([]); setState({ active: true, capture_id: data.capture_id, processed: 0, total: data.total }); }
        if (data.source === 'pcap_replay' && data.type === 'packet') setRecentPackets(previous => [data.packet, ...previous].slice(0, 15));
        if (data.source === 'pcap_replay' && data.type === 'flow') { setEvents(previous => [data, ...previous].slice(0, 50)); setState(previous => ({ ...previous, active: true, processed: data.index, total: data.total })); }
        if (data.type === 'replay_completed') setState(previous => ({ ...previous, active: false }));
      };
    }
    connect();
    return () => {
      disposed = true;
      clearTimeout(timer);
      ws.onopen = ws.onmessage = ws.onerror = ws.onclose = null;
      ws.close();
    };
  }, [demoMode]);
  async function start() {
    setError('');
    try { await api(`/captures/${captureId || captures.data?.[0]?.id}/replay`, { method: 'POST' }); } catch (e) { setError(e.message); }
  }
  if (demoMode) return <><div className="monitor-stage"><div className="radar"><span/><span/><span/><Radio size={34}/></div><Badge>Sample mode</Badge><h2>Replay a real capture</h2><p>Turn sample mode off, import a PCAP in Network Traffic, then return here to watch its analyzed flows stream through WebSockets.</p><a className="button primary" href="#/settings">Open settings <ArrowRight size={16}/></a></div></>;
  return <><Panel title="PCAP replay" subtitle="Accelerated playback of already imported and analyzed traffic"><div className="replay-controls"><Badge tone={connected ? 'benign' : 'suspicious'}>{connected ? 'WebSocket connected' : 'Connecting'}</Badge><select aria-label="Replay capture" value={captureId} onChange={e => setCaptureId(e.target.value)}><option value="">{captures.data?.length ? 'Latest capture' : 'No captures'}</option>{captures.data?.map(c => <option key={c.id} value={c.id}>{c.filename} · {c.flow_count} flows</option>)}</select><button className="button primary" onClick={start} disabled={!captures.data?.length || state.active || !connected}><Play size={14}/>Start replay</button></div>{(error || connectionError) && <div className="error-message" role="alert">{error || connectionError}</div>}<div className="replay-progress"><span>{state.active ? 'Replaying imported traffic' : 'No replay active'}</span><strong>{state.processed || 0} / {state.total || 0} flows</strong><div><i style={{ width: `${state.total ? (state.processed / state.total) * 100 : 0}%` }}/></div></div></Panel><div className="two-columns"><Panel title="Streamed network flows" subtitle="PCAP replay · not live packet capture"><div className="stream-list">{events.length ? events.map((event, index) => <div key={`${event.capture_id}-${event.index}-${index}`}><span className="pulse-dot"/><span className="mono">{event.flow.source}:{event.flow.source_port} → {event.flow.destination}:{event.flow.destination_port}</span><Badge tone={event.flow.classification}>{event.flow.category}</Badge><small>{event.flow.protocol}</small></div>) : <Empty title="Waiting for a replay">Import a PCAP on Network Traffic and select Start replay.</Empty>}</div></Panel><Panel title="Packet activity" subtitle="Headers streamed from the imported capture"><div className="stream-list">{recentPackets.length ? recentPackets.map((packet,index) => <div key={`${packet.timestamp}-${index}`}><span className="pulse-dot"/><span className="mono">{packet.source} → {packet.destination}</span><small>{packet.protocol} · {packet.size} B</small></div>) : <Empty title="No packet events yet"/>}</div></Panel></div><MonitorSummary events={events}/><p className="context-note">Replay runs at an accelerated 150 ms per flow. The timestamp and classification were recorded during the original PCAP analysis. For genuine capture from an adapter, use the Live interface capture tab.</p></>;
}

function MonitorSummary({ events }) {
  const protocols = Object.entries(events.reduce((counts, event) => ({ ...counts, [event.flow.protocol]: (counts[event.flow.protocol] || 0) + 1 }), {})).map(([name, value]) => ({ name, value }));
  const flagged = events.filter(event => event.flow.classification === 'suspicious' || event.flow.classification === 'malicious');
  return <div className="two-columns monitor-summary"><Panel title="Replay protocol distribution" subtitle="Flows received in this replay"><HorizontalChart data={protocols} color="#51d8c8"/></Panel><Panel title="Recent alert timeline" subtitle={`${flagged.length} flagged connection${flagged.length === 1 ? '' : 's'} in this replay`}>{flagged.length ? <div className="monitor-alerts">{flagged.slice(0, 5).map(event => <div key={event.flow.id}><span className="pulse-dot"/><div><strong>{event.flow.category}</strong><small>{event.flow.source} → {event.flow.destination}</small></div><Badge tone={event.flow.classification}>{event.flow.classification}</Badge><time>{clock(event.flow.timestamp)} UTC</time></div>)}</div> : <Empty title="No flagged flows in replay"/>}</Panel></div>;
}

export function AlertsPage({ demoMode, data, revision, inspect, onRefresh }) {
  const alerts = useEndpoint('/alerts', !demoMode, revision);
  const [error, setError] = useState('');
  async function change(id, status) { setError(''); try { await api(`/alerts/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) }); onRefresh(); } catch (e) { setError(e.message); } }
  if (demoMode) return <><PhaseNote phase="1" title="These are sample events">Sample labels demonstrate the alert layout. They have no model confidence or investigation status.</PhaseNote><Panel title="Illustrative security events" subtitle="Fixture rows · no recorded detection">{data.alerts.length ? <div className="detection-list">{data.alerts.map(f => <button key={f.id} className="detection-item" onClick={() => inspect(f)}><strong>{f.category}</strong><span className="mono">{f.source} → {f.destination}</span><Badge tone={f.classification}>Sample</Badge><ArrowRight size={15}/></button>)}</div> : <Empty title="No sample events"/>}</Panel></>;
  return <Panel title="Security alerts" subtitle="Review model findings and manage investigation status"><Loading state={alerts}>{alerts.data?.length ? <div className="alert-management">{alerts.data.map(a => <div key={a.id} className="managed-alert"><button onClick={() => inspect({ id: a.flow_id, source: a.source, destination: a.destination, classification: a.severity === 'High' ? 'malicious' : 'suspicious', is_demo: false })}><ShieldAlert size={17}/><span><strong>Alert #{a.id} · {a.category}</strong><small>{a.source} → {a.destination} · {clock(a.timestamp)} UTC</small></span></button><span>{(a.confidence * 100).toFixed(1)}% confidence</span><Badge tone={a.severity === 'High' ? 'malicious' : 'suspicious'}>{a.severity}</Badge><select aria-label={`Status for alert ${a.id}`} value={a.status} onChange={e => change(a.id, e.target.value)}><option>New</option><option>Investigating</option><option>Resolved</option></select></div>)}</div> : <Empty title="No generated alerts">Only non-benign model classifications create alerts.</Empty>}</Loading>{error && <p className="error-message" role="alert">{error}</p>}</Panel>;
}

export function AnalyticsPage({ data, demoMode, revision }) {
  const model = useEndpoint('/model', true, revision);
  const sizes = useEndpoint('/analytics/packet-sizes', !demoMode, revision);
  return <><div className="two-columns"><Panel title="Traffic activity" subtitle="Flows per hour · UTC"><Timeline data={data.timeline}/></Panel><Panel title="Top communicating sources" subtitle="Flow counts by source IP"><HorizontalChart data={data.top_sources}/></Panel><Panel title="Protocol composition" subtitle="Within the selected time window"><ProtocolChart data={data.protocols} total={data.total}/></Panel><Panel title="Detection categories" subtitle={demoMode ? 'Sample labels only' : 'Trained model results'}><HorizontalChart data={data.threats} color="#ad8bf5"/></Panel></div>{!demoMode && <Panel title="Packet size distribution" subtitle="IP packet lengths measured from live and imported traffic"><Loading state={sizes}><HorizontalChart data={sizes.data || []} color="#53d9c9" measure="Packets"/></Loading></Panel>}<Panel title="Model evaluation" subtitle="Held-out corpus results, not field accuracy">{model.data?.metrics ? <div className="metric-strip">{[['Accuracy', model.data.metrics.accuracy], ['Precision', model.data.metrics.precision_weighted], ['Recall', model.data.metrics.recall_weighted], ['F1 score', model.data.metrics.f1_weighted]].map(([label, score]) => <div key={label}><span>{label}</span><b>{(score * 100).toFixed(1)}%</b></div>)}</div> : <div className="inline-state">No evaluated model installed.</div>}</Panel></>;
}

export function ReportsPage({ demoMode, data }) {
  return <><div className="two-columns">{[['Flow records', 'CSV', 'csv', 'Download flow details and classifications.'], ['Security summary', 'PDF', 'pdf', 'Download a compact security overview.']].map(([title, format, path, description]) => <Panel key={format} title={title} action={<span className="file-type">{format}</span>}><div className="report-preview"><FileBarChart2 size={34}/><p>{description}</p><a className="button primary" href={`/api/reports/${path}`} download><Download size={15}/>Export {format}</a></div></Panel>)}</div><Panel title="Report context" subtitle="Included in every export"><div className="report-summary"><div><span>Data source</span><strong>{demoMode ? 'SAMPLE FIXTURE' : 'Live capture / imported PCAP'}</strong></div><div><span>Flow records in current view</span><strong>{number(data.total)}</strong></div><div><span>Safety label</span><strong>{demoMode ? 'Illustrative only' : 'Analyst review required'}</strong></div></div></Panel>{demoMode && <p className="context-note">Sample exports are visibly marked as fixtures and should not be presented as actual detections.</p>}</>;
}

