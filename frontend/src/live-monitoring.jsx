import { useEffect, useRef, useState } from 'react';
import { Play, RefreshCw, Square } from 'lucide-react';
import { api } from './api';
import { Badge, bytes, clock, Empty, number, Panel, PhaseNote } from './components';
import { HorizontalChart } from './charts';
import { ReplayPage } from './advanced-pages';

export function MonitoringPage({ demoMode, revision, inspect }) {
  const [view, setView] = useState('live');
  if (demoMode) return <PhaseNote title="Live capture requires real data mode">Turn off sample mode in Settings, then explicitly select the Wi-Fi or Ethernet interface you are authorized to monitor. You do not need to upload a PCAP.</PhaseNote>;
  return <>
    <div className="monitor-tabs" aria-label="Monitoring source">
      <button className={`button ${view === 'live' ? 'primary' : ''}`} aria-pressed={view === 'live'} onClick={() => setView('live')}>Live interface capture</button>
      <button className={`button ${view === 'replay' ? 'primary' : ''}`} aria-pressed={view === 'replay'} onClick={() => setView('replay')}>Saved-PCAP replay</button>
    </div>
    {view === 'live' ? <LiveCapture inspect={inspect}/> : <ReplayPage demoMode={false} revision={revision}/>}
  </>;
}

function LiveCapture({ inspect }) {
  const [interfaces, setInterfaces] = useState({ available: false, interfaces: [], error: '' });
  const [selected, setSelected] = useState('');
  const [state, setState] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [streamDropped, setStreamDropped] = useState(0);
  const [reload, setReload] = useState(0);
  const streamVersion = useRef(0);
  useEffect(() => {
    let mounted = true;
    const version = streamVersion.current;
    Promise.all([api('/live/interfaces'), api('/live'), api('/live/sessions')])
      .then(([adapters, current, history]) => {
        if (mounted) { setInterfaces(adapters); if (version === streamVersion.current) setState(current); setSessions(history); }
      }).catch(e => { if (mounted) setError(e.message); });
    return () => { mounted = false; };
  }, [reload]);
  useEffect(() => {
    if (!state?.capture_id || !['stopped', 'error'].includes(state.status)) return;
    let mounted = true;
    api('/live/sessions').then(rows => { if (mounted) setSessions(rows); }).catch(e => { if (mounted) setError(e.message); });
    return () => { mounted = false; };
  }, [state?.capture_id, state?.status]);
  useEffect(() => {
    let socket, timer, mounted = true, delay = 1000;
    function connect() {
      socket = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/ws/monitor`);
      socket.onopen = () => { if (mounted) { setConnected(true); setStreamDropped(0); delay = 1000; } };
      socket.onmessage = event => {
        if (!mounted) return;
        try {
          const message = JSON.parse(event.data);
          if ((message.type === 'live_snapshot' || message.type === 'connected') && message.live) { streamVersion.current += 1; setState(message.live); }
          if (message.stream_dropped) setStreamDropped(message.stream_dropped);
        } catch { setError('The monitoring stream returned an invalid message.'); }
      };
      socket.onerror = () => { if (mounted) setConnected(false); };
      socket.onclose = () => {
        if (mounted) { setConnected(false); timer = setTimeout(connect, delay); delay = Math.min(delay * 2, 5000); }
      };
    }
    connect();
    return () => { mounted = false; clearTimeout(timer); socket?.close(); };
  }, []);
  async function control(action) {
    setBusy(true); setError('');
    const version = streamVersion.current;
    try {
      const options = action === 'start' ? { method: 'POST', body: JSON.stringify({ interface_id: selected }) } : { method: 'POST' };
      const response = await api(`/live/${action}`, options);
      if (version === streamVersion.current) setState(response);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }
  const running = ['starting', 'running', 'stopping'].includes(state?.status);
  const status = state?.status || 'loading';
  const recent = state?.recent_flows || [];
  return <>
    <Panel title="Live interface capture" subtitle="Actual packets from your explicitly selected local adapter">
      <div className="replay-controls">
        <Badge tone={connected ? 'benign' : 'suspicious'}>{connected ? 'WebSocket connected' : 'Reconnecting to stream…'}</Badge>
        <select aria-label="Capture interface" value={selected} onChange={e => setSelected(e.target.value)} disabled={running || busy}>
          <option value="">Select an interface…</option>
          {interfaces.interfaces.map(iface => <option key={iface.id} value={iface.id}>{iface.name}{iface.addresses?.length ? ` · ${iface.addresses.join(', ')}` : ''}</option>)}
        </select>
        <button className="button" aria-label="Refresh interfaces" onClick={() => setReload(n => n + 1)} disabled={running || busy}><RefreshCw size={14}/></button>
        <button className="button primary" disabled={!state || !selected || !interfaces.available || !connected || running || busy} onClick={() => control('start')}><Play size={14}/>Start monitoring</button>
        <button className="button" disabled={!running || status === 'stopping' || busy} onClick={() => control('stop')}><Square size={14}/>Stop monitoring</button>
      </div>
      <div className="live-status" role="status"><Badge tone={status === 'running' ? 'benign' : 'neutral'}>{status}</Badge>
        <span>{state?.interface_name || 'No interface selected'}{state?.capture_id ? ` · Session #${state.capture_id}` : ''}</span>
        {status === 'stopping' && <span>Draining queued packets and saving completed flows…</span>}
      </div>
      {(error || interfaces.error || state?.error) && <div className="live-error" role="alert">{error || state?.error || interfaces.error}</div>}
      <p className="context-note">Capture continues when you leave this page. Use Stop monitoring to close the adapter and save queued packets and active flows. Only monitor traffic you are authorized to inspect.</p>
    </Panel>
    <div className="metric-strip live-metrics">
      <div><span>Packet rate</span><b>{number(state?.packets_per_second || 0)} pkt/s</b></div>
      <div><span>Bandwidth · IP bytes</span><b>{number(Math.round((state?.bits_per_second || 0) / 1000))} kbit/s</b></div>
      <div><span>Active flows</span><b>{number(state?.active_flows)}</b></div>
      <div><span>Processed packets</span><b>{number(state?.processed_packets)}</b></div>
    </div>
    <div className="live-health">
      <span>{number(state?.dropped_packets)} packets dropped</span>
      <span>Queue: {number(state?.queue_depth)} / {number(state?.queue_capacity)}</span>
      <span>Unsupported: {number(state?.unsupported_packets)} · Malformed: {number(state?.malformed_packets)}</span>
      <span>Completed flows: {number(state?.completed_flows)} · {bytes(state?.bytes || 0)} measured</span>
      <span>Driver drops: {state?.driver_dropped_packets == null ? 'unknown' : number(state.driver_dropped_packets)}</span>
      {streamDropped > 0 && <span>{number(streamDropped)} stream updates skipped; showing the latest snapshot</span>}
    </div>
    <p className="context-note">{state?.model_status === 'trained' ? 'Completed flows are classified automatically by the installed model.' : state?.model_error ? `Model error: ${state.model_error}. Traffic is retained as unanalyzed.` : 'Until a trained model is available, flows are saved as unanalyzed and no ML alerts are generated.'} Active flows remain unanalyzed until TCP termination, the 120-second timeout, or Stop.</p>
    <div className="two-columns">
      <Panel title="Recent connections" subtitle="Latest 50 observed flows · active and completed">
        <div className="stream-list">{recent.length ? recent.map(flow => <div key={flow.id}>
          <button className="live-connection mono" onClick={() => inspect?.(flow)} disabled={!inspect}>{flow.source}:{flow.source_port} → {flow.destination}:{flow.destination_port}</button>
          <Badge tone={flow.classification}>{flow.complete ? flow.category : running ? 'Active' : 'Incomplete'}</Badge><small>{flow.protocol} · {number(flow.packets)} packets</small>
        </div>) : <Empty title="Waiting for live traffic">Select an interface and start monitoring.</Empty>}</div>
      </Panel>
      <Panel title="Live protocol distribution" subtitle="Processed packets across this session"><HorizontalChart data={state?.protocols || []} measure="Packets" color="#31d6c4"/></Panel>
      <Panel title="Recent packet activity" subtitle="Latest 15 structured headers · payloads are not retained">
        <div className="stream-list">{state?.recent_packets?.length ? state.recent_packets.map((p, index) => <div key={`${p.timestamp}-${index}`}><span className="mono">{p.source}:{p.source_port} → {p.destination}:{p.destination_port}</span><small>{p.protocol} · {p.size} B · {p.flags || '—'} · {clock(p.timestamp)} UTC</small></div>) : <Empty title="No captured packets yet">Start monitoring an authorized interface to see packet activity.</Empty>}</div>
      </Panel>
      <Panel title="Live security alerts" subtitle="Non-benign model predictions from completed flows">
        <div className="stream-list">{state?.alerts?.length ? state.alerts.map(a => <div key={a.id}><span className="mono">{a.source} → {a.destination}</span><Badge tone={a.severity === 'High' ? 'malicious' : 'suspicious'}>{a.category}</Badge><small>{(a.confidence * 100).toFixed(1)}%</small></div>) : <Empty title="No live ML alerts">Alerts appear after a completed flow receives a non-benign prediction.</Empty>}</div>
      </Panel>
    </div>
    <Panel title="Saved live sessions" subtitle="Local SQLite history · latest 10 sessions">
      <div className="live-session-list">{sessions.length ? sessions.slice(0, 10).map(s => <div key={s.capture_id}><strong>#{s.capture_id} · {s.interface_name}</strong><span>{s.started_at} · {number(s.processed_packets)} packets</span><Badge>{s.status}</Badge>{s.error && <span>{s.error}</span>}</div>) : <Empty title="No saved live sessions">Live sessions are saved here when monitoring starts.</Empty>}</div>
    </Panel>
  </>;
}
