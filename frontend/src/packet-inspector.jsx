import { useEffect, useRef, useState } from 'react';
import { api } from './api';
import { Panel } from './components';
import './packet-inspector.css';

const presets = { 'All packets': '', TCP: 'tcp', DNS: 'dns', HTTP: 'http', TLS: 'tls', SYN: 'tcp.flags.syn', RST: 'tcp.flags.rst', 'Large packets': 'frame.len > 1500' };
const hashParams = () => new URLSearchParams(location.hash.split('?')[1] || '');

export function PacketInspectorPage({ demoMode, revision = 0, inspect }) {
  const [captures, setCaptures] = useState([]);
  const [capture, setCapture] = useState(() => hashParams().get('capture') || '');
  const [flowId, setFlowId] = useState(() => hashParams().get('flow') || '');
  const [selected, setSelected] = useState(() => Number(hashParams().get('packet')) || null);
  const [draft, setDraft] = useState('');
  const [applied, setApplied] = useState('');
  const [query, setQuery] = useState({ filter: '', sort: 'number', order: 'asc', page: 1, pageSize: 50, stream: '' });
  const [refresh, setRefresh] = useState(0);
  const [result, setResult] = useState({ items: [], total: 0 });
  const [detail, setDetail] = useState(null);
  const [detailRevision, setDetailRevision] = useState(0);
  const [field, setField] = useState(null);
  const [bytePage, setBytePage] = useState(0);
  const [error, setError] = useState('');
  const [filterError, setFilterError] = useState('');
  const [detailError, setDetailError] = useState('');
  const [loading, setLoading] = useState(false);
  const [stream, setStream] = useState(null);
  const [streamId, setStreamId] = useState(null);
  const [direction, setDirection] = useState('both');
  const [format, setFormat] = useState('text');
  const appliedRef = useRef('');
  useEffect(() => {
    const change = () => { const params = hashParams(); setCapture(params.get('capture') || ''); setFlowId(params.get('flow') || ''); setSelected(Number(params.get('packet')) || null); setStream(null); setStreamId(null); setQuery(q => ({ ...q, page: 1, stream: '' })); };
    window.addEventListener('hashchange', change);
    return () => window.removeEventListener('hashchange', change);
  }, []);
  useEffect(() => {
    if (demoMode) return;
    const controller = new AbortController(); let active = true;
    api('/inspector/captures', { signal: controller.signal }).then(items => { if (active) { setCaptures(items); setCapture(value => value || String(items[0]?.id || '')); } }).catch(e => { if (active && e.name !== 'AbortError') setError(e.message); });
    return () => { active = false; controller.abort(); };
  }, [demoMode, revision, refresh]);
  useEffect(() => {
    if (demoMode || !capture) return;
    const controller = new AbortController(); let active = true;
    const params = new URLSearchParams({ capture_id: capture, filter: query.filter, sort: query.sort, order: query.order, page: query.page, page_size: query.pageSize });
    if (flowId) params.set('flow_id', flowId);
    if (query.stream) params.set('stream_id', query.stream);
    setLoading(true);
    api(`/inspector/packets?${params}`, { signal: controller.signal }).then(data => {
      if (!active) return;
      const filterChanged = !query.background && query.filter !== appliedRef.current;
      setResult(data); setApplied(query.filter); appliedRef.current = query.filter; setError('');
      if (!query.background) setFilterError('');
      setSelected(id => filterChanged && !data.items.some(packet => packet.id === id) ? data.items[0]?.id ?? null : id ?? data.items[0]?.id ?? null);
    }).catch(e => { if (active && e.name !== 'AbortError') { if (!query.background && query.filter !== appliedRef.current) setFilterError(e.message); else setError(e.message); } }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [demoMode, capture, flowId, query, revision, refresh]);
  useEffect(() => {
    setDetail(null); setField(null); setBytePage(0); setDetailError('');
  }, [demoMode, selected, capture]);
  useEffect(() => {
    if (demoMode || !selected) return;
    const controller = new AbortController(); let active = true;
    api(`/inspector/packets/${selected}`, { signal: controller.signal }).then(data => {
      if (!active) return;
      setDetail(data); setDetailError('');
      setField(value => value && data.layers.flatMap(layer => [layer, ...layer.fields]).find(item => item.name === value.name && item.offset === value.offset && item.length === value.length) || null);
    }).catch(e => { if (active && e.name !== 'AbortError') setDetailError(e.message); });
    return () => { active = false; controller.abort(); };
  }, [demoMode, selected, capture, detailRevision]);
  useEffect(() => {
    setStream(null);
  }, [streamId, demoMode, capture]);
  useEffect(() => {
    if (demoMode || streamId === null) return;
    const controller = new AbortController(); let active = true;
    api(`/inspector/streams/${streamId}`, { signal: controller.signal }).then(data => { if (active) setStream(data); }).catch(e => { if (active && e.name !== 'AbortError') setDetailError(e.message); });
    return () => { active = false; controller.abort(); };
  }, [streamId, demoMode, capture, refresh]);
  useEffect(() => {
    if (demoMode) return;
    let timer; let detailTimer; let reconnectTimer; let socket; let delay = 1000; let active = true;
    const completed = new Map();
    const refreshPackets = () => {
      if (!timer) timer = setTimeout(() => { timer = null; if (active) { setQuery(q => ({ ...q, filter: appliedRef.current, background: true })); setRefresh(v => v + 1); } }, 500);
    };
    const refreshDetail = () => {
      if (!detailTimer) detailTimer = setTimeout(() => { detailTimer = null; if (active) setDetailRevision(v => v + 1); }, 500);
    };
    const connect = () => {
      socket = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/ws/monitor`);
      socket.onopen = () => { if (active) { delay = 1000; refreshPackets(); refreshDetail(); } };
      socket.onmessage = event => {
        if (!active) return;
        let message; try { message = JSON.parse(event.data); } catch { return; }
        if (message.type === 'connected') { refreshPackets(); refreshDetail(); }
        if (message.type === 'packet_updates' || message.type === 'capture_imported' || (message.type === 'live_snapshot' && (message.live?.inspection_count !== undefined || message.inspection_count !== undefined))) refreshPackets();
        if (message.type === 'analysis_completed') refreshDetail();
        if (message.type === 'live_snapshot') {
          const live = message.live || message;
          if (live.completed_flows !== undefined && live.completed_flows !== (completed.get(live.capture_id) ?? 0)) refreshDetail();
          if (live.completed_flows !== undefined) completed.set(live.capture_id, live.completed_flows);
        }
      };
      socket.onclose = () => { if (active) { reconnectTimer = setTimeout(connect, delay); delay = Math.min(delay * 2, 30000); } };
      socket.onerror = () => socket.close();
    };
    connect();
    return () => { active = false; clearTimeout(timer); clearTimeout(detailTimer); clearTimeout(reconnectTimer); socket.close(); };
  }, [demoMode]);
  const fieldPage = value => Math.min(Math.floor(value.offset / 256), Math.max(0, Math.ceil((detail?.hex?.length || 0) / 512) - 1));
  const chooseField = value => { setField(value); if (value.offset != null && value.length > 0) setBytePage(fieldPage(value)); };
  const chooseCapture = value => { setCapture(value); setSelected(null); setFlowId(''); setStreamId(null); setQuery(q => ({ ...q, page: 1, stream: '' })); setResult({ items: [], total: 0 }); };
  if (demoMode) return <Panel title="Packet inspector"><p className="context-note">Packet inspection requires real data mode. Sample flows contain no captured packet bytes.</p><a className="text-link" href="#/settings">Switch data mode</a></Panel>;
  const currentCapture = captures.find(item => String(item.id) === capture);
  const bytes = detail?.hex?.match(/.{2}/g) || [];
  const byteStart = bytePage * 256;
  const selectedByte = index => field?.offset != null && index >= field.offset && index < field.offset + field.length;
  const sort = key => setQuery(q => ({ ...q, sort: key, order: q.sort === key && q.order === 'asc' ? 'desc' : 'asc', page: 1 }));
  return <div className="packet-inspector">
    <div className="inspector-toolbar"><label>Capture <select aria-label="Inspect capture" value={capture} onChange={e => chooseCapture(e.target.value)}><option value="">Select capture</option>{captures.map(item => <option key={item.id} value={item.id}>{item.filename || `Capture ${item.id}`} · {item.source === 'live' ? 'Live' : 'PCAP'} · {item.inspection_count ?? item.packet_count} packets</option>)}</select></label><a className="text-link" href="#/monitoring">Live capture controls</a><a className="text-link" href="#/traffic">Import PCAP</a></div>
    {(currentCapture?.notice || currentCapture?.legacy || result.notice) && <p className="sample-callout">{result.notice || currentCapture.notice || 'Legacy capture: raw packet bytes were not retained.'}</p>}
    <form className="inspector-filter" onSubmit={e => { e.preventDefault(); setQuery(q => ({ ...q, filter: draft, page: 1, background: false })); }}><label htmlFor="display-filter">Display filter</label><input id="display-filter" value={draft} onChange={e => setDraft(e.target.value)} placeholder="tcp && ip.addr == 192.168.1.10"/><button className="button primary" type="submit">Apply filter</button><label>Preset <select aria-label="Filter preset" value="" onChange={e => { setDraft(e.target.value); }}><option value="" disabled>Choose…</option>{Object.entries(presets).map(([name, value]) => <option key={name} value={value}>{name}</option>)}</select></label></form>
    <div className="inspector-status"><span>Applied: <code>{applied || 'All packets'}</code></span>{flowId && <button className="button" onClick={() => { setFlowId(''); setQuery(q => ({ ...q, page: 1 })); }}>Clear flow {flowId}</button>}{query.stream && <button className="button" onClick={() => { setQuery(q => ({ ...q, stream: '', page: 1 })); setStream(null); setStreamId(null); }}>Reset conversation</button>}<details><summary>Filter syntax</summary><p>Subset: ip, ipv6, arp, tcp, udp, icmp, dns, http, tls; &&, ||, ! (and/or/not), parentheses, == != &gt; &gt;= &lt; &lt;=. Fields: ip/ipv6.addr, .src, .dst; tcp/udp.port, .srcport, .dstport; tcp.flags.syn/ack/fin/rst; frame.len, .number, .time_epoch, .time_relative; tcp.stream. Exact IPs only; no CIDR or full Wireshark syntax.</p></details></div>
    {filterError && <p className="error-message" role="alert">{filterError}</p>}{error && <p className="error-message" role="alert">{error}</p>}
    <div className="inspector-panes"><Panel title="Packets" subtitle={`${result.total} matching packets${loading ? ' · Loading…' : ''}`}><div className="inspector-table-scroll"><table className="packet-table"><thead><tr>{[['number', 'No.'], ['timestamp', 'Time (UTC)'], ['source', 'Source'], ['destination', 'Destination'], ['protocol', 'Protocol'], ['length', 'Length']].map(([key, name]) => <th key={key} aria-sort={query.sort === key ? query.order === 'asc' ? 'ascending' : 'descending' : 'none'}><button onClick={() => sort(key)}>{name}{query.sort === key ? query.order === 'asc' ? ' ↑' : ' ↓' : ''}</button></th>)}<th>Info</th></tr></thead><tbody>{result.items.map(packet => <tr key={packet.id} className={`protocol-${String(packet.protocol).toLowerCase()} ${selected === packet.id ? 'selected' : ''}`}><td><button aria-label={`Inspect packet ${packet.number}`} aria-pressed={selected === packet.id} onClick={() => setSelected(packet.id)}>{packet.number}</button></td><td>{packet.timestamp ? new Date(packet.timestamp).toISOString().slice(11, 23) : '—'}</td><td>{packet.source}</td><td>{packet.destination}</td><td>{packet.protocol}</td><td>{packet.length}</td><td>{packet.summary}</td></tr>)}</tbody></table>{!result.items.length && <p className="context-note">{capture ? 'No matching packets.' : 'Choose a capture or import a PCAP.'}</p>}</div><div className="inspector-pagination"><button className="button" disabled={query.page <= 1 || loading} onClick={() => setQuery(q => ({ ...q, page: q.page - 1 }))}>Previous packets</button><span>Page {query.page} of {Math.max(1, Math.ceil(result.total / query.pageSize))}</span><button className="button" disabled={query.page * query.pageSize >= result.total || loading} onClick={() => setQuery(q => ({ ...q, page: q.page + 1 }))}>Next packets</button><select aria-label="Packets per page" value={query.pageSize} onChange={e => setQuery(q => ({ ...q, pageSize: Number(e.target.value), page: 1 }))}><option value={50}>50 rows</option><option value={100}>100 rows</option></select></div></Panel>
    <Panel title="Protocol details" subtitle={detail ? `Packet ${detail.packet.number} · ${detail.packet.protocol}` : 'Select a packet'}>{detailError && <p role="alert" className="error-message">{detailError}</p>}{detail && <><div className="layer-tree">{detail.layers.map((layer, i) => <details key={`${layer.name}-${i}`} open><summary onClick={() => chooseField(layer)}>{layer.name} <small>{layer.offset != null ? `${layer.offset} + ${layer.length} bytes` : ''}</small></summary>{layer.fields.map((item, j) => <button key={j} className={field === item ? 'selected' : ''} onClick={() => chooseField(item)}>{item.name}: {String(item.value)} <small>{item.offset != null ? `[${item.offset}:${item.length}]` : 'No byte range'}</small></button>)}</details>)}</div>{detail.warnings?.map((warning, i) => <p className="context-note" key={i}>{warning}</p>)}<div className="inspector-links">{detail.packet.stream_id != null && <button className="button" onClick={() => { setStreamId(detail.packet.stream_id); setQuery(q => ({ ...q, stream: detail.packet.stream_id, page: 1 })); }}>Follow TCP stream</button>}{detail.flow && inspect && <button className="button" onClick={() => inspect(detail.flow)}>Inspect linked flow</button>}{detail.detection && <p>Model: {detail.detection.category} · {(detail.detection.confidence * 100).toFixed(1)}% · {detail.detection.severity}</p>}{detail.alerts?.length > 0 && <a href="#/alerts" className="text-link">Review {detail.alerts.length} linked alert(s)</a>}</div></>}</Panel>
    <Panel title="Packet bytes" subtitle="Hexadecimal and ASCII · 256 bytes per page">{!bytes.length ? <p className="context-note">{detail ? `Raw bytes unavailable (${detail.packet.raw_status || 'not retained'}). Legacy captures and retention limits may leave summaries only.` : 'Select a packet to view retained bytes.'}</p> : <><div className="inspector-pagination"><button className="button" disabled={!bytePage} onClick={() => setBytePage(p => p - 1)}>Previous bytes</button><span>Bytes {byteStart}–{Math.min(byteStart + 255, bytes.length - 1)} of {bytes.length}</span><button className="button" disabled={byteStart + 256 >= bytes.length} onClick={() => setBytePage(p => p + 1)}>Next bytes</button>{field?.offset != null && field.length > 0 && <button className="button" onClick={() => setBytePage(fieldPage(field))}>Jump to selected field</button>}</div>{field?.offset != null && field.offset + field.length > bytes.length && <p className="context-note">Selected field includes bytes that were not retained.</p>}<div className="hex-view" aria-label="Packet bytes">{Array.from({ length: Math.ceil(bytes.slice(byteStart, byteStart + 256).length / 16) }, (_, row) => { const start = byteStart + row * 16; const line = bytes.slice(start, start + 16); return <div className="hex-line" key={start}><span className="hex-offset">{start.toString(16).padStart(6, '0')}</span><span className="hex-values">{line.map((value, i) => selectedByte(start + i) ? <mark className="hex-byte" key={i}>{value}</mark> : <span className="hex-byte" key={i}>{value}</span>)}</span><span className="ascii-values">{line.map((value, i) => { const n = parseInt(value, 16); const char = n >= 32 && n <= 126 ? String.fromCharCode(n) : '.'; return selectedByte(start + i) ? <mark key={i}>{char}</mark> : <span key={i}>{char}</span>; })}</span></div>; })}</div></>}</Panel></div>
    {stream && <Panel title="TCP conversation" subtitle="Retained stream bytes; gaps and retransmissions may affect reconstruction"><div className="inspector-toolbar"><label>Direction <select aria-label="Stream direction" value={direction} onChange={e => setDirection(e.target.value)}><option value="both">Both directions</option>{stream.directions.map(d => <option key={d.name} value={d.name}>{d.name}</option>)}</select></label><label>Format <select aria-label="Stream format" value={format} onChange={e => setFormat(e.target.value)}><option value="text">Text</option><option value="hex">Hex</option></select></label></div>{stream.warnings?.map((warning, i) => <p className="context-note" key={i}>{warning}</p>)}{stream.directions.filter(d => direction === 'both' || d.name === direction).map(d => <section key={d.name}><h3>{d.name}: {d.source} → {d.destination}</h3><p className="context-note">{d.retransmissions || 0} retransmissions · {d.gaps?.length || 0} gaps{d.truncated ? ' · Retention truncated' : ''}</p>{d.gaps?.map((gap, i) => <p key={i}>Gap at {gap.offset}: {gap.length} bytes</p>)}<pre className="stream-content">{format === 'text' ? d.text : d.hex}</pre><details><summary>Packet provenance</summary>{d.segments?.map((segment, i) => <button className="button" key={i} onClick={() => setSelected(segment.packet_id)}>Packet {segment.packet_id} · stream offset {segment.offset} · {segment.length} bytes</button>)}</details></section>)}</Panel>}
  </div>;
}


