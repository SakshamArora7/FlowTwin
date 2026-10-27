import { useCallback, useEffect, useState } from 'react';
import { AnimatePresence, motion, MotionConfig } from 'framer-motion';
import { Activity, ArrowRight, Bell, BookOpen, BrainCircuit, Check, ChevronDown, CircleHelp, FileBarChart2, FlaskConical, LayoutDashboard, Menu, Network, Radio, RefreshCw, Settings2, Shield, ShieldCheck, ShieldX, TriangleAlert, X } from 'lucide-react';
import { api } from './api';
import { Badge, bytes, clock, Empty, FlowDialog, number, Panel, PhaseNote, Skeleton, TextLink } from './components';
import { TrafficPage, SettingsPage } from './pages';
import { HorizontalChart, ProtocolChart, Timeline } from './charts';
import { DetectionPage, MonitoringPage, AlertsPage, AnalyticsPage, ReportsPage } from './advanced-pages';

const navigation = [
  ['dashboard', 'Dashboard', LayoutDashboard], ['traffic', 'Network Traffic', Network], ['detection', 'AI Threat Detection', BrainCircuit], ['monitoring', 'Live Monitoring', Radio], ['alerts', 'Security Alerts', Bell], ['analytics', 'Analytics', Activity], ['reports', 'Reports', FileBarChart2], ['settings', 'Settings', Settings2],
];
const route = () => navigation.some(([id]) => id === location.hash.slice(2)) ? location.hash.slice(2) : 'dashboard';
const descriptions = {
  dashboard: 'A clearer view of your network. A smarter approach to security.', traffic: 'Explore connections, protocols, and the flow of information.', detection: 'Understand the signals behind every potential threat.', monitoring: 'Your workspace for real-time network visibility.', alerts: 'Review security events and investigate what matters.', analytics: 'Turn network activity into a bigger picture.', reports: 'Keep your findings organized and ready to share.', settings: 'Configure your workspace and data preferences.',
};

function Stats({ data }) {
  return <div className="stats-grid">{[
    ['Total network flows', data.total, Network, 'cyan', 'All connections in this window'], ['Benign traffic', data.benign, ShieldCheck, 'benign', 'Sample normal activity'], ['Suspicious traffic', data.suspicious, TriangleAlert, 'suspicious', 'Sample activity to investigate'], ['Malicious traffic', data.malicious, ShieldX, 'malicious', 'Threats in this window'],
  ].map(([title, value, Icon, tone, caption], i) => <motion.div key={title} className={`stat-card ${tone}`} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}><div className="stat-top"><span>{title}</span><div className="stat-icon"><Icon size={19}/></div></div><div className="stat-value">{number(value)}<span>{data.total ? `${Math.round(value / data.total * 100)}%` : '—'}</span></div><div className="stat-caption"><span className="tiny-dot"/>{data.is_demo ? caption : data.total ? 'Imported PCAP data' : 'No imported traffic yet'}</div></motion.div>)}</div>;
}

function AlertList({ alerts, inspect, full = false }) {
  if (!alerts.length) return <Empty title="No security events" />;
  return <div className="alert-list">{alerts.map(flow => <button key={flow.id} className="alert-row" onClick={() => inspect(flow)}><div className={`alert-icon ${flow.classification}`}><TriangleAlert size={16}/></div><div className="alert-main"><strong>{flow.category}{flow.is_demo && <span className="sample-tag">SAMPLE</span>}</strong><span className="mono">{flow.source} <ArrowRight size={12}/> {flow.destination}</span></div>{full && <span className="muted mono">FT-{String(flow.id).padStart(4, '0')}</span>}<div className="alert-end"><Badge tone={flow.classification}>{flow.classification === 'malicious' ? 'High' : 'Medium'}</Badge><small>{clock(flow.timestamp)} UTC</small></div></button>)}</div>;
}

function Dashboard({ data, inspect }) {
  return <><Stats data={data}/><div className="dashboard-main-grid"><Panel title="Traffic activity" subtitle="Flow volume over time · UTC" action={<div className="legend"><span><i className="bg-emerald-300"/>Benign</span><span><i className="bg-amber-300"/>Suspicious</span><span><i className="bg-rose-400"/>Malicious</span></div>}><Timeline data={data.timeline}/><div className="chart-footer"><span><span className="tiny-dot"/> {data.is_demo ? 'Static sample dataset' : 'Imported PCAP data'}</span><span>{number(data.packets)} packets <i>·</i> {bytes(data.bytes)} transferred</span></div></Panel><Panel title="Protocol distribution" subtitle="A breakdown of network connections" action={<Network size={17} className="muted"/>}><ProtocolChart data={data.protocols} total={data.total}/></Panel></div><div className="dashboard-bottom-grid"><Panel title="Recent security alerts" subtitle={data.is_demo ? "Illustrative sample events" : "Trained model findings"} action={<TextLink to="alerts">View all</TextLink>}><AlertList alerts={data.alerts.slice(0, 4)} inspect={inspect}/></Panel><Panel title="Threat distribution" subtitle={data.is_demo ? "Sample labels · not predictions" : "Predicted categories"} action={<Shield size={17} className="muted"/>}><HorizontalChart data={data.threats}/><div className="chart-footer"><span>{number(data.suspicious + data.malicious)} {data.is_demo ? "sample flagged flows" : "model flagged flows"}</span><TextLink to="detection">Explore detection</TextLink></div></Panel></div><div className="workspace-note"><div><FlaskConical size={18}/><span><strong>{data.is_demo ? "Explore safely." : "Analyze traffic."}</strong> {data.is_demo ? "Sample mode contains illustrative records only." : "Imported PCAP flows are measured from packet data."}</span></div><TextLink to="settings">Data preferences</TextLink></div></>;
}

function OtherPages({ page, data, inspect, revision, refresh }) {
  if (page === 'detection') return <DetectionPage demoMode={data.is_demo} revision={revision} inspect={inspect}/>;
  if (page === 'monitoring') return <MonitoringPage demoMode={data.is_demo} revision={revision}/>;
  if (page === 'alerts') return <AlertsPage demoMode={data.is_demo} data={data} revision={revision} inspect={inspect} onRefresh={refresh}/>;
  if (page === 'analytics') return <AnalyticsPage data={data} demoMode={data.is_demo} revision={revision}/>;
  if (page === 'reports') return <ReportsPage data={data} demoMode={data.is_demo}/>;
  return null;
}

export default function App() {
  const [page, setPage] = useState(route);
  const [menu, setMenu] = useState(false);
  const [hours, setHours] = useState(24);
  const [bundle, setBundle] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(true);
  const [revision, setRevision] = useState(0);
  const [flow, setFlow] = useState(null);
  const [updated, setUpdated] = useState(null);
  const [help, setHelp] = useState(false);
  const [notice, setNotice] = useState('');
  useEffect(() => { const change = () => { setPage(route()); setMenu(false); }; window.addEventListener('hashchange', change); return () => window.removeEventListener('hashchange', change); }, []);
  const refresh = useCallback(() => setRevision(v => v + 1), []);
  useEffect(() => {
    let cancelled = false;
    setBusy(true);
    Promise.all([api('/health'), api('/settings'), api(`/overview?hours=${hours}`)]).then(([health, settings, data]) => {
      if (!cancelled) { setBundle({ health, settings, data }); setError(''); setUpdated(new Date()); }
    }).catch(e => { if (!cancelled) { setError(`Cannot connect to the backend. Start FastAPI on port 8000, then retry. ${e.message}`); setBundle(null); } }).finally(() => { if (!cancelled) setBusy(false); });
    return () => { cancelled = true; };
  }, [hours, revision]);
  useEffect(() => { if (!bundle) return; const timer = setInterval(refresh, bundle.settings.refresh_seconds * 1000); return () => clearInterval(timer); }, [bundle?.settings.refresh_seconds, refresh]);
  useEffect(() => {
    if (!bundle || bundle.settings.demo_mode) return;
    const socket = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/ws/monitor`);
    socket.onmessage = event => {
      const message = JSON.parse(event.data);
      if (message.type === 'capture_imported' || message.type === 'analysis_completed') refresh();
    };
    return () => socket.close();
  }, [bundle?.settings.demo_mode, refresh]);
  const onSettingsSaved = () => { setNotice('Workspace preferences saved.'); setBundle(null); setFlow(null); refresh(); };
  const title = navigation.find(([id]) => id === page)[1];
  return <MotionConfig reducedMotion="user"><div className="app-shell">
    {menu && <button className="nav-scrim" onClick={() => setMenu(false)} aria-label="Close navigation"/>}
    <aside className={`sidebar ${menu ? 'open' : ''}`}><a href="#/dashboard" className="brand"><div className="brand-icon"><ShieldCheck size={24}/></div><div>Flow<span>Twin</span><small>NETWORK INTELLIGENCE</small></div></a><div className="workspace-select"><div className="workspace-avatar">F</div><div>Local workspace<small>Student project</small></div><span className="workspace-version">v1.0</span></div><div className="nav-caption">WORKSPACE</div><nav aria-label="Main navigation">{navigation.map(([id, label, Icon]) => <a href={`#/${id}`} key={id} className={`nav-item ${page === id ? 'active' : ''}`} aria-current={page === id ? 'page' : undefined}><Icon size={18}/><span>{label}</span>{id === 'detection' && <span className="ai-tag">AI</span>}{id === 'alerts' && !!bundle?.data.alerts.length && <span className="nav-count">{bundle.data.alerts.length}</span>}</a>)}</nav><div className="sidebar-bottom"><div className="foundation-card"><div><span className="tiny-dot"/> COMPLETE APPLICATION</div><h3>Analysis workspace</h3><p>Capture · Detect · Investigate</p><div className="phase-progress"><i/><i/><i/><i/></div><span>Four integrated modules</span></div><button className="help-button" onClick={() => setHelp(!help)}><CircleHelp size={18}/> Project guide <ArrowUpRightIcon/></button><div className="sidebar-footer"><div className="user-avatar">FT</div><div>FlowTwin Lab<small>Local environment</small></div><span className="online-dot"/></div></div></aside>
    <div className="main-shell"><header className="topbar"><div className="breadcrumb"><button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMenu(!menu)}><Menu size={20}/></button><span>Workspace</span><span className="slash">/</span><strong>{title}</strong></div><div className="topbar-actions"><span className={`connection-status ${bundle ? 'connected' : ''}`}><span className="tiny-dot"/>{bundle ? 'API connected' : busy ? 'Connecting…' : 'API offline'}</span><a href="#/alerts" className="icon-button notification-button" aria-label="View security alerts"><Bell size={18}/>{bundle?.data.alerts.length > 0 && <i/>}</a><div className="top-avatar">FT</div></div></header>
    <main id="main-content"><div className="page-heading"><div><div className="eyebrow">NETWORK SECURITY WORKSPACE</div><h1>{page === 'dashboard' ? 'Security overview' : title}<span className="heading-dot">.</span></h1><p>{descriptions[page]}</p></div><div className="page-actions"><label className="select-wrap"><Activity size={15}/><select aria-label="Data time window" value={hours} onChange={e => setHours(Number(e.target.value))}><option value={24}>Last 24 hours</option><option value={6}>Last 6 hours</option><option value={1}>Last hour</option></select><ChevronDown size={14}/></label><button className="button" onClick={refresh} disabled={busy}><RefreshCw size={15} className={busy ? 'spin' : ''}/>Refresh</button></div></div>
    <div className={`mode-banner ${bundle && !bundle.data.is_demo ? 'empty-mode' : ''}`}><FlaskConical size={17}/><strong>{bundle ? bundle.data.is_demo ? 'Sample data mode' : 'Real data workspace' : 'Data source unverified'}</strong><span>{bundle ? bundle.data.is_demo ? 'Illustrative traffic only. Switch to real data for PCAP analysis.' : 'Import a PCAP to analyze real network flows and generate model findings.' : 'Waiting for a backend connection. No local fallback data is shown.'}</span><a href="#/settings">Manage <ArrowRight size={14}/></a></div>
    {notice && <div className="save-notice" role="status"><Check size={15}/>{notice}<button className="icon-button" aria-label="Dismiss notification" onClick={() => setNotice('')}><X size={14}/></button></div>}
    {help && <div className="help-panel"><button className="icon-button" onClick={() => setHelp(false)} aria-label="Close project guide"><X size={18}/></button><BookOpen size={23}/><div><h3>Your project, in four phases</h3><p>01 Foundation & dashboard · 02 Packet analysis · 03 Machine learning · 04 Monitoring, alerts & reports</p><p>Use Settings to switch between illustrative sample data and imported PCAP data. Network Traffic accepts captures; Monitoring replays them.</p><a href="http://127.0.0.1:8000/docs" target="_blank" rel="noreferrer" className="text-link">Open local API documentation <ArrowRight size={14}/></a></div></div>}
    {error ? <div className="error-panel" role="alert"><TriangleAlert size={26}/><h2>Backend connection unavailable</h2><p>{error}</p><button className="button primary" onClick={refresh}>Retry connection</button></div> : !bundle ? <Skeleton/> : <AnimatePresence mode="wait"><motion.div key={page} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.16 }} className="page-content">{page === 'dashboard' ? <Dashboard data={bundle.data} inspect={setFlow}/> : page === 'traffic' ? <TrafficPage revision={revision} demoMode={bundle.settings.demo_mode} inspect={setFlow} onImported={refresh}/> : page === 'settings' ? <SettingsPage settings={bundle.settings} onSaved={onSettingsSaved} health={bundle.health}/> : <OtherPages page={page} data={bundle.data} inspect={setFlow} revision={revision} refresh={refresh}/>}</motion.div></AnimatePresence>}
    <footer className="main-footer"><span><Shield size={13}/> FlowTwin <span className="footer-divider">/</span> Intelligent malware traffic detection</span><span>{bundle?.data.window_end && bundle.data.is_demo ? `Fixture · ${new Date(bundle.data.window_end).toLocaleDateString('en-GB', { timeZone: 'UTC' })} UTC` : 'Imported traffic workspace'}<span className="footer-divider">/</span>{updated && bundle ? `Fetched ${updated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : 'Not connected'}</span></footer>
    </main></div>{flow && <FlowDialog flow={flow} close={() => setFlow(null)}/>}</div></MotionConfig>;
}

function ArrowUpRightIcon() { return <ArrowRight size={14} className="-rotate-45"/>; }
