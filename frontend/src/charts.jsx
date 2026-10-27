import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Empty, clock, number } from './components';

const colors = ['#31d6c4', '#6395ff', '#ad8bf5', '#ffb454'];

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return <div className="chart-tooltip"><strong>{typeof label === 'string' && label.includes('T') ? `${clock(label)} UTC` : label}</strong>{payload.map((p, i) => <div key={i}><span style={{ color: p.color || p.payload.fill }}>{p.name}</span><b>{number(p.value)}</b></div>)}</div>;
}

export function Timeline({ data }) {
  if (!data.length) return <Empty />;
  return <div className="chart timeline-chart" role="img" aria-label="Sample flow counts over time by classification"><ResponsiveContainer width="100%" height="100%"><AreaChart data={data} margin={{ top: 12, right: 12, left: -24, bottom: 0 }}>
    <defs><linearGradient id="benignFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#31d6c4" stopOpacity={0.22}/><stop offset="100%" stopColor="#31d6c4" stopOpacity={0}/></linearGradient></defs>
    <CartesianGrid stroke="#202c3c" strokeDasharray="3 5" vertical={false}/><XAxis dataKey="time" tickFormatter={clock} minTickGap={45} tick={{ fill: '#78879c', fontSize: 11 }} tickLine={false} axisLine={false} dy={10}/><YAxis allowDecimals={false} tick={{ fill: '#78879c', fontSize: 11 }} tickLine={false} axisLine={false}/><Tooltip content={<ChartTooltip />} />
    <Area type="monotone" dataKey="benign" name="Benign" stroke="#31d6c4" strokeWidth={2.5} fill="url(#benignFill)" animationDuration={650}/><Area type="monotone" dataKey="suspicious" name="Suspicious" stroke="#ffb454" strokeWidth={2} fill="transparent" animationDuration={650}/><Area type="monotone" dataKey="malicious" name="Malicious" stroke="#f57386" strokeWidth={2} fill="transparent" animationDuration={650}/>
  </AreaChart></ResponsiveContainer></div>;
}

export function ProtocolChart({ data, total }) {
  if (!data.length) return <Empty />;
  return <><div className="donut-wrap"><ResponsiveContainer width="100%" height={190}><PieChart><Pie data={data} dataKey="value" nameKey="name" innerRadius={65} outerRadius={84} paddingAngle={5} stroke="none" cornerRadius={4} animationDuration={650}>{data.map((d, i) => <Cell key={d.name} fill={colors[i % colors.length]} />)}</Pie><Tooltip content={<ChartTooltip />} /></PieChart></ResponsiveContainer><div className="donut-label"><b>{number(total)}</b><span>TOTAL FLOWS</span></div></div><div className="protocol-legend">{data.map((d, i) => <div key={d.name}><span className="legend-dot" style={{ background: colors[i] }}/><span>{d.name}</span><b>{number(d.value)}</b><small>{Math.round(d.value / total * 100)}%</small></div>)}</div></>;
}

export function HorizontalChart({ data, color = '#6395ff', measure = 'Flows' }) {
  if (!data.length) return <Empty title="No matching activity" />;
  return <div className="chart bar-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={data} layout="vertical" margin={{ left: 0, right: 24 }}><CartesianGrid stroke="#202c3c" strokeDasharray="3 5" horizontal={false}/><XAxis type="number" allowDecimals={false} tick={{ fill: '#78879c', fontSize: 11 }} axisLine={false} tickLine={false}/><YAxis type="category" dataKey="name" width={128} tick={{ fill: '#a3b1c5', fontSize: 11 }} axisLine={false} tickLine={false}/><Tooltip content={<ChartTooltip />}/><Bar dataKey="value" name={measure} fill={color} barSize={13} radius={[0, 3, 3, 0]} animationDuration={650}/></BarChart></ResponsiveContainer></div>;
}

