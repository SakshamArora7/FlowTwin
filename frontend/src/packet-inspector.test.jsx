import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, afterEach, expect, it, vi } from 'vitest';
import { PacketInspectorPage } from './packet-inspector';
import { api } from './api';
vi.mock('./api', () => ({ api: vi.fn() }));
let socket;
class Socket { constructor() { socket = this; } close() {} }
const packet = { id: 7, number: 1, source: '10.0.0.1', destination: '10.0.0.2', protocol: 'TCP', length: 300, summary: 'SYN', stream_id: 2 };
beforeEach(() => {
  location.hash = '#/inspector?capture=3&packet=7';
  vi.stubGlobal('WebSocket', Socket);
  api.mockImplementation(path => {
    if (path === '/inspector/captures') return Promise.resolve([{ id: 3, filename: 'test.pcap', packet_count: 1 }]);
    if (path.startsWith('/inspector/packets?')) return path.includes('filter=bad') ? Promise.reject(new Error('Unknown display field')) : Promise.resolve({ items: [packet], total: 1 });
    if (path === '/inspector/streams/2') return Promise.resolve({ directions: [{ name: 'forward', text: 'GET /hello', hex: '474554', gaps: [], segments: [{ packet_id: 7, offset: 0, length: 3 }] }], warnings: [] });
    return Promise.resolve({ packet, hex: '41'.repeat(300), layers: [{ name: 'TCP', offset: 260, length: 4, fields: [{ name: 'Sequence number', value: 42, offset: 260, length: 4 }] }], warnings: [], alerts: [] });
  });
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.clearAllMocks(); });
it('loads URL capture and packet, expands fields and highlights exact paged bytes', async () => {
  render(<PacketInspectorPage demoMode={false}/>);
  fireEvent.click(await screen.findByText(/Sequence number: 42/));
  expect(screen.getByLabelText('Packet bytes').querySelectorAll('mark.hex-byte')).toHaveLength(4);
  expect(screen.getByText('Bytes 256–299 of 300')).toBeInTheDocument();
  expect(api.mock.calls.some(([path]) => path.includes('capture_id=3'))).toBe(true);
});
it('keeps selected packet and results after an invalid filter', async () => {
  render(<PacketInspectorPage demoMode={false}/>);
  await screen.findByText(/Sequence number: 42/);
  fireEvent.change(screen.getByLabelText('Display filter'), { target: { value: 'bad' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filter' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Unknown display field');
  expect(screen.getByText(/Sequence number: 42/)).toBeInTheDocument();
  expect(screen.getByRole('cell', { name: 'SYN' })).toBeInTheDocument();
});
it('refreshes on packet updates and follows a TCP conversation', async () => {
  render(<PacketInspectorPage demoMode={false}/>);
  fireEvent.click(await screen.findByRole('button', { name: 'Follow TCP stream' }));
  expect(await screen.findByText('GET /hello')).toBeInTheDocument();
  const before = api.mock.calls.filter(([path]) => path.startsWith('/inspector/packets?')).length;
  act(() => socket.onmessage({ data: JSON.stringify({ type: 'packet_updates', capture_id: 3 }) }));
  await waitFor(() => expect(api.mock.calls.filter(([path]) => path.startsWith('/inspector/packets?')).length).toBeGreaterThan(before));
});
it('never loads real data in sample mode', () => {
  render(<PacketInspectorPage demoMode/>);
  expect(screen.getByText(/Packet inspection requires real data mode/)).toBeInTheDocument();
  expect(api).not.toHaveBeenCalled();
});
it('ignores a stale packet detail response after another packet is selected', async () => {
  let finishOld;
  const previous = api.getMockImplementation();
  api.mockImplementation(path => path === '/inspector/packets/7' ? new Promise(resolve => { finishOld = resolve; }) : path === '/inspector/packets/8' ? Promise.resolve({ packet: { ...packet, id: 8, number: 2 }, layers: [], hex: '', warnings: [], alerts: [] }) : path.startsWith('/inspector/packets?') ? Promise.resolve({ items: [packet, { ...packet, id: 8, number: 2 }], total: 2 }) : previous(path));
  render(<PacketInspectorPage demoMode={false}/>);
  fireEvent.click(await screen.findByRole('button', { name: 'Inspect packet 2' }));
  await screen.findByText('Packet 2 · TCP');
  await act(async () => finishOld({ packet, layers: [], hex: '', warnings: [], alerts: [] }));
  expect(screen.getByText('Packet 2 · TCP')).toBeInTheDocument();
  expect(screen.queryByText('Packet 1 · TCP')).not.toBeInTheDocument();
});
it('keeps the byte page valid when a truncated field extends beyond retained bytes', async () => {
  const previous = api.getMockImplementation();
  api.mockImplementation(path => path === '/inspector/packets/7' ? Promise.resolve({ packet, hex: '41'.repeat(20), layers: [{ name: 'TCP', fields: [{ name: 'Payload', value: 'truncated', offset: 1000, length: 50 }] }], warnings: [] }) : previous(path));
  render(<PacketInspectorPage demoMode={false}/>);
  fireEvent.click(await screen.findByText(/Payload: truncated/));
  expect(screen.getByText('Bytes 0–19 of 20')).toBeInTheDocument();
  expect(screen.getByText(/Selected field includes bytes that were not retained/)).toBeInTheDocument();
});
it('preserves a rejected filter message while refreshing the applied filter in background', async () => {
  render(<PacketInspectorPage demoMode={false}/>);
  await screen.findByText(/Sequence number: 42/);
  fireEvent.change(screen.getByLabelText('Display filter'), { target: { value: 'bad' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filter' }));
  await screen.findByRole('alert');
  vi.useFakeTimers();
  await act(async () => { socket.onmessage({ data: JSON.stringify({ type: 'packet_updates' }) }); await vi.advanceTimersByTimeAsync(500); });
  expect(screen.getByRole('alert')).toHaveTextContent('Unknown display field');
  expect(screen.getByLabelText('Display filter')).toHaveValue('bad');
  expect(screen.getByRole('cell', { name: 'SYN' })).toBeInTheDocument();
});
it('reconnects a dropped socket and refreshes after connection opens', async () => {
  render(<PacketInspectorPage demoMode={false}/>);
  await screen.findByText(/Sequence number: 42/);
  const oldSocket = socket;
  const before = api.mock.calls.length;
  vi.useFakeTimers();
  await act(async () => { oldSocket.onclose?.(); await vi.advanceTimersByTimeAsync(1000); });
  expect(socket).not.toBe(oldSocket);
  await act(async () => { socket.onopen(); await vi.advanceTimersByTimeAsync(500); });
  expect(api.mock.calls.length).toBeGreaterThan(before);
});
it('refreshes completed flow metadata while preserving the selected field and byte page', async () => {
  let completed = false;
  const previous = api.getMockImplementation();
  api.mockImplementation(async path => { const response = await previous(path); return path === '/inspector/packets/7' && completed ? { ...response, detection: { category: 'Benign', confidence: 0.99, severity: 'low' } } : response; });
  render(<PacketInspectorPage demoMode={false}/>);
  fireEvent.click(await screen.findByText(/Sequence number: 42/));
  completed = true;
  vi.useFakeTimers();
  await act(async () => { socket.onmessage({ data: JSON.stringify({ type: 'analysis_completed' }) }); await vi.advanceTimersByTimeAsync(500); });
  expect(screen.getByText('Model: Benign · 99.0% · low')).toBeInTheDocument();
  expect(screen.getByText('Bytes 256–299 of 300')).toBeInTheDocument();
  expect(screen.getByLabelText('Packet bytes').querySelectorAll('mark.hex-byte')).toHaveLength(4);
  const before = api.mock.calls.filter(([path]) => path === '/inspector/packets/7').length;
  await act(async () => { socket.onmessage({ data: JSON.stringify({ type: 'packet_updates' }) }); await vi.advanceTimersByTimeAsync(500); });
  expect(api.mock.calls.filter(([path]) => path === '/inspector/packets/7')).toHaveLength(before);
  await act(async () => { socket.onmessage({ data: JSON.stringify({ type: 'live_snapshot', live: { capture_id: 3, completed_flows: 2 } }) }); await vi.advanceTimersByTimeAsync(500); });
  expect(api.mock.calls.filter(([path]) => path === '/inspector/packets/7')).toHaveLength(before + 1);
  await act(async () => { socket.onmessage({ data: JSON.stringify({ type: 'live_snapshot', live: { capture_id: 3, completed_flows: 2 } }) }); await vi.advanceTimersByTimeAsync(500); });
  expect(api.mock.calls.filter(([path]) => path === '/inspector/packets/7')).toHaveLength(before + 1);
});
it('refreshes an open live stream on packet updates without reloading detail or losing view choices', async () => {
  let updated = false;
  const previous = api.getMockImplementation();
  api.mockImplementation(async path => { const response = await previous(path); return path === '/inspector/streams/2' && updated ? { ...response, directions: response.directions.map(d => ({ ...d, hex: '47455421' })) } : response; });
  render(<PacketInspectorPage demoMode={false}/>);
  fireEvent.click(await screen.findByRole('button', { name: 'Follow TCP stream' }));
  await screen.findByText('GET /hello');
  fireEvent.change(screen.getByLabelText('Stream direction'), { target: { value: 'forward' } });
  fireEvent.change(screen.getByLabelText('Stream format'), { target: { value: 'hex' } });
  const before = api.mock.calls.filter(([path]) => path === '/inspector/packets/7').length;
  updated = true;
  vi.useFakeTimers();
  await act(async () => { socket.onmessage({ data: JSON.stringify({ type: 'packet_updates' }) }); await vi.advanceTimersByTimeAsync(500); });
  expect(screen.getByText('47455421')).toBeInTheDocument();
  expect(screen.getByLabelText('Stream direction')).toHaveValue('forward');
  expect(screen.getByLabelText('Stream format')).toHaveValue('hex');
  expect(screen.getByRole('button', { name: 'Inspect packet 1' })).toHaveAttribute('aria-pressed', 'true');
  expect(api.mock.calls.filter(([path]) => path === '/inspector/packets/7')).toHaveLength(before);
});
it('reconciles a packet excluded by an explicitly changed filter and clears detail for an empty filter result', async () => {
  const previous = api.getMockImplementation();
  api.mockImplementation(path => path.startsWith('/inspector/packets?') && path.includes('filter=tcp') ? Promise.resolve({ items: [{ ...packet, id: 8, number: 2 }], total: 1 }) : path.startsWith('/inspector/packets?') && path.includes('filter=udp') ? Promise.resolve({ items: [], total: 0 }) : path === '/inspector/packets/8' ? Promise.resolve({ packet: { ...packet, id: 8, number: 2 }, layers: [], hex: '42', warnings: [] }) : previous(path));
  render(<PacketInspectorPage demoMode={false}/>);
  await screen.findByText(/Sequence number: 42/);
  fireEvent.change(screen.getByLabelText('Display filter'), { target: { value: 'tcp' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filter' }));
  await screen.findByText('Packet 2 · TCP');
  expect(screen.getByRole('button', { name: 'Inspect packet 2' })).toHaveAttribute('aria-pressed', 'true');
  fireEvent.change(screen.getByLabelText('Display filter'), { target: { value: 'udp' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filter' }));
  await screen.findByText('No matching packets.');
  await waitFor(() => expect(screen.queryByText('Packet 2 · TCP')).not.toBeInTheDocument());
  expect(screen.getByText('Select a packet to view retained bytes.')).toBeInTheDocument();
});
