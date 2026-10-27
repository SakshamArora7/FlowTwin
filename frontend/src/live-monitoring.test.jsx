import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { MonitoringPage } from './live-monitoring';
import { api } from './api';

vi.mock('./api', () => ({ api: vi.fn() }));
let socket;
class Socket {
  constructor() { socket = this; queueMicrotask(() => this.onopen?.()); }
  close() {}
  message(data) { this.onmessage({ data: JSON.stringify(data) }); }
}
const stopped = { status: 'stopped', source: 'live', active_flows: 0, processed_packets: 0, protocols: [], recent_packets: [], recent_flows: [], alerts: [] };
beforeEach(() => {
  vi.stubGlobal('WebSocket', Socket);
  api.mockImplementation(path => Promise.resolve(path === '/live/interfaces'
    ? { available: true, interfaces: [{ id: 'wifi-id', name: 'Wi-Fi', addresses: ['192.168.1.2'] }], error: '' }
    : path === '/live/sessions' ? [] : path === '/live/start' ? { ...stopped, status: 'running', capture_id: 12 }
    : path === '/live/stop' ? { ...stopped, status: 'stopping' } : stopped));
});
afterEach(() => { vi.unstubAllGlobals(); vi.clearAllMocks(); });

it('requires explicit interface selection and supports start, streamed metrics and stop', async () => {
  render(<MonitoringPage demoMode={false} revision={0}/>);
  await screen.findByRole('option', { name: /Wi-Fi/ });
  expect(screen.getByRole('button', { name: 'Start monitoring' })).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Capture interface'), { target: { value: 'wifi-id' } });
  fireEvent.click(screen.getByRole('button', { name: 'Start monitoring' }));
  await waitFor(() => expect(api).toHaveBeenCalledWith('/live/start', { method: 'POST', body: JSON.stringify({ interface_id: 'wifi-id' }) }));
  await waitFor(() => expect(screen.getByLabelText('Capture interface')).toBeDisabled());
  const { act } = await import('@testing-library/react');
  act(() => socket.message({ type: 'live_snapshot', live: { ...stopped, status: 'running', processed_packets: 123, packets_per_second: 42, dropped_packets: 7, active_flows: 3, bits_per_second: 8000 } }));
  expect(screen.getByText('42 pkt/s')).toBeInTheDocument();
  expect(screen.getByText('7 packets dropped')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Stop monitoring' }));
  await waitFor(() => expect(api).toHaveBeenCalledWith('/live/stop', { method: 'POST' }));
  expect(await screen.findByText(/Draining queued packets/)).toBeInTheDocument();
});

it('shows Npcap failures and never presents replay as live capture', async () => {
  api.mockImplementation(path => Promise.resolve(path === '/live/interfaces' ? { available: false, interfaces: [], error: 'Install Npcap and restart the backend.' } : path === '/live/sessions' ? [] : stopped));
  render(<MonitoringPage demoMode={false} revision={0}/>);
  expect(await screen.findByText('Install Npcap and restart the backend.')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Start monitoring' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Saved-PCAP replay' })).toBeInTheDocument();
});

it('does not start capture or load real packet data in sample mode', () => {
  render(<MonitoringPage demoMode={true} revision={0}/>);
  expect(screen.getByText('Live capture requires real data mode')).toBeInTheDocument();
  expect(api).not.toHaveBeenCalled();
});

it('does not overwrite a newer stopped snapshot with a delayed stop response', async () => {
  let finishStop;
  const previous = api.getMockImplementation();
  api.mockImplementation((path, options) => path === '/live/stop' ? new Promise(resolve => { finishStop = resolve; }) : previous(path, options));
  render(<MonitoringPage demoMode={false} revision={0}/>);
  await screen.findByRole('option', { name: /Wi-Fi/ });
  fireEvent.change(screen.getByLabelText('Capture interface'), { target: { value: 'wifi-id' } });
  fireEvent.click(screen.getByRole('button', { name: 'Start monitoring' }));
  await waitFor(() => expect(screen.getByRole('button', { name: 'Stop monitoring' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Stop monitoring' }));
  await act(async () => {
    socket.message({ type: 'live_snapshot', live: { ...stopped, capture_id: 12 } });
    finishStop({ ...stopped, status: 'stopping', capture_id: 12 });
  });
  await waitFor(() => expect(screen.getByRole('button', { name: 'Start monitoring' })).toBeEnabled());
  expect(screen.queryByText(/Draining queued packets/)).not.toBeInTheDocument();
});
