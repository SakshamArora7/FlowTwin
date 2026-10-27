import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { DetectionPage, ReplayPage } from './advanced-pages';
import { api } from './api';
vi.mock('./api', () => ({ api: vi.fn() }));
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

it('analyzes a saved capture from the detection page and refreshes findings', async () => {
  api.mockImplementation(path => Promise.resolve(path === '/model' ? { status: 'trained', metrics: null } : path === '/captures' ? [{ id: 7, filename: 'Wi-Fi', source: 'live', flow_count: 3 }] : path.endsWith('/analyze') ? { classified_flow_count: 3 } : []));
  render(<DetectionPage demoMode={false} revision={0} inspect={vi.fn()}/>);
  await screen.findByRole('option', { name: /Wi-Fi/ });
  fireEvent.click(screen.getByRole('button', { name: 'Analyze capture' }));
  await screen.findByText('Analyzed 3 flows.');
  expect(api).toHaveBeenCalledWith('/captures/7/analyze', expect.objectContaining({ method: 'POST' }));
  expect(api.mock.calls.filter(([path]) => path === '/detections').length).toBeGreaterThan(1);
});

it('reconnects replay and clears the disconnection warning after recovery', async () => {
  const sockets = [];
  class Socket { constructor() { sockets.push(this); } close() {} }
  vi.stubGlobal('WebSocket', Socket);
  api.mockResolvedValue([]);
  const view = render(<ReplayPage demoMode={false} revision={0}/>);
  await waitFor(() => expect(sockets).toHaveLength(1));
  vi.useFakeTimers();
  act(() => { sockets[0].onerror(); sockets[0].onclose(); });
  expect(screen.getByRole('alert')).toHaveTextContent(/reconnecting/i);
  act(() => vi.advanceTimersByTime(1000));
  expect(sockets).toHaveLength(2);
  act(() => sockets[1].onopen());
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.getByText('WebSocket connected')).toBeInTheDocument();
  act(() => sockets[1].onmessage({ data: JSON.stringify({ type: 'connected', replay: { active: false, processed: 2, total: 2 } }) }));
  expect(screen.getByText('2 / 2 flows')).toBeInTheDocument();
  view.unmount();
  act(() => vi.advanceTimersByTime(30000));
  expect(sockets).toHaveLength(2);
});

it('displays saved-capture analysis errors', async () => {
  api.mockImplementation(path => path.endsWith('/analyze') ? Promise.reject(new Error('Stop the live session before reanalyzing its flows')) : Promise.resolve(path === '/model' ? { status: 'trained', metrics: null } : path === '/captures' ? [{ id: 7, filename: 'Wi-Fi', source: 'live', flow_count: 3 }] : []));
  render(<DetectionPage demoMode={false} revision={0} inspect={vi.fn()}/>);
  await screen.findByRole('option', { name: /Wi-Fi/ });
  fireEvent.click(screen.getByRole('button', { name: 'Analyze capture' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Stop the live session');

});

it('keeps sample mode separate from real detections and capture analysis', async () => {
  api.mockResolvedValue({ status: 'unavailable' });
  api.mockClear();
  render(<DetectionPage demoMode={true} revision={0} inspect={vi.fn()}/>);
  await screen.findByText('No trained model is installed');
  expect(api).toHaveBeenCalledTimes(1);
  expect(api).toHaveBeenCalledWith('/model');
  expect(screen.queryByRole('button', { name: 'Analyze capture' })).not.toBeInTheDocument();
});


it('disables analysis when a model artifact is unavailable', async () => {
  api.mockImplementation(path => Promise.resolve(path === '/model' ? { status: 'unavailable' } : path === '/captures' ? [{ id: 7, filename: 'Wi-Fi', flow_count: 3 }] : []));
  render(<DetectionPage demoMode={false} revision={0} inspect={vi.fn()}/>);
  await screen.findByRole('option', { name: /Wi-Fi/ });
  expect(screen.getByRole('button', { name: 'Analyze capture' })).toBeDisabled();
});
