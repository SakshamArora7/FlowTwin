import React from 'react';
import { act, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import App from './App';
import { api } from './api';
vi.mock('./api', () => ({ api: vi.fn() }));
vi.mock('./live-monitoring', () => ({ MonitoringPage: () => <div>Monitoring recovered</div> }));
afterEach(() => { vi.useRealTimers(); location.hash = ''; });

it('automatically recovers the workspace after a temporary API outage', async () => {
  location.hash = '#/monitoring';
  api.mockRejectedValue(new Error('Service unavailable'));
  vi.useFakeTimers();
  await act(async () => { render(<App/>); });
  expect(screen.getByText('Backend connection unavailable')).toBeInTheDocument();
  api.mockImplementation(path => Promise.resolve(path === '/health' ? { status: 'ok' } : path === '/settings' ? { demo_mode: true, refresh_seconds: 30 } : { is_demo: true, alerts: [] }));
  await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
  expect(screen.queryByText('Backend connection unavailable')).not.toBeInTheDocument();
  expect(screen.getByText('API connected')).toBeInTheDocument();
  expect(screen.getByText('Monitoring recovered')).toBeInTheDocument();
});
