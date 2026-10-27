import { afterEach, expect, it, vi } from 'vitest';
import { api } from './api';

afterEach(() => vi.unstubAllGlobals());
it('surfaces failed HTTP responses', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 503 }));
  await expect(api('/health')).rejects.toThrow('Request failed (503)');
});
it('preserves JSON settings writes and returns server data', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ demo_mode: false }) }));
  const body = JSON.stringify({ demo_mode: false, refresh_seconds: 30 });
  expect(await api('/settings', { method: 'PUT', body })).toEqual({ demo_mode: false });
  expect(fetch).toHaveBeenCalledWith('/api/settings', expect.objectContaining({ method: 'PUT', body, headers: { 'Content-Type': 'application/json' } }));
});
