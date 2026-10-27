import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { SettingsPage, TrafficPage } from './pages';
import { api } from './api';

vi.mock('./api', () => ({ api: vi.fn() }));
const health = { status: 'ok', database: 'connected' };

describe('Workspace preferences', () => {
  it('only persists mode changes on save and waits for the server before refreshing', async () => {
    api.mockResolvedValue({ demo_mode: false, refresh_seconds: 60 });
    const onSaved = vi.fn();
    render(<SettingsPage settings={{ demo_mode: true, refresh_seconds: 30 }} health={health} onSaved={onSaved}/>);
    fireEvent.click(screen.getByRole('switch'));
    expect(screen.getByRole('switch')).toHaveAttribute('aria-checked', 'false');
    expect(onSaved).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('Refresh interval'), { target: { value: '60' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save preferences' }));
    await waitFor(() => expect(onSaved).toHaveBeenCalledOnce());
    expect(api).toHaveBeenCalledWith('/settings', { method: 'PUT', body: JSON.stringify({ demo_mode: false, refresh_seconds: 60 }) });
  });
  it('keeps failed settings visible with an error instead of claiming success', async () => {
    api.mockRejectedValue(new Error('Network unavailable'));
    const onSaved = vi.fn();
    render(<SettingsPage settings={{ demo_mode: true, refresh_seconds: 30 }} health={health} onSaved={onSaved}/>);
    fireEvent.click(screen.getByRole('button', { name: 'Save preferences' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Network unavailable');
    expect(onSaved).not.toHaveBeenCalled();
  });
});

describe('Flow browsing', () => {
  it('sends filters to the API and handles an empty search', async () => {
    api.mockResolvedValue({ total: 0, items: [], is_demo: true });
    render(<TrafficPage revision={0} demoMode={true} inspect={vi.fn()}/>);
    await screen.findByText('No matching flows');
    fireEvent.change(screen.getByLabelText('Search flows'), { target: { value: '192.168.1.10' } });
    fireEvent.change(screen.getByLabelText('Protocol filter'), { target: { value: 'TCP' } });
    fireEvent.change(screen.getByLabelText('Classification filter'), { target: { value: 'malicious' } });
    await waitFor(() => expect(api).toHaveBeenLastCalledWith('/flows?q=192.168.1.10&protocol=TCP&classification=malicious&page=1'));
    expect(await screen.findByText('No matching flows')).toBeInTheDocument();
  });
  it('shows the actual server error without substituting sample data', async () => {
    api.mockRejectedValue(new Error('Service unavailable'));
    render(<TrafficPage revision={0} demoMode={true} inspect={vi.fn()}/>);
    expect(await screen.findByRole('alert')).toHaveTextContent('Service unavailable');
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });
});
