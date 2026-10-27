import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, vi } from 'vitest';

afterEach(() => { cleanup(); vi.restoreAllMocks(); });
globalThis.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
window.matchMedia = () => ({ matches: true, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} });
