import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { port: 5174, strictPort: true, proxy: { '/api': { target: 'http://127.0.0.1:8765', ws: true } } },
  preview: { proxy: { '/api': 'http://127.0.0.1:8765' } },
  test: { environment: 'jsdom', setupFiles: './src/test-setup.js', pool: 'threads', maxWorkers: 1 },
});
