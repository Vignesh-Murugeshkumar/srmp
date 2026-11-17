/// <reference types="vitest" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const BACKEND = process.env.TRACEVAULT_BACKEND ?? 'http://127.0.0.1:8000';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: BACKEND, changeOrigin: true },
      '/ws': { target: BACKEND.replace(/^http/, 'ws'), ws: true, changeOrigin: true },
    },
  },
  build: {
    chunkSizeWarningLimit: 1600,
    rollupOptions: {
      output: {
        manualChunks: {
          graph: ['cytoscape', 'cytoscape-fcose', 'cytoscape-dagre'],
          charts: ['d3', 'recharts'],
          vendor: ['react', 'react-dom', 'react-router-dom', '@tanstack/react-query', 'framer-motion'],
        },
      },
    },
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
