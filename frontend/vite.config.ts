import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    nodePolyfills({
      // polyfill only what you need:
      include: ['buffer', 'crypto', 'stream'],
      globals: { Buffer: true, global: true, process: true },
      protocolImports: true, // enable `node:buffer` style imports
    }),
  ],
  resolve: {
    alias: {
      // ensure Node built-ins resolve to browser-friendly shims
      buffer: 'buffer/',
      crypto: 'crypto-browserify',
      stream: 'stream-browserify',
      process: 'process/browser',
    },
  },
  optimizeDeps: {
    include: ['buffer', 'crypto-browserify', 'stream-browserify', 'process'], // pre-bundle these to avoid externalization
  },
});
