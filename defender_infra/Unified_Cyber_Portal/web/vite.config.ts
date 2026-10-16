import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Dev: React on :5173, API calls forwarded to the portal API on :8800.
// Production: `npm run build` → dist/, served by the portal API itself on :8800.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(__dirname, './src') } },
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: { '/api': 'http://127.0.0.1:8800' },
  },
  build: { chunkSizeWarningLimit: 1500 },
})
