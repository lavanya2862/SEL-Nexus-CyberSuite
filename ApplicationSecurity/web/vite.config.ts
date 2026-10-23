import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Dev: React on :5174, API calls forwarded to the Application Security API on :8500.
// Production: `npm run build` → dist/, served by the API itself on :8500.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(__dirname, './src') } },
  server: {
    host: '127.0.0.1',
    port: 5174,
    proxy: { '/api': 'http://127.0.0.1:8500' },
  },
  build: { chunkSizeWarningLimit: 1500 },
})
