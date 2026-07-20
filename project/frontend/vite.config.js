import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Backend port is negotiated by run_all.py (falls forward from 8000 when the
// default port is held by another app) and shared via AEGIS_BACKEND_PORT.
const backendPort = process.env.AEGIS_BACKEND_PORT || 8000

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Bind to the IPv4 loopback only: localhost-only (not exposed on the LAN)
    // and matches the backend, which also binds 127.0.0.1. Avoids the
    // localhost -> IPv6 (::1) resolution that can mismatch the IPv4 backend.
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${backendPort}`,
        changeOrigin: true,
        secure: false,
      }
    }
  }
})
