import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Backend port is negotiated by run_all.py (falls forward from 8000 when the
// default port is held by another app) and shared via AEGIS_BACKEND_PORT.
const backendPort = process.env.AEGIS_BACKEND_PORT || 8000

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Listen on all interfaces so the UI is reachable via the LAN IP
    // (e.g. http://192.168.1.123:<port>) as well as 127.0.0.1/localhost.
    // NOTE: this exposes the dashboard to the local network with no auth.
    host: true,
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
