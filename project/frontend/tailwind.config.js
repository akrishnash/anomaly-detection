/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          black: "#030712",
          dark: "#0b0f19",
          card: "#111827",
          border: "#1f2937",
          cyan: "#06b6d4",
          green: "#10b981",
          red: "#ef4444",
          yellow: "#f59e0b",
          blue: "#3b82f6"
        },
        // "Obsidian Sentinel" design tokens (Google Stitch DESIGN.md)
        "surface": "#131313",
        "surface-dim": "#131313",
        "surface-bright": "#3a3939",
        "surface-container-lowest": "#0e0e0e",
        "surface-container-low": "#1c1b1b",
        "surface-container": "#201f1f",
        "surface-container-high": "#2a2a2a",
        "surface-container-highest": "#353534",
        "surface-variant": "#353534",
        "surface-tint": "#00dbe9",
        "on-surface": "#e5e2e1",
        "on-surface-variant": "#b9cacb",
        "outline": "#849495",
        "outline-variant": "#3b494b",
        "primary": "#dbfcff",
        "on-primary": "#00363a",
        "primary-container": "#00f0ff",
        "on-primary-container": "#006970",
        "primary-fixed": "#7df4ff",
        "primary-fixed-dim": "#00dbe9",
        "secondary": "#d1bcff",
        "on-secondary": "#3c0090",
        "secondary-container": "#7000ff",
        "on-secondary-container": "#ddcdff",
        "secondary-fixed-dim": "#d1bcff",
        "tertiary": "#f4f5ff",
        "error": "#ffb4ab",
        "on-error": "#690005",
        "error-container": "#93000a",
        "on-error-container": "#ffdad6",
        "background": "#131313",
        "on-background": "#e5e2e1"
      },
      boxShadow: {
        'glow-cyan': '0 0 15px rgba(6, 182, 212, 0.25)',
        'glow-green': '0 0 15px rgba(16, 185, 129, 0.25)',
        'glow-red': '0 0 15px rgba(239, 68, 68, 0.25)',
        'glow-yellow': '0 0 15px rgba(245, 158, 11, 0.25)',
        'neon-cyan': '0 0 15px rgba(0, 240, 255, 0.15)',
        'neon-cyan-strong': '0 0 15px rgba(0, 240, 255, 0.4)',
        'neon-error': '0 0 15px rgba(255, 180, 171, 0.2)',
      },
      spacing: {
        'panel-gap': '16px',
        'gutter': '24px',
        'margin-mobile': '16px',
        'margin-desktop': '48px',
      },
      borderRadius: {
        'card': '18px',
      },
      fontFamily: {
        'geist': ['Geist', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        'label-mono': ['"Space Mono"', 'ui-monospace', 'monospace'],
      },
      fontSize: {
        'display-lg': ['48px', { lineHeight: '56px', letterSpacing: '-0.02em', fontWeight: '700' }],
        'headline-lg': ['32px', { lineHeight: '40px', letterSpacing: '-0.01em', fontWeight: '600' }],
        'headline-md': ['24px', { lineHeight: '32px', fontWeight: '600' }],
        'body-lg': ['18px', { lineHeight: '28px', fontWeight: '400' }],
        'body-md': ['14px', { lineHeight: '22px', fontWeight: '400' }],
        'label-mono': ['12px', { lineHeight: '16px', letterSpacing: '0.05em', fontWeight: '500' }],
        'label-caps': ['11px', { lineHeight: '14px', letterSpacing: '0.1em', fontWeight: '700' }],
      }
    },
  },
  plugins: [],
}
