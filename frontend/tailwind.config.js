/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        lab: {
          bg: '#060a12',
          panel: '#0d1422',
          card: '#111a2e',
          border: '#1e2c48',
          neon: '#00f5a0',
          cyan: '#00d9f5',
          amber: '#f59e0b',
          crimson: '#ef4444',
          indigo: '#6366f1',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
