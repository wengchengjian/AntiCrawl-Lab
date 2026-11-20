import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'node:path'

const backendTarget = process.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000'
const frontendPort = Number(process.env.FRONTEND_PORT || 5173)

export default defineConfig({
  plugins: [
    vue({
      template: {
        compilerOptions: {
          isCustomElement: (tag) => tag === 'price-tag',
        },
      },
    }),
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    host: '127.0.0.1',
    port: frontendPort,
    proxy: {
      '/api': {
        target: backendTarget,
        changeOrigin: true,
      },
      '/ssr': {
        target: backendTarget,
        changeOrigin: true,
      },
    },
  },
})
