import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    tsconfigPaths: true,
  },
  build: {
    rolldownOptions: {
      output: {
        advancedChunks: {
          groups: [
            {
              name: 'vendor-react-dom',
              test: /[\\/]node_modules[\\/]react-dom[\\/]/,
            },
            {
              name: 'vendor-react',
              test: /[\\/]node_modules[\\/](react|scheduler)[\\/]/,
            },
            {
              name: 'vendor-ui',
              test: /[\\/]node_modules[\\/](@base-ui[\\/]|lucide-react[\\/])/,
            },
            {
              name: 'vendor-style',
              test: /[\\/]node_modules[\\/](tailwind-merge|clsx|class-variance-authority)[\\/]/,
            },
            {
              name: 'vendor-state',
              test: /[\\/]node_modules[\\/]zustand[\\/]/,
            },
          ],
        },
      },
    },
  },
  server: {
    host: '0.0.0.0',
    // Dev only: allow all hosts (nsl proxy fronts the dev server)
    allowedHosts: true,
  },
})
