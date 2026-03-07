import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  server: {
    host: '0.0.0.0',
    port: 3000,
    strictPort: true,
    // CRITICAL: Allow the AURA public URL to prevent errors
    allowedHosts: [
      'localhost',
      '.secai.chat', // Allows all *.secai.chat subdomains
    ],
  },
  // Make AURA environment variables available
  define: {
    'import.meta.env.VITE_UI_URL': JSON.stringify(process.env.UI_URL || 'http://localhost:3000'),
    'import.meta.env.VITE_API_URL': JSON.stringify(process.env.API_URL || 'http://localhost:8000'),
    'import.meta.env.VITE_AUX_URL': JSON.stringify(process.env.AUX_URL || 'http://localhost:9000'),
  },
})
