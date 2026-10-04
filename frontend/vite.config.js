import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// `npm run dev`   -> dashboard at http://localhost:5173/ (talks to the backend on :8000)
// `npm run build` -> files in dist/, which the backend serves at http://localhost:8000/
export default defineConfig({
  plugins: [react(), tailwindcss()],
})
