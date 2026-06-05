import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Standalone web app (NO Tauri — banned). Builds to a static bundle in dist-app.
export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist-app', target: 'es2022' },
});
