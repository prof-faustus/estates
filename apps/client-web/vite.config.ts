import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Tauri drives this dev server. Keep vite's HMR file-watcher OUT of the Rust
  // build tree: cargo rewrites src-tauri/target/**/*.dll while it compiles, and
  // watching those locked files throws `EBUSY` and kills the dev server (which
  // takes the whole `tauri dev` down with it). Ignore the Rust side entirely.
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    watch: { ignored: ['**/src-tauri/**'] },
  },
  build: { outDir: 'dist-app', target: 'es2022' },
});
