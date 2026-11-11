import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// BASE is the sub-path the built files are served from. The demo on the site
// lives under /demo/. BASE=./ makes a build that works wherever it sits
// (the real program embeds it that way).
const base = process.env.BASE ?? '/demo/';
// 'demo': an in-memory ConnectRPC transport answers from fixtures, nothing
// leaves the page. 'real': the page talks to the local ritueel process.
const mode = process.env.RITUEEL_MODE ?? 'demo';

export default defineConfig({
  base,
  plugins: [react(), tailwindcss()],
  define: {
    __RITUEEL_MODE__: JSON.stringify(mode),
    // Where "back to the site" goes. It is a link the visitor follows, never a fetch.
    __SITE_URL__: JSON.stringify(process.env.SITE_URL ?? 'https://ritueel.id/'),
  },
  build: {
    target: 'es2022',
    sourcemap: false,
    outDir: process.env.OUT_DIR ?? 'dist',
    emptyOutDir: true,
    // The minified code carries no licence notices, and MIT, BSD and Apache-2.0 ask for them to travel with it:
    // Vite writes every bundled package's licence into this file, next to index.html.
    license: { fileName: 'THIRD-PARTY-LICENSES.md' },
  },
  test: { environment: 'node', include: ['src/**/*.test.{ts,tsx}'] },
});
