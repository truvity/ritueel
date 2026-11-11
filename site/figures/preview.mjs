#!/usr/bin/env node
// Writes one standalone HTML file per figure and theme, to look at a drawing (in headless Chrome, or
// a browser) without building the site: `node site/figures/preview.mjs <out-dir> [starlight-style-dir]`.
// The page is the figure as Figure.astro would place it, in a column like the site's (sidebar from
// 50em, content at most 72rem, 16px gutter on a phone), with site/src/styles/figures.css.
// With the second argument, Starlight's own CSS is used (props.css, layers.css, reset.css, markdown.css
// from `npm pack @astrojs/starlight@0.42.10`, folder package/dist/style), so list numbers, paragraph
// spacing and the layers are the real ones; without it, a few stand-in tokens of the same values.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { figures } from './index.mjs';
import { renderFigure } from './markup.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const [out, styleDir] = process.argv.slice(2);
if (!out) {
  console.error('usage: preview.mjs <out-dir> [starlight-style-dir]');
  process.exit(2);
}
mkdirSync(out, { recursive: true });
const css = readFileSync(join(here, '..', 'src', 'styles', 'figures.css'), 'utf8');
const layout = readFileSync(join(here, '..', 'src', 'styles', 'layout.css'), 'utf8').match(/--ritueel-prose-width:[^;]*;/)[0];

const stand = `
:root { --sl-color-white: hsl(0,0%,100%); --sl-color-gray-1: hsl(224,20%,94%); --sl-color-gray-2: hsl(224,6%,77%); --sl-color-gray-3: hsl(224,6%,56%); --sl-color-gray-5: hsl(224,10%,23%); --sl-color-gray-6: hsl(224,14%,16%); --sl-color-black: hsl(224,10%,10%);
  --sl-color-accent-low: hsl(224,54%,20%); --sl-color-accent: hsl(224,100%,60%); --sl-color-accent-high: hsl(224,100%,85%);
  --sl-color-text: var(--sl-color-gray-2); --sl-color-bg: var(--sl-color-black); --sl-color-bg-nav: var(--sl-color-gray-6); --sl-color-bg-sidebar: var(--sl-color-gray-6);
  --sl-text-sm: 0.875rem; --sl-text-base: 1rem; --sl-sidebar-width: 18.75rem; --sl-content-gap-y: 1rem; --sl-font-system: system-ui, sans-serif; --sl-font-system-mono: ui-monospace, monospace; }
:root[data-theme='light'] { --sl-color-white: hsl(224,10%,10%); --sl-color-gray-1: hsl(224,14%,16%); --sl-color-gray-2: hsl(224,10%,23%); --sl-color-gray-3: hsl(224,7%,36%); --sl-color-gray-5: hsl(224,6%,77%); --sl-color-gray-6: hsl(224,20%,94%);
  --sl-color-black: hsl(0,0%,100%); --sl-color-accent-high: hsl(234,80%,30%); --sl-color-accent: hsl(234,90%,60%); --sl-color-accent-low: hsl(234,88%,90%); --sl-color-bg-nav: hsl(224,19%,97%); --sl-color-bg-sidebar: var(--sl-color-bg); }
`;

function slStyles() {
  if (!styleDir) return stand;
  const rd = (n) => readFileSync(join(styleDir, n), 'utf8');
  return [rd('layers.css'), rd('props.css'), rd('reset.css'), rd('util.css'), rd('markdown.css')].join('\n');
}

const page = (name, theme, fragment) => `<!doctype html>
<html lang="en" data-theme="${theme}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${name} (${theme})</title>
<style>
${slStyles()}
:root { ${layout} }
html { color-scheme: ${theme}; }
body { margin: 0; background: var(--sl-color-bg); color: var(--sl-color-text); font-family: var(--__sl-font, var(--sl-font-system)); font-size: var(--sl-text-base); line-height: var(--sl-line-height, 1.6); }
main { padding: 1.5rem 1rem; }
@media (min-width: 50em) { main { margin-left: var(--sl-sidebar-width); padding: 2rem 1.5rem; } body::before { content: ''; position: fixed; inset: 0 auto 0 0; width: var(--sl-sidebar-width); background: var(--sl-color-bg-sidebar); border-right: 1px solid var(--sl-color-hairline-light, var(--sl-color-gray-5)); } }
.sl-markdown-content { max-width: 72rem; }
.sl-markdown-content h2 { font-size: var(--sl-text-h2, 1.5rem); color: var(--sl-color-white); }
.sl-markdown-content > p { max-width: var(--ritueel-prose-width, 75ch); }
</style>
<style>${css}</style></head>
<body><main><div class="sl-markdown-content">
<p>A paragraph before the figure, as on a page of the site.</p>
${fragment}
<p>A paragraph after the figure. Preview of ${name}, ${theme} theme.</p>
</div></main></body></html>
`;

for (const fig of Object.values(figures)) {
  for (const theme of ['light', 'dark']) {
    const file = join(out, `${fig.id}-${theme}.html`);
    writeFileSync(file, page(fig.id, theme, renderFigure(fig)));
    console.log(file);
  }
}
