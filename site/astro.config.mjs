import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import { docsLinksMdastPlugin } from './lib/docs-links.mjs';
import { partsMdastPlugin } from './lib/parts.mjs';

// A link from a published page to a page of docs/ that is not published becomes a link to that
// file on GitHub (site/lib/docs-links.mjs). Astro 7 renders Markdown with Satteri, so the rule is
// an mdast plugin of the Markdown processor. The integration is listed before starlight(), so
// that the rewrite is done before the link validator reads the links.
const docsLinks = {
  name: 'ritueel-docs-links',
  hooks: {
    'astro:config:setup': ({ config }) => {
      const processor = config.markdown?.processor;
      if (!processor || processor.name !== 'satteri' || !Array.isArray(processor.options?.mdastPlugins)) {
        throw new Error('ritueel-docs-links: the Markdown processor is not satteri; see site/lib/docs-links.mjs');
      }
      processor.options.mdastPlugins.push(({ fileURL }) => docsLinksMdastPlugin(fileURL));
    },
  },
};

// A page with `flow: rows` in its front matter gets its sections wrapped, for the rows of the wide
// layout (site/lib/parts.mjs). The same Satteri processor, the same place in the order.
const docsParts = {
  name: 'ritueel-docs-parts',
  hooks: {
    'astro:config:setup': ({ config }) => {
      const processor = config.markdown?.processor;
      if (!processor || processor.name !== 'satteri' || !Array.isArray(processor.options?.mdastPlugins)) {
        throw new Error('ritueel-docs-parts: the Markdown processor is not satteri; see site/lib/parts.mjs');
      }
      processor.options.mdastPlugins.push(() => partsMdastPlugin);
    },
  },
};

// The syntax colours of a code block (Starlight's default themes) have blues, purples and teal; the
// site has one green accent and neutral greys (src/styles/theme.css). A colour in the blue to purple
// range (hue 165 to 300 degrees, and not grey) becomes the accent green of the theme's own kind; the
// other colours of a token (greys, amber, red) are kept. Only the code blocks of the hand-off
// contract page are affected today. The green is the accent of theme.css (its night and its day
// value): the line below repeats them, because the highlighter works on values, not on variables.
const CODE_ACCENT = { dark: '#3dd68c', light: '#07603f' };
function codeSyntaxColours(theme) {
  for (const rule of theme.settings ?? []) {
    const fg = rule.settings?.foreground;
    const m = typeof fg === 'string' ? /^#([0-9a-f]{6})/i.exec(fg) : null;
    if (!m) continue;
    const [r, g, b] = [0, 2, 4].map((i) => parseInt(m[1].slice(i, i + 2), 16) / 255);
    const max = Math.max(r, g, b);
    const min = Math.min(r, g, b);
    const d = max - min;
    if (d === 0) continue;
    const l = (max + min) / 2;
    const sat = d / (1 - Math.abs(2 * l - 1));
    const hue = (max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4) * 60;
    const h = (hue + 360) % 360;
    if (sat > 0.15 && h >= 165 && h <= 300) rule.settings.foreground = rule.scope ? CODE_ACCENT[theme.type === 'light' ? 'light' : 'dark'] : theme.type === 'light' ? '#262626' : '#d4d4d4';
  }
  // The plain text of a block is neutral, not the slate of the default themes.
  if (theme.colors?.['editor.foreground']) theme.colors['editor.foreground'] = theme.type === 'light' ? '#262626' : '#d4d4d4';
  return theme;
}

// https://ritueel.id. The custom domain and its DNS are managed outside this repository; the
// site is static and is served from the root by a Cloudflare Worker with static assets
// (site/wrangler.jsonc).
export default defineConfig({
  site: 'https://ritueel.id',
  trailingSlash: 'always',
  prefetch: { prefetchAll: true, defaultStrategy: 'hover' },
  // Astro inlines a bundled script under 4 KB into the page, which would need its hash in the
  // Content-Security-Policy; the status page's live script (src/scripts/status-live.ts) must stay a
  // file of this site that `script-src 'self'` covers, so nothing is inlined.
  vite: { build: { assetsInlineLimit: 0 } },
  integrations: [
    docsLinks,
    docsParts,
    starlight({
      title: 'ritueel',
      description:
        'ritueel teaches how to keep the root of a PKI and the primary key of OpenPGP safe, and plans tools that simplify the ceremonies. Open source, taught in the open.',
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/truvity/ritueel' }],
      editLink: { baseUrl: 'https://github.com/truvity/ritueel/edit/main/' },
      lastUpdated: false,
      // Starlight's Markdown transforms (heading ids and anchor links, asides) run on files under
      // the symlinked content directory. An .mdx page reaches them by its real path under docs/, and
      // so do the decision records, so docs/ is named here; without it the link validator cannot see
      // the headings of those pages and calls every link to one of them broken.
      markdown: { processedDirs: ['../docs'] },
      // The 404 page is src/pages/404.astro.
      disable404Route: true,
      head: [
        { tag: 'meta', attrs: { property: 'og:site_name', content: 'ritueel' } },
        { tag: 'meta', attrs: { property: 'og:type', content: 'website' } },
      ],
      // The look is Starlight's own: its parts and templates, with the colours and the fonts set through
      // its variables (theme.css, fonts.css). site.css holds the few rules a page is broken without,
      // each with its reason. No component of Starlight is replaced.
      expressiveCode: { customizeTheme: codeSyntaxColours },
      customCss: ['./src/styles/theme.css', './src/styles/fonts.css', './src/styles/site.css'],
      routeMiddleware: './src/route-middleware.ts',
      // The menu is six entries: only the target (docs/contributing/pages.md, "What is published").
      // The pages are those of site/published.txt; a slug that is not on the list fails the build.
      // The hand-off contract is not in the menu; the design page links it.
      sidebar: [
        {
          label: 'Learn',
          items: [
            { slug: 'learn', label: 'Overview' },
            // Four groups, in the order of a reader: the basics, down one chain, where a key lives,
            // side by side. Only the basics start from zero; every other page says in its first
            // lines what it assumes. The goals are a table on the overview, not pages.
            {
              label: 'Basics',
              collapsed: false,
              items: [{ slug: 'learn/what-is-a-root', label: 'What is a root?' }],
            },
            {
              label: 'Down the chain',
              collapsed: false,
              items: [
                { slug: 'learn/custody-chain', label: 'The custody chain' },
                { slug: 'learn/chain-private-pki', label: 'Private PKI' },
                { slug: 'learn/chain-openpgp', label: 'OpenPGP' },
                { slug: 'learn/chain-ssh', label: 'SSH' },
              ],
            },
            {
              label: 'Where a key lives',
              collapsed: false,
              items: [
                // The passkey page belongs to the YubiKey page: a Starlight group is not a link, so
                // the pair is a group of its own.
                {
                  label: 'A key on a YubiKey',
                  collapsed: false,
                  items: [
                    { slug: 'learn/how-a-yubikey-holds-keys', label: 'How a YubiKey holds keys' },
                    { slug: 'learn/how-passkeys-work', label: 'How passkeys work' },
                  ],
                },
                { slug: 'learn/how-a-kms-key-works', label: 'How a KMS key works' },
                { slug: 'learn/a-key-in-a-file', label: 'A key in a file' },
                { slug: 'learn/choosing-where-a-root-lives', label: 'Choosing where a root lives' },
              ],
            },
            {
              label: 'Side by side',
              collapsed: false,
              items: [
                { slug: 'learn/two-roots', label: 'Several keys, one root' },
                { slug: 'learn/life-of-a-root', label: 'The life of a root' },
                { slug: 'learn/revoke', label: 'Revoke' },
              ],
            },
          ],
        },
        {
          label: 'How it works',
          collapsed: false,
          items: [
            { slug: 'how-it-works', label: 'Overview' },
            { slug: 'how-it-works/cards', label: 'The kinds of card' },
            { slug: 'how-it-works/bundle-and-stick', label: 'The bundle and the USB stick' },
          ],
        },
        // The demo of the local page is a build product (public/demo), not a page of the docs.
        { label: 'Demo', link: '/demo/' },
        { label: 'Glossary', slug: 'glossary' },
        {
          label: 'Where it stands',
          // The status page is built from the repository and the issues (src/pages/status.astro).
          items: [{ label: 'Status', link: '/status/' }, { slug: 'roadmap' }],
        },
        { label: 'The design', slug: 'design' },
      ],
      plugins: [
        // Fails the build on a broken internal link or anchor of a published page; a link to a page
        // that is not published is a link to its file on GitHub before the validator reads it
        // (docsLinks above). The decision records have no page, so a left-over link to one of their
        // addresses fails the build. The status page is generated in src/pages (a custom page the
        // validator cannot see); the demo of the local page (/demo/) is built by `just ui-demo` into
        // public/demo, so no page of the site is its source; site/scripts/check-built.sh checks that
        // the status page is built.
        starlightLinksValidator({
          errorOnRelativeLinks: false,
          exclude: ['/status/', '/demo/', '/demo/**'],
        }),
      ],
    }),
  ],
});
