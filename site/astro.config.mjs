import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import { docsLinksMdastPlugin } from './lib/docs-links.mjs';

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
    starlight({
      title: 'ritueel',
      description:
        'ritueel teaches how to keep the root of a PKI and the primary key of OpenPGP safe, and gives tools that simplify the ceremonies. Open source, taught in the open.',
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
      // PageSidebar draws "On this page" as the dropdown at the top of the content below 100rem and
      // as a column at the right from 100rem; TwoColumnContent leaves the column to it;
      // src/styles/layout.css sets the wide column and the breakpoint; the route middleware drops
      // the list from pages with fewer than two headings.
      components: {
        TwoColumnContent: './src/components/TwoColumnContent.astro',
        PageSidebar: './src/components/PageSidebar.astro',
        // The home page's headline and links (the only page with `hero:` front matter).
        Hero: './src/components/Hero.astro',
      },
      customCss: ['./src/styles/layout.css', './src/styles/home.css'],
      routeMiddleware: './src/route-middleware.ts',
      // The menu is six entries: only the target (docs/contributing/pages.md, "What is published").
      // The pages are those of site/published.txt; a slug that is not on the list fails the build.
      // The hand-off contract is not in the menu; the design page links it.
      sidebar: [
        {
          label: 'Learn',
          items: [
            { slug: 'learn', label: 'Overview' },
            { slug: 'learn/what-is-a-root', label: '1. What is a root?' },
            { slug: 'learn/where-a-root-is-used', label: '2. Where a root is used' },
            { slug: 'learn/how-a-yubikey-holds-keys', label: '3. How a YubiKey holds keys' },
            { slug: 'learn/how-passkeys-work', label: '4. How passkeys work' },
            { slug: 'learn/how-a-kms-key-works', label: '5. How a KMS key works' },
            { slug: 'learn/choosing-where-a-root-lives', label: '6. Choosing where a root lives' },
            {
              label: 'Going further',
              collapsed: false,
              items: [
                { slug: 'learn/life-of-a-root' },
                { slug: 'learn/revoke' },
                { slug: 'learn/custody-chain' },
                { slug: 'learn/chain-openpgp', label: 'OpenPGP: one identity, many keys' },
              ],
            },
          ],
        },
        {
          label: 'How it works',
          collapsed: false,
          items: [
            { slug: 'how-it-works', label: 'Overview' },
            { slug: 'how-it-works/cards', label: 'The three cards' },
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
