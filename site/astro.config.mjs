import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';

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
    starlight({
      title: 'ritueel',
      description:
        'ritueel teaches how to keep the root of a PKI and the master key of OpenPGP safe, and gives tools that simplify the ceremonies. Open source, taught in the open.',
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/truvity/ritueel' }],
      editLink: { baseUrl: 'https://github.com/truvity/ritueel/edit/main/' },
      lastUpdated: false,
      // The 404 page is src/pages/404.astro.
      disable404Route: true,
      head: [
        { tag: 'meta', attrs: { property: 'og:site_name', content: 'ritueel' } },
        { tag: 'meta', attrs: { property: 'og:type', content: 'website' } },
      ],
      // TwoColumnContent and PageSidebar drop the right-hand "On this page" column
      // for the dropdown at the top of the content; src/styles/layout.css sets the
      // wide column; the route middleware drops the bar from pages with fewer than
      // two headings.
      components: {
        TwoColumnContent: './src/components/TwoColumnContent.astro',
        PageSidebar: './src/components/PageSidebar.astro',
        // The home page's headline and links (the only page with `hero:` front matter).
        Hero: './src/components/Hero.astro',
      },
      customCss: ['./src/styles/layout.css', './src/styles/home.css'],
      routeMiddleware: './src/route-middleware.ts',
      sidebar: [
        // Learn comes first: the site teaches, and the tools simplify the rituals.
        { label: 'Learn', items: [{ autogenerate: { directory: 'learn' } }] },
        { label: 'Guides', items: [{ autogenerate: { directory: 'guides' } }] },
        { label: 'Tools', items: [{ autogenerate: { directory: 'tools' } }] },
        { label: 'Reference', items: [{ autogenerate: { directory: 'reference' } }] },
        { label: 'Decisions', link: '/decisions/' },
        { label: 'Principles', slug: 'principles' },
        { label: 'Research', items: [{ autogenerate: { directory: 'research' } }] },
        { label: 'Roadmap', slug: 'roadmap' },
        // Built from the repository and the issues (src/pages/status.astro).
        { label: 'Project status', link: '/status/' },
        {
          label: 'Contributing',
          items: [{ label: 'Overview', slug: 'contributing' }, { autogenerate: { directory: 'contributing' } }],
        },
      ],
      plugins: [
        // Fails the build on a broken internal link or anchor. The decision pages and the status
        // page are generated in src/pages (custom pages the validator cannot see);
        // site/scripts/check-anchors.mjs checks the links of the decision pages in the built site
        // instead, and site/scripts/check-built.sh checks that the status page is built.
        starlightLinksValidator({
          errorOnRelativeLinks: false,
          exclude: ['/decisions/', '/decisions/**', '/status/'],
        }),
      ],
    }),
  ],
});
