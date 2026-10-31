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
  integrations: [
    starlight({
      title: 'ritueel',
      description:
        'ritueel keeps the roots of trust: it creates, vouches for, overlaps, supersedes and revokes X.509 and OpenPGP roots. Open source, taught in the open.',
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/truvity/ritueel' }],
      editLink: { baseUrl: 'https://github.com/truvity/ritueel/edit/main/docs/' },
      lastUpdated: false,
      // The 404 page is src/pages/404.astro.
      disable404Route: true,
      head: [
        { tag: 'meta', attrs: { property: 'og:site_name', content: 'ritueel' } },
        { tag: 'meta', attrs: { property: 'og:type', content: 'website' } },
      ],
      sidebar: [
        { label: 'Concepts', items: [{ autogenerate: { directory: 'concepts' } }] },
        { label: 'Roadmap', slug: 'roadmap' },
        { label: 'Decisions', link: '/decisions/' },
        {
          label: 'Contributing',
          items: [{ label: 'Overview', slug: 'contributing' }, { autogenerate: { directory: 'contributing' } }],
        },
      ],
      plugins: [
        // Fails the build on a broken internal link or anchor. The decision pages are
        // generated in src/pages from docs/decisions (custom pages the validator cannot see).
        starlightLinksValidator({
          errorOnRelativeLinks: false,
          exclude: ['/decisions/', '/decisions/**'],
        }),
      ],
    }),
  ],
});
