import { fileURLToPath } from 'node:url';
import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsSchema, i18nSchema } from '@astrojs/starlight/schema';
import { i18nLoader } from '@astrojs/starlight/loaders';
import { z } from 'astro/zod';
import { publishedDocs } from '../lib/published.mjs';

// The documentation lives in ../docs (the repository's docs/ directory, linked at
// src/content/docs), so it reads the same on GitHub as on ritueel.id. The ADRs in
// docs/decisions are their own collection: their front matter is not the site's, and they are
// indexed for counting (the status page), not rendered: they have no page. The docs collection holds
// only the pages of site/published.txt: a file of docs/ that is not listed has no page (it stays
// in the repository, and its old address redirects to it on GitHub).
const docsRoot = fileURLToPath(new URL('../../docs', import.meta.url));

export const collections = {
  docs: defineCollection({
    loader: glob({ base: 'src/content/docs', pattern: publishedDocs() }),
    // `flow: rows` shows the sections of a page in rows of two on a wide screen (lib/parts.mjs wraps
    // them, src/styles/layout.css lays them out). It is for a page of short parts.
    schema: docsSchema({ extend: z.object({ flow: z.enum(['rows']).optional() }) }),
  }),
  i18n: defineCollection({ loader: i18nLoader(), schema: i18nSchema() }),
  decisions: defineCollection({
    loader: glob({ base: `${docsRoot}/decisions`, pattern: ['*.md', '!README.md', '!_*'] }),
    schema: z.object({
      title: z.string().optional(),
      description: z.string().optional(),
    }).passthrough(),
  }),
};
