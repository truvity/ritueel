import { fileURLToPath } from 'node:url';
import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsSchema, i18nSchema } from '@astrojs/starlight/schema';
import { i18nLoader } from '@astrojs/starlight/loaders';
import { z } from 'astro/zod';

// The documentation lives in ../docs (the repository's docs/ directory, linked at
// src/content/docs), so it reads the same on GitHub as on ritueel.id. The ADRs in
// docs/decisions are their own collection: their front matter is not the site's, and
// the site indexes them instead of treating them as ordinary pages.
const docsRoot = fileURLToPath(new URL('../../docs', import.meta.url));

export const collections = {
  docs: defineCollection({
    loader: glob({ base: 'src/content/docs', pattern: ['**/[^_]*.{md,mdx}', '!decisions/**'] }),
    schema: docsSchema(),
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
