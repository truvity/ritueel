import { fileURLToPath } from 'node:url';
import { defineCollection } from 'astro:content';
import { file, glob } from 'astro/loaders';
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
    // `flow: rows` shows the sections of a page in rows of two on a wide screen. `flow: landing` is
    // the layout of a case page, a page that stands alone: no side menu, the parts in two or three
    // columns, one screen. lib/parts.mjs wraps the parts of both.
    schema: docsSchema({ extend: z.object({ flow: z.enum(['rows', 'landing']).optional() }) }),
  }),
  i18n: defineCollection({ loader: i18nLoader(), schema: i18nSchema() }),
  // docs/coverage.yaml: the legend and the tables of the status page. lib/coverage.mjs checks what
  // the whole file must satisfy; a wrong shape or an unknown field fails here.
  coverage: defineCollection({
    loader: file(`${docsRoot}/coverage.yaml`),
    schema: z.discriminatedUnion('kind', [
      z.strictObject({
        id: z.string(),
        kind: z.literal('legend'),
        advice: z.array(z.strictObject({ id: z.string(), label: z.string() })).min(1),
        states: z.array(z.strictObject({ id: z.string(), label: z.string(), meaning: z.string() })).min(1),
      }),
      z.strictObject({
        id: z.string(),
        kind: z.literal('case'),
        number: z.number().int().positive(),
        title: z.string(),
        // The address of the case page: one path part, and a line of site/published.txt (lib/coverage.mjs).
        page: z.string().regex(/^\/[a-z-]+\/$/),
        rows: z.array(
          z.strictObject({
            way: z.string(),
            // One state of the legend, except a way that is not recommended: it shows advice only.
            state: z.string().optional(),
            advice: z.string().optional(),
            why: z.string().min(1),
            // The milestone of a way that is planned, or explained with a tool planned.
            milestone: z.string().optional(),
          }),
        ),
      }),
    ]),
  }),
  decisions: defineCollection({
    loader: glob({ base: `${docsRoot}/decisions`, pattern: ['*.md', '!README.md', '!_*'] }),
    schema: z.object({
      title: z.string().optional(),
      description: z.string().optional(),
    }).passthrough(),
  }),
};
