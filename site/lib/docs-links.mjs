// The link rule of the site: a link from a published page to a page of docs/ that is not
// published becomes a link to that file on GitHub, with its #anchor kept. The Markdown sources
// keep their links as they are (they read the same on GitHub); the rewrite happens while the
// site is built, so a page that is published again gets its own links back by itself.
//
// Astro 7 renders Markdown with Satteri, not remark: the plugin below is a Satteri mdast plugin,
// added to the processor by an integration in astro.config.mjs (it must come before starlight(),
// so that the link validator sees the links after the rewrite).
import { realpathSync } from 'node:fs';
import { join, posix, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fileOfPath, githubUrl, isPublished, repoRoot } from './published.mjs';

const defaults = () => ({ docsRoot: join(repoRoot(), 'docs'), isPublished: (file) => isPublished(file) });

/**
 * The href to write for `href`, found in the docs file `sourceFile` (a path relative to docs/).
 * Unchanged unless it leads to a docs file that is not published. `ctx` is for tests:
 * { docsRoot, isPublished(file) }.
 */
export function rewriteHref(href, sourceFile, ctx = defaults()) {
  // 1. Not a path of this site: empty, a fragment, another host, any scheme, a query.
  if (!href || href.startsWith('#') || href.startsWith('//') || /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(href) || href.includes('?')) return href;
  // 2. Keep the fragment as written: GitHub gives a heading the same id Starlight does.
  const hash = href.indexOf('#');
  const path = hash === -1 ? href : href.slice(0, hash);
  const fragment = hash === -1 ? '' : href.slice(hash);
  // 3. A site path, or a relative path to a Markdown file; any other relative path is not ours.
  let sitePath;
  if (path.startsWith('/')) sitePath = path;
  else if (/\.mdx?$/.test(path)) {
    // Without clamping at the root: a link that climbs out of docs/ is not a link to a docs file.
    const joined = posix.normalize(`${posix.dirname(sourceFile)}/${path}`);
    if (joined === '..' || joined.startsWith('../')) return href;
    sitePath = `/${joined}`;
  } else return href;
  // 4. The docs file behind it. 5. None: a page made by src/pages, an asset, a stale address.
  const file = fileOfPath(sitePath, ctx.docsRoot);
  if (!file) return href;
  // 6. Published: the site has the page. 7. Otherwise the file on GitHub.
  return ctx.isPublished(file) ? href : githubUrl(file) + fragment;
}

/** The same rule for a hand-written page (src/pages/*.astro) that links a site path. */
export function docsHref(href) {
  return rewriteHref(href, 'index.mdx');
}

/**
 * The Satteri mdast plugin for one document: undefined for a file outside docs/, else a plugin
 * that rewrites the url of every link and every link definition. Written as a factory of
 * `{ fileURL }`, the form Starlight's own plugins use.
 */
export function docsLinksMdastPlugin(fileURL, ctx = defaults()) {
  if (!fileURL) return undefined;
  let file;
  try {
    // The docs collection is read through the link site/src/content/docs; the decisions
    // collection through docs/decisions itself. Both resolve to the real folder.
    const rel = relative(realpathSync(ctx.docsRoot), realpathSync(fileURLToPath(fileURL)));
    if (rel === '' || rel.startsWith('..') || rel.split(sep).includes('..')) return undefined;
    file = rel.split(sep).join('/');
  } catch {
    return undefined;
  }
  const fix = (node, context) => {
    const to = rewriteHref(node.url, file, ctx);
    if (to !== node.url) context.setProperty(node, 'url', to);
  };
  return { name: 'ritueel-docs-links', link: fix, definition: fix };
}
