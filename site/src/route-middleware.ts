// Drops the table of contents from a page with fewer than two headings: the
// "On this page" bar (src/components/PageSidebar.astro) would only list the page
// title. A page with `tableOfContents: false` has no table of contents to begin
// with.
//
// And it points each page's "Edit page" link at the file in the repository. Starlight builds
// the link from `editLink.baseUrl` plus the entry's path from the site directory,
// `src/content/docs/<id>.md`; that directory is a symlink to the repository's docs/, so the
// file on GitHub is `docs/<id>.md` (or .mdx). No baseUrl can drop the middle of that path. A
// link set in a page's own `editUrl` (the generated decision pages) is left alone; the
// other generated pages have none. site/scripts/check-edit-links.mjs checks the result in
// the built site.
//
// And it marks the "Decisions" menu entry as the current one on a decision record page
// (/decisions/<id>/), which is not the entry's own address.
import { defineRouteMiddleware } from '@astrojs/starlight/route-data';

type TocItem = { children?: TocItem[] };

// Headings in the table of contents, not counting the first entry Starlight adds
// for the page title ("Overview").
const countHeadings = (items: TocItem[]): number =>
  items.reduce((n, item) => n + 1 + countHeadings(item.children ?? []), 0);

// The symlink the docs collection is loaded through (src/content.config.ts), and where it
// points in the repository.
const CONTENT_DIR = 'src/content/docs/';
const REPO_DIR = 'docs/';

// The address of the decisions index, the menu entry that a record page belongs to.
const DECISIONS = '/decisions/';

export const onRequest = defineRouteMiddleware((context) => {
  const route = context.locals.starlightRoute;
  const { filePath } = route.entry;
  if (route.editUrl && typeof route.entry.data.editUrl !== 'string' && filePath.startsWith(CONTENT_DIR)) {
    const base = route.editUrl.href.slice(0, route.editUrl.href.length - filePath.length);
    route.editUrl = new URL(base + REPO_DIR + filePath.slice(CONTENT_DIR.length));
  }
  if (context.url.pathname.startsWith(DECISIONS) && context.url.pathname !== DECISIONS) {
    const entry = route.sidebar.find((e) => e.type === 'link' && e.href === DECISIONS);
    if (entry && entry.type === 'link') entry.isCurrent = true;
  }
  if (route.toc && countHeadings(route.toc.items.slice(1)) < 2) {
    route.toc = undefined;
  }
});
