// Drops the table of contents from a page with fewer than two headings: the
// "On this page" bar (src/components/PageSidebar.astro) would only list the page
// title. A page with `tableOfContents: false` has no table of contents to begin
// with.
import { defineRouteMiddleware } from '@astrojs/starlight/route-data';

type TocItem = { children?: TocItem[] };

// Headings in the table of contents, not counting the first entry Starlight adds
// for the page title ("Overview").
const countHeadings = (items: TocItem[]): number =>
  items.reduce((n, item) => n + 1 + countHeadings(item.children ?? []), 0);

export const onRequest = defineRouteMiddleware((context) => {
  const route = context.locals.starlightRoute;
  if (route.toc && countHeadings(route.toc.items.slice(1)) < 2) {
    route.toc = undefined;
  }
});
