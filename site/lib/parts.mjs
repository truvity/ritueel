// The parts of a page that asks for `flow: rows` in its front matter (src/content.config.ts):
// each `##` heading and what follows it, up to the next `##`, is wrapped in
// <section class="ritueel-part">, while the page is built, so that src/styles/layout.css can
// lay the parts out in rows of two on a wide screen. What comes before the first `##` stays as it
// is. The headings keep their ids and anchor links (Starlight adds them to the headings later and
// finds them inside the section), so "On this page" and every link to a heading work as before.
// A page without the field is not touched.
//
// Like lib/docs-links.mjs this is a Satteri mdast plugin, added to the Markdown processor by an
// integration in astro.config.mjs. The element is made the way Starlight makes its asides: a node
// with `data.hName`.

/** The Satteri mdast plugin: wraps the parts of a page whose front matter has `flow: rows`. */
export const partsMdastPlugin = {
  name: 'ritueel-parts',
  before(root, ctx) {
    if (ctx.data.astro?.frontmatter?.flow !== 'rows') return;
    const children = [];
    let part = null;
    for (const node of root.children) {
      if (node.type === 'heading' && node.depth === 2) {
        part = { type: 'paragraph', data: { hName: 'section', hProperties: { class: 'ritueel-part' } }, children: [node] };
        children.push(part);
      } else if (part) {
        part.children.push(node);
      } else {
        children.push(node);
      }
    }
    ctx.setProperty(root, 'children', children);
  },
};
