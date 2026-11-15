// The parts of a page that asks for `flow: rows` or `flow: landing` in its front matter (src/content.config.ts):
// each `##` heading and what follows it, up to the next `##`, is wrapped in
// <section class="ritueel-part">, while the page is built, so that the page can lay the parts out
// in rows of two on a wide screen. What comes before the first `##` stays as it is. The headings keep
// their ids and anchor links (Starlight adds them to the headings later and finds them inside the
// section), so "On this page" and every link to a heading work as before.
// `rows` is for a page of many short parts (the design page).
//
// `landing` is a case page (docs/pki.md and four more), which a visitor may reach by a shared link
// and which stands alone. The parts get classes of their own, `lp-part lp-<name>`, and not
// `ritueel-part`, so that no rule of the rows applies to them (src/styles/site.css, "A CASE PAGE").
// The names of these classes are the contract that the look styles:
//   - `## The pain` is `lp-pain` (the reader's own lines, read first), `## What ritueel does for you`
//     is `lp-does`, `## What to do` is `lp-do`, `## What not to do` is `lp-dont`, `## Read next` is
//     `lp-read`;
//   - inside "does", a thematic break (`---`) cuts the part in segments. A segment that starts
//     with a `###` heading (the block "Next to what you already run") is its own part, `lp-nextto`.
//     The segment after the last break (the stage of ritueel and the button) is the block
//     `lp-stage`, which stays INSIDE `lp-does`: the first paragraph of it is the label of the stage
//     (`lp-stagelabel`), the others are lines under it (`lp-stageline`). What is before the first
//     break stays in `lp-does`. The breaks are dropped;
//   - a paragraph in "What to do" or "What not to do" is a note under the list (`lp-note`);
//   - a paragraph that holds only a bold link is the button of the page (`lp-button`), and the last
//     paragraph of "Read next" is the row of the two quiet links (`lp-links`).
// A page without the field is not touched.
//
// Like lib/docs-links.mjs this is a Satteri mdast plugin, added to the Markdown processor by an
// integration in astro.config.mjs. The element is made the way Starlight makes its asides: a node
// with `data.hName`.

const section = (cls, children) => ({ type: 'paragraph', data: { hName: 'section', hProperties: { class: cls } }, children });
const text = (n) => (n.children ?? []).map((c) => c.value ?? text(c)).join('').trim();
const LANDING_PART = { 'the pain': 'pain', 'what ritueel does for you': 'does', 'what to do': 'do', 'what not to do': 'dont', 'read next': 'read' };
const isButton = (n) => n.type === 'paragraph' && n.children?.[0]?.type === 'strong' && n.children[0].children?.some((c) => c.type === 'link');
const withClass = (n, cls) => ({ ...n, data: { ...n.data, hName: 'p', hProperties: { class: cls } } });

/** One node of the stage segment: the button, the bold label of the stage, or a line under it. */
function stageNode(n, i) {
  if (isButton(n)) return withClass(n, 'lp-button');
  if (n.type !== 'paragraph') return n;
  return withClass(n, i === 0 ? 'lp-stagelabel' : 'lp-stageline');
}

/** The parts of a case page, from the nodes of one `##` section ("does" is cut in segments). */
function landingParts(heading, rest) {
  const name = LANDING_PART[text(heading).toLowerCase()] ?? 'other';
  if (name === 'does') {
    const segments = [[]];
    for (const n of rest) n.type === 'thematicBreak' ? segments.push([]) : segments.at(-1).push(n);
    const first = segments.shift();
    const last = segments.length && segments.at(-1)[0]?.type !== 'heading' ? segments.pop() : null;
    // The does-paragraphs, the stage and the button are one part, so that they stand together in one
    // grid cell whatever the height of the parts beside them.
    const inside = [heading, ...first];
    // The button is outside the block of the stage, under it.
    if (last) inside.push(section('lp-stage', last.filter((n) => !isButton(n)).map(stageNode)), ...last.filter(isButton).map(stageNode));
    const out = [section('lp-part lp-does', inside)];
    // The small table's heading is a level-2 heading like the others, so that the columns start on the
    // same line in the same type.
    for (const seg of segments) out.push(section('lp-part lp-nextto', [{ ...seg[0], depth: 2 }, ...seg.slice(1)]));
    return out;
  }
  const kids = rest.slice();
  // A paragraph in "What to do" or "What not to do" is a note under the list, not a point of it.
  if (name === 'do' || name === 'dont') for (let i = 0; i < kids.length; i++) if (kids[i].type === 'paragraph') kids[i] = withClass(kids[i], 'lp-note');
  if (name === 'read' && kids.length && kids.at(-1).type === 'paragraph') kids.push(withClass(kids.pop(), 'lp-links'));
  return [section(`lp-part lp-${name}`, [heading, ...kids])];
}

/** The nodes of a case page: what comes before the first `##` stays, each `##` becomes its parts. */
function landing(nodes) {
  const out = [];
  let head = null;
  let rest = [];
  const flush = () => {
    if (head) out.push(...landingParts(head, rest));
    head = null;
    rest = [];
  };
  for (const node of nodes) {
    if (node.type === 'heading' && node.depth === 2) {
      flush();
      head = node;
    } else if (head) {
      rest.push(node);
    } else {
      out.push(node);
    }
  }
  flush();
  return out;
}

/** The Satteri mdast plugin: wraps the parts of a page whose front matter has `flow: rows` or `flow: landing`. */
export const partsMdastPlugin = {
  name: 'ritueel-parts',
  before(root, ctx) {
    const flow = ctx.data.astro?.frontmatter?.flow;
    if (flow !== 'rows' && flow !== 'landing') return;
    if (flow === 'landing') return ctx.setProperty(root, 'children', landing(root.children));
    const children = [];
    let part = null;
    for (const node of root.children) {
      if (node.type === 'heading' && node.depth === 2) {
        part = section('ritueel-part', [node]);
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
