// The outer element of every drawing, in one place so that no figure forgets what the test demands:
// role="img", an aria-label that says what is drawn, and data-pagefind-ignore (the words inside a
// drawing stay out of the search index; the captions on the page stay in it).
const esc = (t) => String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** <svg> of a viewBox `w` by `h`. `cls` is for the layout drawings ('fig-wide', 'fig-narrow'). */
export function svgBox(w, h, label, inner, cls = '') {
  return (
    `<svg${cls ? ` class="${cls}"` : ''} viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(label)}" data-pagefind-ignore>` +
    inner +
    '</svg>'
  );
}
