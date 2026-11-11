// The HTML of a figure, one function for the Figure.astro component, the preview and the test, so
// that what the owner looks at is what the site builds.
import { esc } from './draw.mjs';

/** Text for a double-quoted attribute: `esc` leaves the quote alone, and a quote would end the value. */
const escAttr = (t) => esc(t).replace(/"/g, '&quot;');

/**
 * <figure> with its drawing(s) and its caption. `captionHtml` is HTML that is already safe (the
 * page's own caption, rendered from the slot), or the module's own plain-text caption, escaped.
 * A strip is an ordered list of panels, each with its caption as text under it; a layout holds two
 * drawings of which CSS shows one; a single is one drawing. The class not-content keeps Starlight's
 * Markdown styles (list numbers, paragraph spacing) off it.
 */
export function renderFigure(fig, captionHtml = esc(fig.caption)) {
  let inner;
  if (fig.kind === 'strip') {
    inner =
      `<ol class="fig-panels" role="list" aria-label="${escAttr(fig.label)}">` +
      fig.panels
        .map((p) => `<li>${p.svg}<p class="fig-cap"><strong>${p.n} ${esc(p.title)}.</strong> ${esc(p.caption)}</p></li>`)
        .join('') +
      '</ol>';
  } else if (fig.kind === 'layout') {
    inner = fig.wide + fig.narrow;
  } else if (fig.kind === 'single') {
    inner = fig.svg;
  } else {
    throw new Error(`figure ${fig.id}: unknown kind ${fig.kind}`);
  }
  return `<figure class="fig fig-${fig.kind} not-content" data-figure="${escAttr(fig.id)}">${inner}<figcaption>${captionHtml}</figcaption></figure>`;
}
