// Two bundles of one holder on one pair of root cards: each bundle keeps its own card list and its own
// sealed copy of the card's secrets; a second bundle gets its copy by a request to the first, which
// wraps the secrets for it. Rests on record 0003, rules 6 to 8 (and record 0005, rule 26, for the way
// request and answer travel). The pair is two cards, and each card has its own PIN, PUK and management
// key for all its bundles (record 0003, rule 6). The accent is the wrapped copy that travels in the
// answer. The drawing is 360 units wide and tall, the two bundles stacked, so that on a phone it is
// drawn at about 1:1 and its text stays at 12px. The bundle names are made up.
import { acc, arrow, card, line, rect, text } from './draw.mjs';
import { bundle, lock } from './parts.mjs';
import { svgBox } from './svg.mjs';

const LABEL =
  'Two bundles drawn as open directories, acme above and personal below, with two cards between them. ' +
  'Each bundle holds a card list and a padlock chip with its own sealed copy of the card secrets. ' +
  'An arrow up from personal to acme carries a request. An arrow down from acme to personal carries the answer, a padlock chip in the accent colour: the secrets wrapped for personal. ' +
  'Beside the cards a note says each card has one PIN for all its bundles.';

const W = 360;
const H = 486;

/** A padlock chip with a label, (x,y) its top left. */
const chip = (x, y, w, word, cls = 'paper-t') => rect(x, y, w, 26, cls, 6) + lock(x + 8, y + 5.5) + text(x + 26, y + 18, word, 't t-s');

/** A bundle with its card list and its sealed copy, `top` its top edge, 328 wide at x = 16. */
function holder(top, name) {
  return (
    bundle(16, top + 112, 328, 112, `bundle ${name}`) +
    rect(28, top + 28, 304, 30, 'paper-t', 5) + text(40, top + 48, 'card list', 't t-s') +
    chip(28, top + 68, 304, `sealed for ${name}`)
  );
}

function drawing() {
  let s = rect(2, 2, W - 4, H - 4, 'p-frame', 10);
  s += holder(16, 'acme');
  s += holder(358, 'personal');
  // the pair: two cards, one behind the other, joined to both bundles
  s += line(110, 128, 110, 202, 'ln ln-thin ln-dim') + line(110, 256, 110, 358, 'ln ln-thin ln-dim');
  s += card(88, 206, 44, 28) + card(104, 222, 44, 28);
  s += text(170, 228, 'a pair of root cards', 't t-s t-long') + text(170, 246, 'one PIN on each card,', 't t-s t-long t-dim') + text(170, 262, 'for all its bundles', 't t-s t-long t-dim');
  // the request goes up, the answer comes down
  s += arrow(40, 346, 40, 136, 'request', { lx: 72, ly: 300 });
  s += arrow(324, 136, 324, 344, 'answer', { lx: 292, ly: 160 });
  s += acc('wrapped', chip(232, 296, 92, 'wrapped', 'acc-f'));
  return svgBox(W, H, LABEL, s, 'fig-small');
}

export default {
  id: 'two-bundles-one-pair',
  kind: 'single',
  label: 'Two bundles on one pair of root cards, each with its own sealed copy of the card secrets',
  caption:
    'A second bundle gets its own sealed copy of the card’s secrets from the answer to a request to the first. The secrets travel wrapped, never in the clear.',
  svg: drawing(),
};
