// Two bundles of one holder on one pair of root cards: each bundle keeps its own card list and its own
// sealed copy of the card's secrets; a second bundle gets its copy by a request to the first, which
// wraps the secrets for it. Rests on record 0003, rules 6 to 8 (and record 0005, rule 26, for the way
// request and answer travel). The accent is the wrapped copy that travels in the answer. The bundle
// names are made up.
import { acc, arrow, card, line, rect, text } from './draw.mjs';
import { bundle, lock } from './parts.mjs';
import { svgBox } from './svg.mjs';

const LABEL =
  'Two bundles drawn as open directories, acme on the left and personal on the right, and one card between them at the bottom. ' +
  'Each bundle holds a card list and a padlock chip with its own sealed copy of the card secrets. ' +
  'An arrow from personal to acme carries a request. An arrow from acme to personal carries the answer, a padlock chip in the accent colour: the secrets wrapped for personal.';

const W = 600;
const H = 300;

/** A padlock chip with a label, (x,y) its top left. */
const chip = (x, y, w, word, cls = 'paper-t') => rect(x, y, w, 26, cls, 6) + lock(x + 8, y + 5.5) + text(x + 26, y + 18, word, 't t-s');

function drawing() {
  let s = rect(2, 2, W - 4, H - 4, 'p-frame', 10) + text(16, 27, 'A shared pair', 't t-b');
  s += bundle(20, 232, 220, 168, 'bundle acme');
  s += rect(32, 100, 196, 30, 'paper-t', 5) + text(44, 120, 'card list', 't t-s');
  s += chip(32, 142, 196, 'sealed for acme');
  s += bundle(360, 232, 220, 168, 'bundle personal');
  s += rect(372, 100, 196, 30, 'paper-t', 5) + text(384, 120, 'card list', 't t-s');
  s += chip(372, 142, 196, 'sealed for personal');
  s += arrow(360, 92, 246, 92, 'request', { lx: 303, ly: 84 });
  s += arrow(246, 128, 354, 128, 'answer', { lx: 300, ly: 120 });
  s += acc('wrapped', chip(256, 142, 92, 'wrapped', 'acc-f'));
  s += card(278, 196, 44, 28) + rect(270, 224, 60, 7, 'paper-t', 2);
  s += text(300, 252, 'one card pair', 't t-s', 'm') + text(300, 270, 'one PIN', 't t-s t-dim', 'm');
  s += line(240, 214, 276, 214, 'ln ln-thin ln-dim') + line(324, 214, 360, 214, 'ln ln-thin ln-dim');
  return svgBox(W, H, LABEL, s);
}

export default {
  id: 'two-bundles-one-pair',
  kind: 'single',
  label: 'Two bundles on one pair of root cards, each with its own sealed copy of the card secrets',
  caption:
    'A second bundle gets its own sealed copy of the card’s secrets by a request to the first. The secrets travel wrapped, never in the clear.',
  svg: drawing(),
};
