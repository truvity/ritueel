// A big key glyph, shared by the figures of the YubiKey page: a ring, a shaft and two teeth, centred
// on (cx,cy). `cls` is the line class ('ln ln-key', or with 'ln-acc' inside an accent object).
import { circle, line } from './draw.mjs';

export function keyBig(cx, cy, cls = 'ln ln-key') {
  return circle(cx - 14, cy, 8, cls) + line(cx - 6, cy, cx + 20, cy, cls) + line(cx + 10, cy, cx + 10, cy + 8, cls) + line(cx + 19, cy, cx + 19, cy + 8, cls);
}
