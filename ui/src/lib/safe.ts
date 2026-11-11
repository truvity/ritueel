// Text from the bundle is data. Before it is drawn, anything that is not
// plain printable ASCII becomes a visible U+XXXX escape, and the length is
// capped. The result is a list of parts so React can draw escapes in their
// own style; React still writes every part as text.

export interface SafePart {
  text: string;
  escaped: boolean;
}

export const DEFAULT_CAP = 240;

function escapeOf(codePoint: number): string {
  const hex = codePoint.toString(16).toUpperCase();
  return 'U+' + (hex.length < 4 ? hex.padStart(4, '0') : hex);
}

/** True for the characters that may be written as they are. */
function isPlain(codePoint: number): boolean {
  return codePoint >= 0x20 && codePoint <= 0x7e;
}

export function safeParts(input: string | undefined | null, cap: number = DEFAULT_CAP): SafePart[] {
  const value = input ?? '';
  const parts: SafePart[] = [];
  let plain = '';
  let count = 0;
  let truncated = false;
  for (const ch of value) {
    if (count >= cap) {
      truncated = true;
      break;
    }
    count += 1;
    const cp = ch.codePointAt(0) ?? 0;
    if (isPlain(cp)) {
      plain += ch;
    } else {
      if (plain) parts.push({ text: plain, escaped: false });
      plain = '';
      parts.push({ text: escapeOf(cp), escaped: true });
    }
  }
  if (plain) parts.push({ text: plain, escaped: false });
  if (truncated) parts.push({ text: '... (cut: the text is longer than ' + cap + ' characters)', escaped: false });
  return parts;
}

/** The same rule as a plain string, for places that need no styling. */
export function safeString(input: string | undefined | null, cap: number = DEFAULT_CAP): string {
  return safeParts(input, cap)
    .map((p) => p.text)
    .join('');
}

/** The longest fingerprint or digest the page groups and shows whole. */
export const FINGERPRINT_CAP = 130;

/**
 * A fingerprint or a digest in groups of four. Only hexadecimal is split;
 * anything else is shown as safe text in one piece, so a name can never pass
 * for a fingerprint.
 */
export function groupFingerprint(fp: string, size = 4): string[] {
  const clean = safeString(fp, FINGERPRINT_CAP);
  if (!/^[0-9A-Fa-f]+$/.test(clean)) return [clean];
  const groups: string[] = [];
  for (let i = 0; i < clean.length; i += size) groups.push(clean.slice(i, i + size));
  return groups;
}

/** Splits a sentence into plain text and long hexadecimal runs (fingerprints, digests). */
export function splitHexRuns(text: string): { text: string; hex: boolean }[] {
  const out: { text: string; hex: boolean }[] = [];
  const re = /[0-9A-Fa-f]{32,}/g;
  let last = 0;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (m.index > last) out.push({ text: text.slice(last, m.index), hex: false });
    out.push({ text: m[0], hex: true });
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push({ text: text.slice(last), hex: false });
  return out;
}

/** The longest command the page shows whole, and so the longest it will copy. */
export const COMMAND_CAP = 500;

/**
 * True when the page shows this command exactly as it is, and so may copy it:
 * every character is plain printable ASCII (no newline, no bidirectional or
 * zero-width character) and the whole text fits under the cap. What the screen
 * did not show in full is never put on the clipboard.
 */
export function copyable(text: string): boolean {
  return text.length > 0 && text.length <= COMMAND_CAP && safeString(text, Infinity) === text;
}

/** A name for an element id or a DOM key, made from data: letters, digits, "_" and "-" only. */
export function domId(input: string | undefined | null, cap = 40): string {
  return (input ?? '').replace(/[^A-Za-z0-9_-]/g, '_').slice(0, cap);
}

/** A card serial as a person reads it: digits only. A serial of any other shape is never put into a command the page builds. */
export function isSerial(input: string | undefined | null): boolean {
  return /^[0-9]{4,16}$/.test(input ?? '');
}
