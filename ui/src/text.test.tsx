import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { COMMAND_CAP, copyable, domId, groupFingerprint, isSerial, safeParts, safeString } from './lib/safe';
import { learnPathOk } from './lib/finding';
import { Cmd } from './ui/Cmd';
import { Fp } from './ui/Fp';
import { T } from './ui/T';

// Text from the folder is data. Bidirectional, zero-width and control
// characters show as visible U+XXXX escapes, and a long text is capped.

describe('text from the folder is data', () => {
  it('passes plain ASCII as it is', () => {
    expect(safeString('Example Holder <holder@example.com>')).toBe('Example Holder <holder@example.com>');
  });
  it('shows non-ASCII as U+XXXX', () => {
    expect(safeString('café')).toBe('cafU+00E9');
  });
  it('shows every bidirectional control as an escape', () => {
    for (const cp of [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0x200e, 0x200f, 0x061c]) {
      const hex = cp.toString(16).toUpperCase().padStart(4, '0');
      expect(safeString(`a${String.fromCodePoint(cp)}b`)).toBe(`aU+${hex}b`);
    }
  });
  it('shows every zero-width character as an escape', () => {
    for (const cp of [0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x00ad]) {
      const hex = cp.toString(16).toUpperCase().padStart(4, '0');
      expect(safeString(`a${String.fromCodePoint(cp)}b`)).toBe(`aU+${hex}b`);
    }
  });
  it('shows control characters as escapes', () => {
    expect(safeString('a\u0000b\nc\u007Fd\te\u001b')).toBe('aU+0000bU+000AcU+007FdU+0009eU+001B');
    expect(safeString('\u0085  ')).toBe('U+0085U+2028U+2029');
  });
  it('shows an astral character as one escape', () => {
    expect(safeString('\u{1F511}')).toBe('U+1F511');
  });
  it('marks escapes so they can be drawn apart', () => {
    expect(safeParts('a​b').map((p) => p.escaped)).toEqual([false, true, false]);
  });
  it('caps a very long user ID, and says it was cut', () => {
    const long = 'Example Holder ' + 'x'.repeat(5000) + ' <holder@example.com>';
    const shown = safeString(long, 160);
    expect(shown.startsWith('Example Holder xxxx')).toBe(true);
    expect(shown.length).toBeLessThan(260);
    expect(shown).toMatch(/cut: the text is longer than 160 characters/);
    expect(shown).not.toContain('holder@example.com');
  });
  it('caps by characters, so an escape counts once', () => {
    expect(safeString('‮'.repeat(50), 10)).toBe('U+202E'.repeat(10) + '... (cut: the text is longer than 10 characters)');
  });
});

describe('the component writes text, never markup', () => {
  it('escapes markup and shows hostile characters as codes', () => {
    const html = renderToStaticMarkup(<T>{'<img src=x onerror=alert(1)> ‮ evil'}</T>);
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;img');
    expect(html).toContain('U+202E');
    expect(html).not.toContain('‮');
  });
  it('a very long user ID in the component is capped at its default', () => {
    const html = renderToStaticMarkup(<T cap={100}>{'y'.repeat(100_000)}</T>);
    expect(html.length).toBeLessThan(1000);
  });
  it('a fingerprint is shown whole, in groups of four; a name is not split as one', () => {
    expect(groupFingerprint('10000123456789ABCDEF0123456789ABCDEF0123')).toHaveLength(10);
    expect(groupFingerprint('Not a fingerprint')).toEqual(['Not a fingerprint']);
    const html = renderToStaticMarkup(<Fp value="10000123456789ABCDEF0123456789ABCDEF0123" />);
    expect(html).toContain('1000');
    expect(html).toContain('0123');
  });
});

describe('a command is copied only as the page shows it', () => {
  const ok = 'ritueel personal primary extend --expires-in 3y --plan-only';
  it('copies a plain one-line command', () => {
    expect(copyable(ok)).toBe(true);
  });
  it('never copies a newline, a bidirectional override or a control character', () => {
    expect(copyable('ritueel due\nrm -rf x')).toBe(false);
    expect(copyable('ritueel due ' + String.fromCodePoint(0x202e) + 'x')).toBe(false);
    expect(copyable('ritueel due ' + String.fromCodePoint(0x200d))).toBe(false);
    expect(copyable('ritueel due\u0007')).toBe(false);
    expect(copyable('ritueel due \u00e9')).toBe(false);
  });
  it('never copies more than the page shows', () => {
    expect(copyable('x'.repeat(COMMAND_CAP))).toBe(true);
    expect(copyable('x'.repeat(COMMAND_CAP + 1))).toBe(false);
    expect(copyable('')).toBe(false);
  });
  it('the button is off, and the label is safe, for a command it will not copy', () => {
    const bad = 'ritueel due\n' + String.fromCodePoint(0x202e) + 'rm -rf x' + 'y'.repeat(700);
    const html = renderToStaticMarkup(<Cmd>{bad}</Cmd>);
    expect(html).toMatch(/<button[^>]*disabled/);
    expect(html).toContain('will not copy it');
    expect(html).toContain('U+000A');
    expect(html).toContain('U+202E');
    expect(html).not.toContain(String.fromCodePoint(0x202e));
    expect(html).not.toContain('\n');
  });
  it('the button is on for a plain command', () => {
    expect(renderToStaticMarkup(<Cmd>{ok}</Cmd>)).not.toMatch(/<button[^>]*disabled/);
  });
});

describe('other data the page puts into an address, an id or a command', () => {
  it('a guide path is a plain site path or no link', () => {
    expect(learnPathOk('/learn/expiry/')).toBe(true);
    expect(learnPathOk('/learn/stage-two/#why')).toBe(true);
    for (const bad of ['//evil.example.com/', 'https://evil.example.com/', '/learn/../x', '/learn/x y', '/learn/' + String.fromCodePoint(0x202e), '', undefined]) {
      expect(learnPathOk(bad as string | undefined), String(bad)).toBe(false);
    }
  });
  it('a serial is digits', () => {
    expect(isSerial('00000101')).toBe(true);
    expect(isSerial('1; rm -rf x')).toBe(false);
    expect(isSerial('0000010' + String.fromCodePoint(0x202e))).toBe(false);
  });
  it('an element id made from data holds only letters, digits, underscore and dash', () => {
    expect(domId('0000' + String.fromCodePoint(0x202e) + ' "x"')).toBe('0000__' + '_x_');
    expect(domId('a'.repeat(100)).length).toBe(40);
  });
});
