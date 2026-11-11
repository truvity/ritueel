import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

// The rules the brief sets for this page, enforced by test over the source.
// (There is no ESLint here: that would be one more dependency. This scan
// reads every source file, strips comments, and fails on a banned call.)

const SRC = new URL('.', import.meta.url).pathname;

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name === 'gen' || name === 'fixtures') continue; // generated code and data
      walk(p, out);
    } else if (/\.(ts|tsx|css)$/.test(name) && !/\.test\.tsx?$/.test(name)) out.push(p);
  }
  return out;
}

const strip = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
const files = walk(SRC);
// The one address that is not a request: the XML namespace an SVG element names.
const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';
const code = files.filter((f) => /\.tsx?$/.test(f)).map((f) => [f, strip(readFileSync(f, 'utf8')).split(SVG_NAMESPACE).join('')] as const);

const BANNED: [string, RegExp][] = [
  ['dangerouslySetInnerHTML', /dangerouslySetInnerHTML/],
  ['innerHTML', /innerHTML/],
  ['insertAdjacentHTML', /insertAdjacentHTML/],
  ['outerHTML', /outerHTML/],
  ['document.write', /\bdocument\s*\.\s*write(ln)?\b/],
  ['eval', /(^|[^.\w])eval\s*[(\[]/],
  ['indirect eval', /\(\s*0\s*,\s*eval\s*\)/],
  ['new Function', /\bnew\s+Function\b/],
  ['Function(...)', /(^|[^.\w])Function\s*\(/],
  ['.constructor(...) to build code', /\.constructor\s*\(\s*['"`]/],
  ['setTimeout or setInterval with a string', /set(Timeout|Interval)\s*\(\s*['"`]/],
  ['a remote URL', /https?:\/\/[a-z0-9]/i],
  ['a protocol-relative URL', /['"`]\/\/[a-z0-9][a-z0-9.-]+\.[a-z]/i],
  ['XMLHttpRequest', /\bXMLHttpRequest\b/],
  ['sendBeacon', /\bsendBeacon\b/],
  ['WebSocket', /\bWebSocket\b/],
  ['EventSource', /\bEventSource\b/],
  ['importScripts', /\bimportScripts\b/],
  ['a script or link element made by hand', /createElement\s*\(\s*['"`](script|link|iframe|object|embed)['"`]/],
  ['a computed access to a banned name', /\[\s*['"`](innerHTML|outerHTML|insertAdjacentHTML|eval|write|Function)['"`]\s*\]/],
  ['a banned name put together from pieces', /['"`](inner|outer|insertAdjacent|dangerously)['"`]\s*\+/],
  ['window.open without noopener', /window\s*\.\s*open\s*\((?![^)]*noopener)/],
  ['cookies', /document\s*\.\s*cookie/],
  ['@import of a remote stylesheet', /@import\s+(url\()?['"]?https?:/],
];

describe('banned calls (src, outside gen/ and fixtures/)', () => {
  it('finds the source files', () => expect(code.length).toBeGreaterThan(25));
  for (const [name, re] of BANNED) {
    it(`has no ${name}`, () => {
      expect(code.filter(([, text]) => re.test(text)).map(([f]) => f)).toEqual([]);
    });
  }
  it('has no fetch: the only network code is the ConnectRPC transport of the real build', () => {
    expect(code.filter(([, text]) => /(^|[^.\w])fetch\s*\(/.test(text) || /\bglobalThis\s*\.\s*fetch\b/.test(text)).map(([f]) => f)).toEqual([]);
  });
  it('has no remote URL in the styles', () => {
    const css = files.filter((f) => f.endsWith('.css')).map((f) => readFileSync(f, 'utf8'));
    for (const c of css) expect(c).not.toMatch(/url\(\s*['"]?(https?:)?\/\//);
  });
});

describe('the page and its files', () => {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  it('links nothing remote and carries a content security policy', () => {
    expect(html).not.toMatch(/(src|href)="(https?:)?\/\//);
    expect(html).toMatch(/Content-Security-Policy/);
    expect(html).toMatch(/default-src 'self'/);
    expect(html).toMatch(/connect-src 'self'/);
    expect(html).toMatch(/form-action 'none'/);
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/); // no inline script
  });
  it('the public script reads storage only inside try', () => {
    const js = readFileSync(new URL('../public/scheme.js', import.meta.url), 'utf8');
    expect(js).not.toMatch(/https?:/);
    expect(js).not.toMatch(/\b(fetch|eval|innerHTML)\b/);
    expect(js.match(/localStorage/g)?.length).toBe(js.match(/try\s*\{[^}]*localStorage/g)?.length);
  });
});

describe('text is readable', () => {
  // The smallest text is 0.75rem (12px). An arbitrary size below it fails.
  const MIN = 0.75;
  const toRem = (v: number, unit: string) => (unit === 'px' ? v / 16 : v);
  it('no Tailwind arbitrary text size, and no font size in the code, is below 12px', () => {
    const bad: string[] = [];
    for (const [f, text] of code) {
      for (const m of text.matchAll(/text-\[(\d*\.?\d+)(rem|px)\]/g)) if (toRem(Number(m[1]), m[2]) < MIN) bad.push(`${f}: ${m[0]}`);
      for (const m of text.matchAll(/fontSize\s*:\s*['"`]?(\d*\.?\d+)(rem|px)?/g)) {
        const unit = m[2] ?? 'px';
        if (toRem(Number(m[1]), unit) < MIN) bad.push(`${f}: ${m[0]}`);
      }
      for (const m of text.matchAll(/text-(2xs|3xs)\b/g)) bad.push(`${f}: ${m[0]}`);
    }
    expect(bad).toEqual([]);
  });
});
