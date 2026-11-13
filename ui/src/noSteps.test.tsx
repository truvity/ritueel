import { describe, expect, it, vi } from 'vitest';
import type { ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { CeremonyCommand } from './gen/ritueel/local/v1alpha1/common_pb';
import { COMMAND_TEXT } from './lib/commands';
import { feed, noStyle, plain, WORLDS, type World } from './testkit';

vi.mock('./api/hooks', async (orig) => (await import('./testkit')).hooksMock(await orig()));

// A ceremony is one act, `apply` (record 0005, rule 3). The page names no steps of it: no list
// of plan, confirm, reserve, sign, verify and record, and no numbered list of six. The panel of a
// ceremony says in one sentence what its command does. This test draws every screen that can
// carry such a list, for every example bundle and scene, and fails when a step list comes back.
// The four words of the state of a ceremony (planned, started, recorded, closed) are not steps.

const TITLES = ['Plan', 'Confirm', 'Reserve', 'Sign', 'Verify', 'Record'];

async function screens(w: World): Promise<[string, () => ReactElement][]> {
  const { Todo } = await import('./screens/Todo');
  const { Inventory } = await import('./screens/Inventory');
  const { History } = await import('./screens/History');
  const { Trust } = await import('./screens/Trust');
  const list: [string, () => ReactElement][] = [
    ['to do', () => <Todo tab="changes" />],
    ['findings', () => <Todo tab="findings" />],
    ['inventory by card', () => <Inventory view="cards" />],
    ['inventory by root', () => <Inventory view="roots" />],
    ['inventory by date', () => <Inventory view="dates" />],
    ['history', () => <History />],
    ['trust set', () => <Trust />],
  ];
  for (const c of w.ceremonies.ceremonies) list.push([`ceremony ${c.id}`, () => <History id={c.id} />]);
  return list;
}

/** The list items of every ordered list of the markup, as the plain text of each. */
function orderedLists(html: string): string[][] {
  return [...html.matchAll(/<ol\b[^>]*>([\s\S]*?)<\/ol>/g)].map((m) => [...m[1].matchAll(/<li\b[^>]*>([\s\S]*?)<\/li>/g)].map((li) => plain(li[1])));
}

describe('the page shows no list of steps of a ceremony', () => {
  for (const plainWorld of WORLDS()) {
    it(`no screen of ${plainWorld.id} holds a step list`, async () => {
      feed.world = plainWorld;
      feed.state = 'ready';
      const problems: string[] = [];
      let panels = 0;
      for (const [name, render] of await screens(plainWorld)) {
        const html = noStyle(renderToStaticMarkup(render()));
        const text = plain(html);
        if (/usual steps/i.test(text)) problems.push(`${name}: "The usual steps"`);
        if (/\b\d+ steps\b|\bsix steps\b/i.test(text)) problems.push(`${name}: a count of steps`);
        // The words "reserve" and "verify" as step names: a title that ends in a full stop or stands as a list item.
        for (const t of ['Reserve', 'Verify']) {
          if (new RegExp(`(^|[.>]\\s*)${t}\\.`).test(text) || new RegExp(`<li[^>]*>\\s*(<[^>]+>\\s*)*${t}\\b`, 'i').test(html)) problems.push(`${name}: "${t}" as a step name`);
        }
        // Two or more of the six titles, each followed by a full stop, are a catalogue.
        const titled = TITLES.filter((t) => new RegExp(`(^|[.>]\\s)${t}\\. `).test(text));
        if (titled.length >= 2) problems.push(`${name}: step titles ${titled.join(', ')}`);
        // In History a numbered list of six or more items is a step list (the place of a ceremony has three words).
        // Other screens have long numbered lists of their own, such as the findings.
        for (const items of orderedLists(html)) {
          if (items.length >= 6 && (name.startsWith('ceremony ') || name === 'history')) problems.push(`${name}: a numbered list of ${items.length} (${items.slice(0, 2).join(' | ')} ...)`);
          if (TITLES.filter((t) => items.some((i) => i.startsWith(t))).length >= 3) problems.push(`${name}: a list that starts with step titles`);
        }
        if (name.startsWith('ceremony ')) panels += 1;
      }
      expect(problems).toEqual([]);
      expect(panels).toBe(plainWorld.ceremonies.ceremonies.length);
      expect(panels).toBeGreaterThan(0);
    });
  }

  it('the checker sees a step list when one is drawn', () => {
    const six = `<ol>${TITLES.map((t) => `<li><span>${t}.</span> text</li>`).join('')}</ol>`;
    expect(orderedLists(six)[0]).toHaveLength(6);
    expect(TITLES.filter((t) => orderedLists(six)[0].some((i) => i.startsWith(t)))).toHaveLength(6);
    expect(new RegExp('<li[^>]*>\\s*(<[^>]+>\\s*)*Reserve\\b', 'i').test(six)).toBe(true);
  });
});

describe('the panel of a ceremony says what its command does', () => {
  it('has one sentence for apply and one for close, and nothing for any other value', () => {
    expect(Object.keys(COMMAND_TEXT).sort()).toEqual([String(CeremonyCommand.APPLY), String(CeremonyCommand.CLOSE)].sort());
    expect(COMMAND_TEXT[CeremonyCommand.APPLY]?.title).toBe('What apply does');
    expect(COMMAND_TEXT[CeremonyCommand.CLOSE]?.title).toBe('What close does');
    // One sentence of the plan to the record for apply; close says only what record 0005, rules 7 and 31, say.
    expect(COMMAND_TEXT[CeremonyCommand.CLOSE]?.text).not.toMatch(/closing record|reason/i);
  });
  it('every ceremony panel shows the sentence of its command, and the state words stay', async () => {
    const { History } = await import('./screens/History');
    for (const w of WORLDS()) {
      feed.world = w;
      feed.state = 'ready';
      for (const c of w.ceremonies.ceremonies) {
        const t = COMMAND_TEXT[c.command];
        expect(t, `${w.id} ${c.id}: a command with no sentence`).toBeDefined();
        const text = plain(noStyle(renderToStaticMarkup(<History id={c.id} />)));
        expect(text, `${w.id} ${c.id}`).toContain(t!.title);
        expect(text, `${w.id} ${c.id}`).toContain(t!.text.replace(/'/g, "'"));
        if (c.command === CeremonyCommand.APPLY) for (const word of ['planned', 'started']) expect(text).toContain(word);
      }
    }
  });
});
