import { describe, expect, it, vi } from 'vitest';
import type { ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ObjectKind, Store } from './gen/ritueel/local/v1alpha1/common_pb';
import type { ObjectRef } from './gen/ritueel/local/v1alpha1/common_pb';
import { feed, loadWorld, noStyle, plain, WORLDS, attrsOf, type World } from './testkit';
import { objectSlug, type InventoryView, type ObjectSlug } from './lib/route';
import { buildIndex, cardGroups } from './lib/inventory';

vi.mock('./api/hooks', async (orig) => (await import('./testkit')).hooksMock(await orig()));

// The three views of Inventory list the same keys, and a change that is not applied yet is
// marked on its object in every view that lists the object. The rows carry data attributes
// (data-key-fp, data-object, data-changes) so the rule is checked from the markup.
// A static render draws the narrow layout: a row is an li, and the choice of the first object
// of a wide screen is not made. Each test names the object it wants.

const VIEWS: InventoryView[] = ['cards', 'roots', 'dates'];

async function view(w: World, v: InventoryView, object?: { kind: ObjectSlug; id: string }): Promise<string> {
  const { Inventory } = await import('./screens/Inventory');
  feed.world = w;
  feed.state = 'ready';
  const el: ReactElement = <Inventory view={v} object={object} />;
  return noStyle(renderToStaticMarkup(el));
}

/** Every element of the markup that carries a data-object attribute, with its attributes and the markup up to the next such element. */
function marked(html: string): { attrs: Record<string, string>; chunk: string }[] {
  const out: { attrs: Record<string, string>; chunk: string }[] = [];
  const starts = [...html.matchAll(/<[a-z]+ [^>]*\bdata-object="[^"]*"[^>]*>/g)];
  starts.forEach((m, i) => {
    const end = starts[i + 1]?.index ?? html.length;
    out.push({ attrs: attrsOf(m[0]), chunk: html.slice(m.index, end) });
  });
  return out;
}

const fingerprints = (html: string) => new Set([...html.matchAll(/\bdata-key-fp="([^"]*)"/g)].map((m) => m[1]));

describe('N1: the three views show the same keys', () => {
  for (const w of WORLDS()) {
    it(w.id, async () => {
      const all = new Set(w.inventory.keys.map((k) => k.fingerprint));
      const cards = fingerprints(await view(w, 'cards'));
      const roots = fingerprints(await view(w, 'roots'));
      const dates = fingerprints(await view(w, 'dates'));
      expect([...cards].sort(), 'by card').toEqual([...all].sort());
      expect([...roots].sort(), 'by root').toEqual([...all].sort());
      // By date lists certifications; a key is there as an issuer or as the subject of a certification.
      const inCertifications = new Set<string>();
      for (const c of w.inventory.certifications) {
        inCertifications.add(c.issuer);
        if (c.subject?.kind === ObjectKind.KEY) inCertifications.add(c.subject.id);
      }
      for (const fp of dates) expect(all.has(fp), `${w.id}: by date names a key the inventory lacks`).toBe(true);
      expect([...dates].sort(), 'by date').toEqual([...inCertifications].filter((fp) => all.has(fp)).sort());
    });
  }
  it('acme, scene 1: 11 keys by card and by root, and 8 certifications by date', async () => {
    const w = loadWorld('acme', 1);
    expect((await view(w, 'cards')).match(/data-key-fp=/g)).not.toBeNull();
    expect(fingerprints(await view(w, 'cards')).size).toBe(11);
    expect(fingerprints(await view(w, 'roots')).size).toBe(11);
    const dates = marked(await view(w, 'dates')).filter((m) => m.attrs['data-object'].startsWith('certification/'));
    expect(dates).toHaveLength(8);
  });
  it('a fingerprint in an attribute is the whole fingerprint, and no row shows it in a cell', async () => {
    const w = loadWorld('acme', 1);
    const html = await view(w, 'cards');
    for (const fp of fingerprints(html)) expect(fp).toMatch(/^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$/);
    // The table shows a key as "key A", never as its fingerprint (the panel does).
    expect(plain(html)).not.toMatch(/[0-9a-fA-F]{16}/);
  });
});

/** The objects a change names: its own and the ones it involves. */
const objectsOfChange = (c: { object?: ObjectRef; involves: ObjectRef[] }): ObjectRef[] => [...(c.object ? [c.object] : []), ...c.involves];

describe('N2: a change is marked on its object in each view that lists the object', () => {
  for (const w of WORLDS()) {
    it(w.id, async () => {
      let checked = 0;
      for (const v of VIEWS) {
        const rows = marked(await view(w, v));
        for (const c of w.inventory.changes)
          for (const o of objectsOfChange(c)) {
            const slug = objectSlug(o.kind);
            if (!slug) continue;
            for (const row of rows.filter((r) => r.attrs['data-object'] === `${slug}/${o.id}`)) {
              checked += 1;
              expect((row.attrs['data-changes'] ?? '').split(' '), `${w.id} ${v}: ${slug}/${o.id} carries ${c.id}`).toContain(c.id);
              expect(plain(row.chunk), `${w.id} ${v}: ${slug}/${o.id} shows a mark`).toMatch(/\b\d+ changes? not applied yet/);
            }
          }
      }
      if (w.inventory.changes.length > 0) expect(checked, `${w.id}: the walk met a marked row`).toBeGreaterThan(0);
    });
  }
  it('no row carries a change that does not name it, directly or through a group it holds', async () => {
    for (const w of WORLDS()) {
      const ids = new Set(w.inventory.changes.map((c) => c.id));
      for (const v of VIEWS)
        for (const row of marked(await view(w, v)))
          for (const id of (row.attrs['data-changes'] ?? '').split(' ').filter(Boolean)) expect(ids.has(id), `${w.id} ${v}: ${row.attrs['data-object']} names ${id}`).toBe(true);
    }
  });
  it('acme, scene 1: By root marks delegation acme-release, By date marks certification cert-8, By card marks nothing', async () => {
    const w = loadWorld('acme', 1);
    const withChange = async (v: InventoryView) => marked(await view(w, v)).filter((r) => r.attrs['data-changes']).map((r) => r.attrs['data-object']);
    expect(await withChange('roots')).toContain('delegation/acme-release');
    expect(await withChange('dates')).toEqual(['certification/cert-8']);
    expect(await withChange('cards')).toEqual([]);
  });
  it('acme, scene 2: the new user IDs are marked by root, the OpenPGP keys of A, B and C by card and by root, the root cards by card', async () => {
    const w = loadWorld('acme', 2);
    const withChange = async (v: InventoryView) => new Set(marked(await view(w, v)).filter((r) => r.attrs['data-changes']).map((r) => r.attrs['data-object']));
    const byRoot = await withChange('roots');
    for (const id of ['uid-A-2', 'uid-B-2', 'uid-C-2']) expect(byRoot.has(`userid/${id}`), id).toBe(true);
    const primaries = w.inventory.keys.filter((k) => k.root === 'acme-release' && k.role === 1 /* ROOT_KEY */).map((k) => `key/${k.fingerprint}`);
    expect(primaries).toHaveLength(3);
    const byCard = await withChange('cards');
    for (const p of primaries) {
      expect(byCard.has(p), `by card ${p}`).toBe(true);
      expect(byRoot.has(p), `by root ${p}`).toBe(true);
    }
    expect(byCard.has('card/root-a')).toBe(true);
    expect(byCard.has('card/root-b')).toBe(true);
    expect(byCard.has('card/day-ana')).toBe(false);
  });
});

describe('N2b: the panel counts the ceremonies that touched an object', () => {
  for (const w of WORLDS()) {
    it(w.id, async () => {
      const inv = w.inventory;
      const objects: { kind: ObjectSlug; id: string; view: InventoryView; touched: number }[] = [
        ...inv.cards.map((o) => ({ kind: 'card' as const, id: o.name, view: 'cards' as const, touched: o.touchedBy.length })),
        ...inv.roots.map((o) => ({ kind: 'root' as const, id: o.name, view: 'roots' as const, touched: o.touchedBy.length })),
        ...inv.keys.map((o) => ({ kind: 'key' as const, id: o.fingerprint, view: 'roots' as const, touched: o.touchedBy.length })),
        ...inv.userIds.map((o) => ({ kind: 'userid' as const, id: o.id, view: 'roots' as const, touched: o.touchedBy.length })),
        ...inv.delegations.map((o) => ({ kind: 'delegation' as const, id: o.name, view: 'roots' as const, touched: o.touchedBy.length })),
        ...inv.certifications.map((o) => ({ kind: 'certification' as const, id: o.id, view: 'dates' as const, touched: o.touchedBy.length })),
        ...inv.requests.map((o) => ({ kind: 'request' as const, id: o.stem, view: 'roots' as const, touched: o.touchedBy.length })),
      ];
      let withCount = 0;
      for (const o of objects) {
        const text = plain(await view(w, o.view, { kind: o.kind, id: o.id }));
        const m = /Ceremonies \((\d+)\)/.exec(text);
        if (o.touched === 0) {
          expect(m, `${w.id}: ${o.kind} ${o.id} lists no ceremony`).toBeNull();
        } else {
          withCount += 1;
          expect(m?.[1], `${w.id}: ${o.kind} ${o.id}`).toBe(String(o.touched));
        }
      }
      expect(withCount, `${w.id}: some object was touched`).toBeGreaterThan(0);
    });
  }
});

describe('N3: a cloud key shows its provider and its account', () => {
  const SSH_C = '0f8b64c10f8b64c10f8b64c10f8b64c10f8b64c10f8b64c10f8b64c10f8b64c1';

  for (const w of WORLDS()) {
    it(`${w.id}: By card has one group for each provider and account, and each key is in the group of its own account`, () => {
      const groups = cardGroups(buildIndex(w.inventory)).filter((g) => g.kind === 'cloud');
      const cloud = w.inventory.keys.filter((k) => k.place?.store === Store.AWS_KMS);
      const wanted = new Set(cloud.map((k) => `${k.place?.provider}/${k.place?.account}`));
      expect(groups.map((g) => `${g.provider}/${g.account}`).sort(), 'one group each').toEqual([...wanted].sort());
      for (const g of groups) for (const k of g.keys) expect(k.place?.account, `${w.id}: ${k.fingerprint}`).toBe(g.account);
      expect(groups.flatMap((g) => g.keys).length, 'every cloud key is in a group').toBe(cloud.length);
    });
  }

  it('acme, scene 1: two groups, each with its provider and account in its title line', async () => {
    const text = plain(await view(loadWorld('acme', 1), 'cards'));
    expect(text).toContain('Cloud keys · AWS KMS · account 444455556666');
    expect(text).toContain('Cloud keys · AWS KMS · account 111122223333');
    expect(text.match(/Cloud keys/g)).toHaveLength(2);
    // The Region stays in the column Place.
    expect(text).toContain('eu-west-1');
  });
  it('globex: its own account and the other account of its one delegated key', async () => {
    const text = plain(await view(loadWorld('globex', 1), 'cards'));
    expect(text).toContain('Cloud keys · AWS KMS · account 123456789012');
    expect(text).toContain('Cloud keys · AWS KMS · account 111122223333');
  });
  it('a bundle with no cloud key has no cloud group', async () => {
    expect(plain(await view(loadWorld('personal', 1), 'cards'))).not.toContain('Cloud keys');
  });
  it('By root says the provider and the account where a card says its name', async () => {
    const text = plain(await view(loadWorld('acme', 1), 'roots'));
    expect(text).toContain('AWS · 444455556666');
    // A delegation line has no Place cell, so the key it holds in the other account is not drawn here.
    expect(text).not.toContain('cloud key');
  });
  it('the key panel has Provider and Account before Region', async () => {
    const html = await view(loadWorld('acme', 1), 'cards', { kind: 'key', id: SSH_C });
    const text = plain(html);
    const at = (word: string) => text.indexOf(` ${word} `);
    expect(text).toMatch(/ Provider AWS Account 444455556666 /);
    expect(at('Store')).toBeGreaterThan(-1);
    expect(at('Provider')).toBeGreaterThan(at('Store'));
    expect(at('Account')).toBeGreaterThan(at('Provider'));
    expect(at('Region')).toBeGreaterThan(at('Account'));
  });
  it('a card key has no Provider and no Account row', async () => {
    const text = plain(await view(loadWorld('acme', 1), 'cards', { kind: 'key', id: '3a1f9c023a1f9c023a1f9c023a1f9c023a1f9c023a1f9c023a1f9c023a1f9c02' }));
    expect(text).not.toContain(' Provider ');
    expect(text).not.toContain(' Account ');
  });
  it('a long or odd account is cut by its cap in the title, the cell and the panel, and never reaches the markup whole', async () => {
    const base = loadWorld('acme', 1);
    const odd = '4'.repeat(300) + '\u202e' + 'x';
    const w = { ...base, inventory: { ...base.inventory, keys: base.inventory.keys.map((k) => (k.place?.store === Store.AWS_KMS ? { ...k, place: { ...k.place, account: odd } } : k)) } } as World;
    for (const [v, object] of [['cards', undefined], ['roots', undefined], ['cards', { kind: 'key' as const, id: SSH_C }]] as const) {
      const html = await view(w, v, object);
      expect(html, `${v}: the whole account`).not.toContain('4'.repeat(40));
      expect(html, `${v}: the override`).not.toContain('\u202e');
      expect(plain(html), `${v}: marked as cut`).toContain('cut');
    }
  });
});
