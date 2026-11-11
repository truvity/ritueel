import { describe, expect, it } from 'vitest';
import { href, hrefOf, parseHash, routeForBundle, type BundleContents, type Route } from './lib/route';

describe('hash routes', () => {
  it('an empty hash is Start', () => {
    expect(parseHash('')).toEqual({ name: 'start' });
    expect(parseHash('#')).toEqual({ name: 'start' });
    expect(parseHash('#/')).toEqual({ name: 'start' });
  });
  it('names every screen', () => {
    expect(parseHash('#/findings')).toEqual({ name: 'findings' });
    expect(parseHash('#/roots')).toEqual({ name: 'roots' });
    expect(parseHash('#/trust')).toEqual({ name: 'trust' });
    // A root is named by its label inside the bundle the page shows: A, B ... Never by a bundle or a company.
    expect(parseHash('#/key')).toEqual({ name: 'key', root: 'A' });
    expect(parseHash('#/key/A')).toEqual({ name: 'key', root: 'A' });
    expect(parseHash('#/key/B')).toEqual({ name: 'key', root: 'B' });
    expect(parseHash('#/cards/00000001')).toEqual({ name: 'cards', serial: '00000001' });
    expect(parseHash('#/history/20261103T142000Z-init')).toEqual({ name: 'history', id: '20261103T142000Z-init' });
    expect(parseHash('#/plan/renew-due')).toEqual({ name: 'plan', goal: 'renew-due' });
    expect(parseHash('#plan')).toEqual({ name: 'plan', goal: undefined });
  });
  it('an unknown hash is not found, never another screen', () => {
    expect(parseHash('#/nope')).toEqual({ name: 'notfound', hash: '#/nope' });
    expect(parseHash('#/findings/extra')).toMatchObject({ name: 'notfound' });
    expect(parseHash('#/cards/a/b')).toMatchObject({ name: 'notfound' });
  });
  it('a malformed escape is not found and does not throw', () => {
    expect(parseHash('#/key/%E0%A4%A')).toMatchObject({ name: 'notfound' });
  });
  it('links round-trip', () => {
    expect(parseHash(href.key('a b'))).toEqual({ name: 'key', root: 'a b' });
    expect(parseHash(href.key())).toEqual({ name: 'key', root: 'A' });
    expect(parseHash(href.key('B'))).toEqual({ name: 'key', root: 'B' });
    expect(parseHash(href.history('20261103T142000Z-init'))).toEqual({ name: 'history', id: '20261103T142000Z-init' });
    expect(parseHash(href.cards('00000004'))).toEqual({ name: 'cards', serial: '00000004' });
    expect(parseHash(href.plan('adopt-key'))).toEqual({ name: 'plan', goal: 'adopt-key' });
    expect(parseHash(href.plan('retire-subkeys'))).toEqual({ name: 'plan', goal: 'retire-subkeys' });
  });
});

describe('the address of a route', () => {
  it('hrefOf is the inverse of parseHash for every route', () => {
    const routes: Route[] = [
      { name: 'start' },
      { name: 'findings' },
      { name: 'roots' },
      { name: 'key', root: 'B' },
      { name: 'cards' },
      { name: 'cards', serial: '00000001' },
      { name: 'history' },
      { name: 'history', id: '20261103T142000Z-init' },
      { name: 'trust' },
      { name: 'plan' },
      { name: 'plan', goal: 'adopt-key' },
      { name: 'notfound', hash: '#/nope' },
    ];
    for (const r of routes) expect(parseHash(hrefOf(r)), hrefOf(r)).toEqual(r);
  });
});

describe('the route to show when the example bundle changes', () => {
  // A bundle with one root, one card, one record and one goal; the names are made up.
  const has: BundleContents = { roots: ['A'], cards: ['00000001'], records: ['20261103T142000Z-init'], goals: ['renew-due'] };
  const none: BundleContents = { roots: [], cards: [], records: [], goals: [] };

  it('a screen that every bundle has stays, whatever the bundle holds', () => {
    for (const r of [{ name: 'start' }, { name: 'findings' }, { name: 'roots' }, { name: 'cards' }, { name: 'history' }, { name: 'trust' }, { name: 'plan' }] as Route[]) {
      expect(routeForBundle(r, has)).toBe(r);
      expect(routeForBundle(r, none)).toBe(r);
    }
  });
  it('a hash that names no screen stays not found', () => {
    const r: Route = { name: 'notfound', hash: '#/nope' };
    expect(routeForBundle(r, none)).toBe(r);
  });
  it('a root stays if the bundle has a root with that label, and goes to Roots if not', () => {
    const a: Route = { name: 'key', root: 'A' };
    expect(routeForBundle(a, has)).toBe(a);
    expect(routeForBundle({ name: 'key', root: 'B' }, has)).toEqual({ name: 'roots' });
    expect(routeForBundle(a, none)).toEqual({ name: 'roots' });
  });
  it('a card stays if the bundle has that serial, and goes to Cards if not', () => {
    const c: Route = { name: 'cards', serial: '00000001' };
    expect(routeForBundle(c, has)).toBe(c);
    expect(routeForBundle({ name: 'cards', serial: '00000002' }, has)).toEqual({ name: 'cards' });
    expect(routeForBundle(c, none)).toEqual({ name: 'cards' });
  });
  it('a ledger record stays if the bundle has that id, and goes to History if not', () => {
    const h: Route = { name: 'history', id: '20261103T142000Z-init' };
    expect(routeForBundle(h, has)).toBe(h);
    expect(routeForBundle({ name: 'history', id: '20260101T000000Z-due' }, has)).toEqual({ name: 'history' });
    expect(routeForBundle(h, none)).toEqual({ name: 'history' });
  });
  it('the wizard of a goal stays if the bundle offers the goal, and goes to the goals if not', () => {
    const p: Route = { name: 'plan', goal: 'renew-due' };
    expect(routeForBundle(p, has)).toBe(p);
    expect(routeForBundle({ name: 'plan', goal: 'adopt-key' }, has)).toEqual({ name: 'plan' });
    expect(routeForBundle({ name: 'plan', goal: 'no-such-goal' }, has)).toEqual({ name: 'plan' });
    expect(routeForBundle(p, none)).toEqual({ name: 'plan' });
  });
  it('a fallback is always a list, which is a route that a second switch keeps', () => {
    for (const r of [{ name: 'key', root: 'Z' }, { name: 'cards', serial: '9' }, { name: 'history', id: 'x' }, { name: 'plan', goal: 'x' }] as Route[]) {
      const once = routeForBundle(r, none);
      expect(routeForBundle(once, none)).toBe(once);
    }
  });
});
