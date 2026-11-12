import { describe, expect, it } from 'vitest';
import { ChangeKind, ChangeState, type Change } from './gen/ritueel/local/v1alpha1/inspect_service_pb';
import { ObjectKind } from './gen/ritueel/local/v1alpha1/common_pb';
import { href, hrefForChange, hrefForObject, hrefOf, objectSlug, parseHash, routeForBundle, routeTitle, type BundleContents, type ObjectSlug, type Route } from './lib/route';
import { BUNDLES, loadWorld } from './testkit';

describe('hash routes', () => {
  it('the empty address and the address of To do are To do, on the tab Not applied yet', () => {
    for (const hash of ['', '#', '#/', '#/todo', '#todo']) expect(parseHash(hash), JSON.stringify(hash)).toEqual({ name: 'todo', tab: 'changes' });
    expect(parseHash('#/todo/findings')).toEqual({ name: 'todo', tab: 'findings' });
  });
  it('every address of the four entries reads as its route', () => {
    expect(parseHash('#/inventory')).toEqual({ name: 'inventory', view: 'cards' });
    expect(parseHash('#/inventory/cards')).toEqual({ name: 'inventory', view: 'cards' });
    expect(parseHash('#/inventory/roots')).toEqual({ name: 'inventory', view: 'roots' });
    expect(parseHash('#/inventory/dates')).toEqual({ name: 'inventory', view: 'dates' });
    expect(parseHash('#/inventory/cards/card/root-a')).toEqual({ name: 'inventory', view: 'cards', object: { kind: 'card', id: 'root-a' } });
    expect(parseHash('#/inventory/roots/delegation/acme-release')).toEqual({ name: 'inventory', view: 'roots', object: { kind: 'delegation', id: 'acme-release' } });
    expect(parseHash('#/inventory/dates/certification/cert-8')).toEqual({ name: 'inventory', view: 'dates', object: { kind: 'certification', id: 'cert-8' } });
    expect(parseHash('#/history')).toEqual({ name: 'history', id: undefined });
    expect(parseHash('#/history/20261120T100000Z-apply-3fa9c1d2')).toEqual({ name: 'history', id: '20261120T100000Z-apply-3fa9c1d2' });
    expect(parseHash('#/trust')).toEqual({ name: 'trust' });
  });
  it('an unknown hash is not found and never another screen, and so are the addresses of the older page', () => {
    const none = ['#/start', '#/findings', '#/roots', '#/key/A', '#/cards', '#/cards/00000011', '#/plan', '#/plan/renew-due', '#/nothing-here', '#/todo/x', '#/todo/findings/x', '#/inventory/x', '#/inventory/cards/x/y', '#/inventory/cards/card', '#/inventory/cards/card/a/b', '#/history/a/b', '#/trust/x'];
    for (const hash of none) expect(parseHash(hash), hash).toEqual({ name: 'notfound', hash });
  });
  it('a malformed escape is not found and does not throw', () => {
    expect(parseHash('#/history/%E0%A4%A')).toMatchObject({ name: 'notfound' });
    expect(parseHash('#/inventory/cards/card/%')).toMatchObject({ name: 'notfound' });
  });
  it('hrefOf is the inverse of parseHash for every route, for every object of every bundle and scene', () => {
    const routes: Route[] = [{ name: 'todo', tab: 'changes' }, { name: 'todo', tab: 'findings' }, { name: 'history' }, { name: 'trust' }];
    for (const view of ['cards', 'roots', 'dates'] as const) routes.push({ name: 'inventory', view });
    for (const bundle of BUNDLES)
      for (const scene of bundle === 'acme' ? [1, 2, 3, 4, 5] : [1]) {
        const w = loadWorld(bundle, scene);
        const inv = w.inventory;
        const objects: [ObjectSlug, string][] = [
          ...inv.cards.map((o): [ObjectSlug, string] => ['card', o.name]),
          ...inv.roots.map((o): [ObjectSlug, string] => ['root', o.name]),
          ...inv.keys.map((o): [ObjectSlug, string] => ['key', o.fingerprint]),
          ...inv.userIds.map((o): [ObjectSlug, string] => ['userid', o.id]),
          ...inv.delegations.map((o): [ObjectSlug, string] => ['delegation', o.name]),
          ...inv.certifications.map((o): [ObjectSlug, string] => ['certification', o.id]),
          ...inv.requests.map((o): [ObjectSlug, string] => ['request', o.stem]),
        ];
        for (const [kind, id] of objects) for (const view of ['cards', 'roots', 'dates'] as const) routes.push({ name: 'inventory', view, object: { kind, id } });
        for (const c of w.ceremonies.ceremonies) routes.push({ name: 'history', id: c.id });
      }
    expect(routes.length).toBeGreaterThan(300);
    for (const r of routes) expect(parseHash(hrefOf(r)), hrefOf(r)).toEqual(r);
    // The link builders agree with hrefOf.
    expect(href.todo()).toBe('#/todo');
    expect(href.findings()).toBe('#/todo/findings');
    expect(href.inventory()).toBe('#/inventory/cards');
    expect(href.history('a b')).toBe('#/history/a%20b');
    expect(parseHash(href.history('a b'))).toEqual({ name: 'history', id: 'a b' });
    expect(href.trust()).toBe('#/trust');
  });
  it('the route for a bundle: a screen that every bundle has stays, a detail view stays only if the new bundle has it, and a fallback is always a list', () => {
    const has: BundleContents = { objects: ['card/root-a', 'certification/cert-8'], ceremonies: ['20261120T100000Z-apply-3fa9c1d2'] };
    const keep: Route[] = [{ name: 'todo', tab: 'changes' }, { name: 'trust' }, { name: 'history' }, { name: 'inventory', view: 'roots' }, { name: 'notfound', hash: '#/nope' }];
    for (const r of keep) expect(routeForBundle(r, has), JSON.stringify(r)).toBe(r);
    const card: Route = { name: 'inventory', view: 'cards', object: { kind: 'card', id: 'root-a' } };
    expect(routeForBundle(card, has)).toBe(card);
    expect(routeForBundle({ name: 'inventory', view: 'roots', object: { kind: 'root', id: 'acme-tls' } }, has)).toEqual({ name: 'inventory', view: 'roots' });
    expect(routeForBundle({ name: 'inventory', view: 'dates', object: { kind: 'certification', id: 'cert-9' } }, has)).toEqual({ name: 'inventory', view: 'dates' });
    const ceremony: Route = { name: 'history', id: '20261120T100000Z-apply-3fa9c1d2' };
    expect(routeForBundle(ceremony, has)).toBe(ceremony);
    expect(routeForBundle({ name: 'history', id: 'other' }, has)).toEqual({ name: 'history' });
    expect(routeForBundle({ name: 'inventory', view: 'cards', object: { kind: 'card', id: 'root-a' } }, { objects: [], ceremonies: [] })).toEqual({ name: 'inventory', view: 'cards' });
  });
  it('hrefForObject opens a card in By card, a certification in By date, a ceremony in History, and any other object in By root', () => {
    const ref = (kind: ObjectKind, id: string) => ({ kind, id });
    expect(hrefForObject(ref(ObjectKind.CARD, 'root-a'))).toBe('#/inventory/cards/card/root-a');
    expect(hrefForObject(ref(ObjectKind.CERTIFICATION, 'cert-8'))).toBe('#/inventory/dates/certification/cert-8');
    for (const [kind, slug] of [[ObjectKind.ROOT, 'root'], [ObjectKind.KEY, 'key'], [ObjectKind.USER_ID, 'userid'], [ObjectKind.DELEGATION, 'delegation'], [ObjectKind.REQUEST, 'request']] as const)
      expect(hrefForObject(ref(kind, 'x')), slug).toBe(`#/inventory/roots/${slug}/x`);
    expect(hrefForObject(ref(ObjectKind.CEREMONY, '20261120T100000Z-apply-3fa9c1d2'))).toBe('#/history/20261120T100000Z-apply-3fa9c1d2');
    expect(hrefForObject(ref(ObjectKind.TRUST_SET, '13-3fa9c1d2'))).toBe('#/trust');
    expect(hrefForObject(ref(ObjectKind.TRUST_FILE, 'root-list.json'))).toBe('#/trust');
    expect(hrefForObject(ref(ObjectKind.BUNDLE, 'acme'))).toBe('#/todo');
    expect(hrefForObject(ref(ObjectKind.UNSPECIFIED, 'x'))).toBe('#/todo');
  });
  it('hrefForChange opens the certification of a renewal, and the own object of any other change', () => {
    const change = (init: Partial<Pick<Change, 'kind' | 'object' | 'involves'>>) => ({ kind: ChangeKind.CERTIFY, state: ChangeState.READY, object: undefined, involves: [], ...init }) as Pick<Change, 'kind' | 'object' | 'involves'>;
    const renew = change({ kind: ChangeKind.RENEW, object: { kind: ObjectKind.DELEGATION, id: 'acme-release', label: '' } as never, involves: [{ kind: ObjectKind.CERTIFICATION, id: 'cert-8', label: '' } as never] });
    expect(hrefForChange(renew)).toBe('#/inventory/dates/certification/cert-8');
    const certify = change({ kind: ChangeKind.CERTIFY, object: { kind: ObjectKind.USER_ID, id: 'uid-A-2', label: '' } as never });
    expect(hrefForChange(certify)).toBe('#/inventory/roots/userid/uid-A-2');
    expect(hrefForChange(change({ kind: ChangeKind.RENEW, object: { kind: ObjectKind.DELEGATION, id: 'd', label: '' } as never }))).toBe('#/inventory/roots/delegation/d');
    expect(hrefForChange(change({}))).toBe('#/todo');
  });
  it('objectSlug maps every kind the panel shows to a slug that parseHash accepts, and the other kinds to nothing', () => {
    const shown = [ObjectKind.CARD, ObjectKind.ROOT, ObjectKind.KEY, ObjectKind.USER_ID, ObjectKind.DELEGATION, ObjectKind.CERTIFICATION, ObjectKind.REQUEST];
    for (const k of shown) {
      const slug = objectSlug(k);
      expect(slug, ObjectKind[k]).toBeDefined();
      expect(parseHash(`#/inventory/roots/${slug}/x`), ObjectKind[k]).toEqual({ name: 'inventory', view: 'roots', object: { kind: slug, id: 'x' } });
    }
    for (const k of [ObjectKind.BUNDLE, ObjectKind.CEREMONY, ObjectKind.TRUST_SET, ObjectKind.TRUST_FILE, ObjectKind.UNSPECIFIED]) expect(objectSlug(k), ObjectKind[k]).toBeUndefined();
  });
  it('every screen has a title, and a missing screen says so', () => {
    expect(routeTitle({ name: 'todo', tab: 'changes' })).toBe('To do');
    expect(routeTitle({ name: 'todo', tab: 'findings' })).toBe('Findings');
    expect(routeTitle({ name: 'inventory', view: 'roots' })).toBe('Inventory, by root');
    expect(routeTitle({ name: 'history' })).toBe('History');
    expect(routeTitle({ name: 'trust' })).toBe('Trust set');
    expect(routeTitle({ name: 'notfound', hash: '#/x' })).toBe('No such screen');
  });
});
