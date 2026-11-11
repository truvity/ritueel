import { describe, expect, it } from 'vitest';
import { href, parseHash } from './lib/route';

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
