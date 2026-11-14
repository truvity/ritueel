import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

// The site and the demo of the local page show one icon in the browser tab. The demo is built from
// ui/, which has its own public/ directory, so the file is kept there as a copy of the site's.
const site = new URL('../public/favicon.svg', import.meta.url);
const demo = new URL('../../ui/public/favicon.svg', import.meta.url);

test('the demo uses the icon of the site', () => {
  assert.ok(
    readFileSync(site).equals(readFileSync(demo)),
    'ui/public/favicon.svg differs from site/public/favicon.svg: copy the site file over it',
  );
});
