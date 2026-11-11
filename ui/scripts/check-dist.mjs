// Checks the two built bundles (npm run build, npm run build:real).
//  - no remote host except the ones listed (namespace URIs, the error pages
//    React and MUI name in a message, and the link back to the site),
//  - the demo build holds the fixtures (the three example bundles), the in-memory
//    transport, the state switch and the bundle switch, and not the real transport,
//  - the real build holds none of the demo.
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const ALLOWED = new Set(['www.w3.org', 'mui.com', 'react.dev', 'ritueel.id', 'in-memory']);

function read(dir) {
  const files = [];
  const walk = (d) => {
    for (const n of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, n.name);
      if (n.isDirectory()) walk(p);
      else if (/\.(js|css|html|json|svg)$/.test(n.name)) files.push([p, readFileSync(p, 'utf8')]);
    }
  };
  walk(dir);
  return files;
}

let failed = 0;
const fail = (m) => {
  failed += 1;
  console.error('FAIL', m);
};
const ok = (m) => console.log('ok  ', m);

for (const [name, dir, demo] of [['demo build (dist)', join(root, 'dist'), true], ['real build (dist-real)', join(root, 'dist-real'), false]]) {
  if (!existsSync(dir)) {
    fail(`${name}: ${dir} is missing, build it first`);
    continue;
  }
  const files = read(dir);
  // a comment in a style file (the licence line of Tailwind names its site) is not a request
  const all = files.map(([p, t]) => (p.endsWith('.css') ? t.replace(/\/\*[\s\S]*?\*\//g, '') : t)).join('\n');
  // "https://host" only: a protocol-relative match inside a regex or a comment is not a host
  const real = new Set([...all.matchAll(/https?:\/\/([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)/g)].map((m) => m[1]));
  const strange = [...real].filter((h) => !ALLOWED.has(h));
  strange.length ? fail(`${name}: remote hosts named: ${strange.join(', ')}`) : ok(`${name}: names no remote host but ${[...real].sort().join(', ')}`);
  const has = (s) => all.includes(s);
  const expect = (cond, msg) => (cond ? ok(`${name}: ${msg}`) : fail(`${name}: ${msg}`));
  expect(files.some(([p, t]) => p.endsWith('index.html') && t.includes("connect-src 'self'")), "index.html carries connect-src 'self'");
  if (demo) {
    expect(has('Example Holder'), 'holds the fixtures');
    expect(has('Try the states'), 'holds the state switch');
    expect(has('Try a bundle'), 'holds the bundle switch');
    expect(has('globex') && has('personal-keyring') && has('acme-gateway'), 'holds the three example bundles');
    expect(has('ledger/20261111T090000Z-due/plan.json'), 'holds a plan saved as ledger/<ceremony>/plan.json');
    expect(!has('createConnectTransport'), 'holds no connect-web transport');
  } else {
    expect(!has('Example Holder') && !has('deadbeef') && !has('0123456789ABCDEF'), 'holds no fixture');
    expect(!has('Try the states'), 'holds no state switch');
    expect(!has('Try a bundle'), 'holds no bundle switch');
    expect(!has('globex') && !has('personal-keyring') && !has('acme-gateway'), 'holds none of the example bundles');
    expect(!has('20261111T090000Z'), 'holds no made-up ceremony');
    expect(!has('createRouterTransport'), 'holds no in-memory transport');
    expect(has('createConnectTransport'), 'holds the real transport');
  }
}
if (failed) process.exit(1);
