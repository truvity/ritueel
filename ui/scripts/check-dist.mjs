// Checks the two builds (npm run build, npm run build:real).
//  - no remote host except the ones listed (namespace URIs, the error pages
//    React and MUI name in a message, and the link back to the site),
//  - the demo build holds the fixtures (the three example bundles and the five
//    scenes of acme), the in-memory transport, the state switch ("Page state"),
//    the bundle switch ("Example bundle"), the scene control ("Scene"), the help
//    for a first visitor, and not the real transport,
//  - the real build holds none of the demo, and none of that help,
//  - neither build holds a word of the plan service that went.
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
  // The plan service and its words went with the plan screen (record 0010). No build carries them.
  for (const word of ['SavePlan', 'StartPlan', 'PlanService', 'ListIntentions', 'Make a plan', 'Save the plan']) {
    expect(!has(word), `holds no "${word}"`);
  }
  if (demo) {
    expect(has('Page state'), 'holds the state switch, named Page state');
    expect(has('Example bundle'), 'holds the bundle switch, named Example bundle');
    expect(has('Scene'), 'holds the scene control, named Scene');
    expect(!has('Try the states') && !has('Try a bundle'), 'holds neither of the old switch names');
    expect(has('Example Release Root A'), 'holds the fixtures');
    expect(has('acme-keyring') && has('globex'), 'holds the three example bundles');
    expect(has('Back to ritueel.id'), 'holds the way back to the site');
    // the help for a first visitor of the demo
    expect(has('helps you keep a root'), 'says on To do what ritueel is');
    expect(has('command line is not built yet'), 'says the command line is not built');
    expect(has('never answers, on purpose'), 'says the Waiting state is on purpose');
    expect(!has('createConnectTransport'), 'holds no connect-web transport');
  } else {
    expect(has('No such screen'), 'says No such screen for an address that names no screen');
    expect(has('createConnectTransport'), 'holds the real transport');
    expect(!has('Example Release Root') && !has('acme-keyring') && !has('globex'), 'holds no fixture and none of the example bundles');
    expect(!has('Page state') && !has('Example bundle') && !has('Scene 1 of 5'), 'holds no state switch, bundle switch or scene control');
    // the help for a first visitor of the demo is the demo's alone
    for (const phrase of ['helps you keep a root', 'command line is not built yet', 'never answers, on purpose']) {
      expect(!has(phrase), `holds no demo help: "${phrase}"`);
    }
    expect(!has('createRouterTransport'), 'holds no in-memory transport');
    expect(!has('20261124T'), 'holds no made-up ceremony');
  }
}
if (failed) process.exit(1);
