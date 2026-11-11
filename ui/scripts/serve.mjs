// Serves dist/ under /demo/ on a loopback port, the way the site will.
// usage: node scripts/serve.mjs [port] [--headers FILE]
//   port        0 or none = a free port; the URL is printed
//   --headers   a Cloudflare-style _headers file (site/public/_headers): the headers of its
//               /* rule are sent with every response, so the page is tried under the
//               site's own Content-Security-Policy
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
const hi = args.indexOf('--headers');
const headersFile = hi >= 0 ? args.splice(hi, 2)[1] : undefined;

// The /* rule of a _headers file: unindented path line, then indented "Name: value" lines.
function siteHeaders(file) {
  const out = {};
  let inRule = false;
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    if (!/^\s/.test(line)) inRule = line.trim() === '/*';
    else if (inRule) {
      const i = line.indexOf(':');
      out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
  }
  if (!out['Content-Security-Policy']) throw new Error(`${file} has no Content-Security-Policy for /*`);
  return out;
}
const extra = headersFile ? siteHeaders(headersFile) : {};

const root = fileURLToPath(new URL('../dist/', import.meta.url));
const prefix = '/demo/';
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.woff2': 'font/woff2' };

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://localhost');
  if (!url.pathname.startsWith(prefix)) {
    res.writeHead(302, { location: prefix }).end();
    return;
  }
  let rel = decodeURIComponent(url.pathname.slice(prefix.length)) || 'index.html';
  const file = normalize(join(root, rel));
  if (!file.startsWith(root.endsWith(sep) ? root : root + sep)) {
    res.writeHead(403).end();
    return;
  }
  try {
    const s = await stat(file);
    const path = s.isDirectory() ? join(file, 'index.html') : file;
    const body = await readFile(path);
    res.writeHead(200, { ...extra, 'content-type': types[extname(path)] ?? 'application/octet-stream', 'cache-control': 'no-store' }).end(body);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
  }
});

server.listen(Number(args[0] ?? 0), '127.0.0.1', () => {
  const { port } = server.address();
  console.log(`http://127.0.0.1:${port}${prefix}`);
});
