// The routes of the Worker, all under /api/ and all read-only:
//
//   GET /api/status        the live status as JSON (src/worker/status.ts)
//   GET /api/status/live/  the status page's live parts, an HTML fragment drawn by the renderer
//                          the build uses for the snapshot (src/lib-status-html.ts)
//
// The Worker runs first for /api/* only (wrangler.jsonc); every other path is a static asset.
// There is no webhook and no way to write: the cron (src/worker/index.ts) is the only writer.
import { liveHtml, liveStatus, statusJson, type Env } from './status.ts';

// Response headers of every API answer. The _headers file applies to static assets only.
const BASE = {
  'x-content-type-options': 'nosniff',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
  'referrer-policy': 'strict-origin-when-cross-origin',
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
};
// The data changes at most every 15 minutes; a minute in a browser or proxy is enough.
export const STATUS_CACHE = 'public, max-age=60';

export const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body, null, 1) + '\n', {
    status,
    headers: { ...BASE, 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra },
  });

const notReady = 'no live status yet; the build-time snapshot is on https://ritueel.id/status/';

async function status(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'GET' && request.method !== 'HEAD') return json({ error: 'method not allowed' }, 405, { allow: 'GET, HEAD' });
  const live = await liveStatus(env, request.url);
  if (!live) return json({ error: notReady }, 503, { 'retry-after': '300' });
  return json(statusJson(live), 200, { 'cache-control': STATUS_CACHE, 'access-control-allow-origin': '*' });
}

// The fragment is fetched by the page's own script and inserted, never navigated to; if it
// is, it is a bare HTML document under a policy that allows nothing but this origin's styles.
async function liveBlock(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'GET' && request.method !== 'HEAD') return json({ error: 'method not allowed' }, 405, { allow: 'GET, HEAD' });
  const live = await liveStatus(env, request.url);
  const headers = {
    ...BASE,
    'content-security-policy': "default-src 'none'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    'x-robots-tag': 'noindex',
  };
  if (!live) {
    return new Response('The live status is not available yet; the page keeps its build-time snapshot.\n', {
      status: 503,
      headers: { ...headers, 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'retry-after': '300' },
    });
  }
  return new Response(liveHtml(live), { headers: { ...headers, 'content-type': 'text/html; charset=utf-8', 'cache-control': STATUS_CACHE } });
}

// Every request that reaches the Worker. A trailing slash is optional on each route.
export async function api(request: Request, env: Env): Promise<Response> {
  const path = new URL(request.url).pathname.replace(/\/+$/, '');
  try {
    if (path === '/api/status') return await status(request, env);
    if (path === '/api/status/live') return await liveBlock(request, env);
  } catch (e) {
    console.log(`${path}: failed: ${e instanceof Error ? e.message : e}`);
    return json({ error: 'internal error' }, 500);
  }
  return json({ error: 'not found', routes: ['/api/status', '/api/status/live/'] }, 404);
}
