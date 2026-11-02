// The Worker of ritueel.id. Static assets are served before any of this runs; the Worker runs
// first for /api/* only, and is a plain module that Wrangler bundles, with no Astro server in it
// (site/wrangler.jsonc names it as `main`).
//
// - fetch: the routes of src/worker/api.ts.
// - scheduled: every 15 minutes, a refresh of the status document in KV. This is the only
//   writer: the status is as live as the cron is frequent.
import { api } from './api.ts';
import { refresh, type Env } from './status.ts';

interface Ctx { waitUntil(p: Promise<unknown>): void }

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return api(request, env);
  },
  async scheduled(_controller: unknown, env: Env, ctx: Ctx): Promise<void> {
    ctx.waitUntil(refresh(env, 'cron').then((line) => console.log(line)));
  },
};
