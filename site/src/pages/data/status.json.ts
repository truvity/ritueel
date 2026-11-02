// /data/status.json: the milestones of the roadmap as the build read them, and when. The
// Worker reads this file from its own static assets to join the live issues to the roadmap
// (src/worker/status.ts), so the live block and the snapshot place the issues the same way.
import type { APIRoute } from 'astro';
import { BUILT_AT, roadmapMilestones } from '../../lib-status';

export const GET: APIRoute = () =>
  new Response(JSON.stringify({ schema: 1, builtAt: BUILT_AT, roadmap: roadmapMilestones() }, null, 1) + '\n', {
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
