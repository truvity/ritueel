import { createClient, type Transport } from '@connectrpc/connect';
import { InspectService } from '../gen/ritueel/local/v1alpha1/inspect_service_pb';
import { PlanService } from '../gen/ritueel/local/v1alpha1/plan_service_pb';

/** True in the build that is the demo on the site. */
export const isDemo = __RITUEEL_MODE__ === 'demo';

/**
 * The transport is loaded on first use. __RITUEEL_MODE__ is a build-time
 * constant, so the other branch (and everything only it imports) is not in
 * the bundle: the demo build carries no connect-web, the real build carries
 * no fixtures and no in-memory transport.
 *
 * Demo: an in-memory ConnectRPC transport that answers from fixture files.
 * Real: the page is embedded in the binary and talks to the ritueel process.
 * That process is one long-running background process, started on demand and
 * bound to a Unix socket, which the command line uses. A browser cannot open a
 * Unix socket, so while the page is in use the same process also answers on
 * the loopback address, with the same calls and answers. The page is served
 * from that address, so baseUrl '/' below is that origin.
 */
async function loadTransport(): Promise<Transport> {
  if (__RITUEEL_MODE__ === 'demo') {
    const { createDemoTransport } = await import('./demo');
    return createDemoTransport();
  }
  const { createConnectTransport } = await import('@connectrpc/connect-web');
  return createConnectTransport({ baseUrl: '/' });
}

function lazyTransport(load: () => Promise<Transport>): Transport {
  let loaded: Promise<Transport> | undefined;
  const get = () => (loaded ??= load());
  const unary: Transport['unary'] = async (method, signal, timeoutMs, header, input, contextValues) =>
    (await get()).unary(method, signal, timeoutMs, header, input, contextValues);
  const stream: Transport['stream'] = async (method, signal, timeoutMs, header, input, contextValues) =>
    (await get()).stream(method, signal, timeoutMs, header, input, contextValues);
  return { unary, stream };
}

const transport = lazyTransport(loadTransport);

export const inspect = createClient(InspectService, transport);
export const plans = createClient(PlanService, transport);
