/**
 * Route aggregation layer — the single place that composes the edge's HTTP
 * surface. It registers the bare `GET /health` and mounts the domain
 * sub-routers (fingerprint: `GET /challenge`, `POST /identify`,
 * `DELETE /visitor/:id`; check-in: `POST /checkin/assess`) over the injected
 * {@link Deps}. `app.ts` mounts this aggregate; the handler bodies themselves
 * live in each module's `*.routes.ts`.
 */

import { Hono } from 'hono'
import type { Deps } from '../app'
import { checkinRoutes } from '../modules/checkin'
import { fingerprintRoutes } from '../modules/fingerprint'

/** Build the aggregate router over the injected {@link Deps}. */
export function routes(deps: Deps): Hono {
  const app = new Hono()

  app.get('/health', (c) => c.body(null, 200))

  // Mount the domain sub-routers. Each takes the structurally-compatible slice
  // of `deps` it needs; the fingerprint and check-in domains share no imports.
  app.route('/', fingerprintRoutes(deps))
  app.route('/', checkinRoutes(deps))

  return app
}
