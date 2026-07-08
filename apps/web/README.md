# @cdlab/fingerprintd-web

Browser **playground / debug console** for the
[`fingerprintd`](../../crates/fingerprintd) challenge/identify flow. It drives
the collect-only [`@cdlab/fingerprintd-client`](../../packages/client) SDK against a
server you point it at and visualizes both what the client **sends** and what
the server **judges** — the client never derives an id, the server is
authoritative.

## What it shows

Enter a server base URL → **Run flow** runs `getChallenge → collect → identify`:

- **Identity** — the server verdict: `visitorId`, `confidence`, `decision`
  (`match` / `review` / `new_device`), `is_new_device`, `collision_risk`, and
  the passive `signals` (`ua_tls_consistent`, `ip_risk`).
- **Collected evidence** — the three lanes straight out of the SDK's `Collected`,
  each in its own section:
  - `stable_components` — the "who is this device" matching input.
  - `probe` — `hex(HMAC-SHA256(key, nonce))` computed in WASM, the nonce freshness
    proof (never a matching signal; sent only when the challenge advertises
    `collect.challenge.verify`).
  - `ts` — the client clock at collection.
- **Response signature** — whether the server signed the response; supply a
  UTF-8 signing key to verify the `x-fp-signature` tag client-side.

## Tech Stack

React 19 · TypeScript · Vite · Tailwind CSS v4 · shadcn/ui (base-nova) +
`@base-ui/react` · Zustand · i18next · Biome

## Development

```bash
bun install
# The playground consumes the built SDK — build it once first (its dist/ is
# gitignored), or run the workspace build from the repo root.
bun run --filter @cdlab/fingerprintd-client build

bun run dev        # dev server (nsl → http://fingerprintd-web.localhost:<port>)
bun run typecheck  # tsc --noEmit
bun run build      # production build to dist/
bun run preview    # serve the production build
```

To skip the nsl proxy: `bun x vite`.

## Deploy

Ships as a **static-assets Cloudflare Worker** (`wrangler.jsonc`, no server
code) to the same account as the edge Worker — `fingerprintd-web.<account>.workers.dev`.

```bash
bun run --filter @cdlab/fingerprintd-client build   # SDK dist (gitignored)
bun run build                                 # SPA -> ./dist
bun run deploy:dry                            # validate config, upload nothing
bun run deploy                                # wrangler deploy
```

CI: `.github/workflows/deploy-web.yml` (manual `workflow_dispatch`) does the
same — install → build SDK → build web → `wrangler deploy`. It reuses the
`CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID` secrets shared with
`deploy-edge.yml`.

## Notes

- **Cross-origin.** The playground fetches `/challenge` and `/identify` on the
  server origin you enter, so that server must allow this app's origin via CORS.
  The edge Worker does this via `FP_CORS_ORIGINS` (see
  [`apps/edge/README.md`](../edge/README.md)); it also exposes the response
  signature headers so the client can verify them. Point at another server and it
  must set its own CORS.
- **Probe key parity.** The vendored WASM ships a **dev** probe key
  (`test-probe-secret`). Against a deployment configured with a different
  `FP_PROBE_KEY`, the probe will not match and a probe-enforcing server returns
  `401` — rebuild the SDK's WASM with the server's key for real parity (see
  [`packages/client/README.md`](../../packages/client/README.md)).
- **Real-browser only.** Canvas/audio/WebGL collection needs a real browser;
  there is no headless in-repo e2e for this app.
