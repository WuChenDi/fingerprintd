import { defineConfig } from 'drizzle-kit'

// Schema -> D1 migrations (out: ./drizzle). The `./src/db/schema.ts` barrel
// aggregates both domains (fingerprint state + the check-in event log), so one
// generated migration set covers the whole single D1 database.
//
// `drizzle-kit generate` needs only dialect + schema + out and runs locally
// with no account — that is what produces the committed migration SQL the test
// pool (`readD1Migrations`) and `wrangler d1 migrations apply` consume. Applying
// to a REAL D1 uses `driver: 'd1-http'` + CLOUDFLARE_* credentials (or the
// `cf:localdb`/`cf:remotedb` wrangler scripts), deferred to a human with a CF
// account per the campaign ENV LIMIT.
export default defineConfig({
  dialect: 'sqlite',
  schema: './src/db/schema.ts',
  out: './drizzle',
})
