import { defineConfig } from 'drizzle-kit'

// Schema -> D1 migrations (out: ./src/database, drizzle-kit house layout).
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
  out: './src/database',
})
