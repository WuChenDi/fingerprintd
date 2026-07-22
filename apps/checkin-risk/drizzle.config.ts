import { defineConfig } from 'drizzle-kit'

// Schema -> D1 migrations (out: ./src/database, drizzle-kit house layout),
// mirroring apps/edge. `drizzle-kit generate` needs only dialect + schema + out
// and runs locally with no account — it produces the committed migration SQL the
// test pool (`readD1Migrations`) and `wrangler d1 migrations apply` consume.
// Applying to a REAL D1 is deferred to a human with a CF account (the campaign
// ENV LIMIT); never hand-author the emitted SQL.
export default defineConfig({
  dialect: 'sqlite',
  schema: './src/db/schema.ts',
  out: './src/database',
})
