// Setup file for the Workers test pool: apply the D1 schema before any state
// test runs. The migrations are read at config time (`readD1Migrations`) and
// injected as `env.TEST_MIGRATIONS`; `applyD1Migrations` runs the pending ones
// against the isolated test database, so each test starts from the real schema.

import { applyD1Migrations, env } from 'cloudflare:test'

await applyD1Migrations(env.DB, env.TEST_MIGRATIONS)
await applyD1Migrations(env.CHECKIN_DB, env.TEST_CHECKIN_MIGRATIONS)
