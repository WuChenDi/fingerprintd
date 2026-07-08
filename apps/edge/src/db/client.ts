import type { DrizzleD1Database } from 'drizzle-orm/d1'
import { drizzle } from 'drizzle-orm/d1'
import * as schema from './schema'

/** A Drizzle client bound to the edge D1 fingerprint database + its schema. */
export type Db = DrizzleD1Database<typeof schema>

/** Wrap the `DB` D1 binding in a schema-aware Drizzle client. Construct once per
 *  isolate from `env.DB`; it holds no state, so every query hits the shared D1. */
export function getDb(d1: D1Database): Db {
  return drizzle(d1, { schema })
}
