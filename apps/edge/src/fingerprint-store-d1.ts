/**
 * The D1-backed fingerprint library (PCF4): stage-one candidate recall plus
 * drift persistence, the externalized form of `fp_core::fuzzy`'s in-memory
 * `RecordStore` + `BlockingIndex`.
 *
 * Two tables (see `src/db/schema.ts`): `templates` holds each visitor's RAW
 * component object (the WASM engine re-salts it on recall, so no salted state is
 * stored here), and `blocking_index` is the `key -> visitorId` inverted index
 * recall unions over. Persistence mirrors the native `identify` verdict handling
 * (design §7): a match drifts the template, a new device stores a fresh one, a
 * review writes nothing.
 *
 * Queries go through Drizzle (`drizzle-orm/d1`); the emitted SQL is equivalent
 * to the hand-written statements it replaced, so the cross-stack parity holds.
 */

import { eq, inArray, sql } from 'drizzle-orm'
import type { Db } from './db/client'
import { getDb } from './db/client'
import { blockingIndex, templates } from './db/schema'
import type { Candidate, CandidateSource } from './state'
import type { ScoreOutcome } from './types'

/**
 * Recall + persist over D1 via Drizzle. Construct once per isolate from the `DB`
 * binding. Holds no state itself — every method is a query against the shared
 * database.
 */
export class D1FingerprintStore implements CandidateSource {
  private readonly db: Db

  constructor(d1: D1Database) {
    this.db = getDb(d1)
  }

  /**
   * Union of every stored template sharing any of `blockingKeys` (design §4).
   * Empty keys ⇒ nothing to recall. `selectDistinct` collapses a visitor matched
   * by several keys to one candidate; the inner join drops any index row whose
   * template was not (yet) written.
   */
  async recall(blockingKeys: string[]): Promise<Candidate[]> {
    if (blockingKeys.length === 0) return []
    const rows = await this.db
      .selectDistinct({
        visitorId: templates.visitorId,
        components: templates.components,
      })
      .from(templates)
      .innerJoin(
        blockingIndex,
        eq(blockingIndex.visitorId, templates.visitorId),
      )
      .where(inArray(blockingIndex.key, blockingKeys))
    return rows.map((row) => ({
      visitor_id: row.visitorId,
      components: JSON.parse(row.components) as Record<string, unknown>,
    }))
  }

  /**
   * Fold the observation in per the verdict (design §7). A review is a no-op
   * (anti-poisoning); a match drifts the matched template toward `components` by
   * a per-component merge (present values overwrite, absent ones are retained —
   * mirroring `RecordStore::observe`); a new device is stored whole. Either
   * write also indexes `blockingKeys` under the resolved id.
   */
  async persist(
    outcome: ScoreOutcome,
    components: Record<string, unknown>,
    blockingKeys: string[],
    nowMs: number,
  ): Promise<void> {
    if (outcome.decision === 'review') return

    let toStore = components
    if (outcome.decision === 'match') {
      const existing = await this.storedComponents(outcome.visitor_id)
      // Per-component merge: the new observation overwrites present values and
      // leaves absent ones intact, so a browser upgrade drifts the template
      // without erasing components this probe happened not to report.
      if (existing) toStore = { ...existing, ...components }
    }
    await this.write(outcome.visitor_id, toStore, blockingKeys, nowMs)
  }

  /** The stored raw components for `visitorId`, or `undefined` if unknown. */
  private async storedComponents(
    visitorId: string,
  ): Promise<Record<string, unknown> | undefined> {
    const row = await this.db
      .select({ components: templates.components })
      .from(templates)
      .where(eq(templates.visitorId, visitorId))
      .get()
    if (row === undefined) return undefined
    return JSON.parse(row.components) as Record<string, unknown>
  }

  /**
   * Upsert the template and index its blocking keys in one atomic batch. The
   * upsert stamps `last_seen`/`observation_count` on an existing row and seeds
   * `first_seen` on a new one; indexing is idempotent via the composite key.
   */
  private async write(
    visitorId: string,
    components: Record<string, unknown>,
    blockingKeys: string[],
    nowMs: number,
  ): Promise<void> {
    const upsert = this.db
      .insert(templates)
      .values({
        visitorId,
        components: JSON.stringify(components),
        firstSeen: nowMs,
        lastSeen: nowMs,
        observationCount: 1,
      })
      .onConflictDoUpdate({
        target: templates.visitorId,
        set: {
          components: sql`excluded.components`,
          lastSeen: sql`excluded.last_seen`,
          observationCount: sql`${templates.observationCount} + 1`,
        },
      })
    const index = blockingKeys.map((key) =>
      this.db
        .insert(blockingIndex)
        .values({ key, visitorId })
        .onConflictDoNothing(),
    )
    await this.db.batch([upsert, ...index])
  }
}
