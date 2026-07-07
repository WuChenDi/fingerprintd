/**
 * The D1-backed fingerprint library (PCF4): stage-one candidate recall plus
 * drift persistence, the externalized form of `fp_core::fuzzy`'s in-memory
 * `RecordStore` + `BlockingIndex`.
 *
 * Two tables (see `migrations/0001_init.sql`): `templates` holds each visitor's
 * RAW component object (the WASM engine re-salts it on recall, so no salted
 * state is stored here), and `blocking_index` is the `key -> visitorId` inverted
 * index recall unions over. Persistence mirrors the native `identify` verdict
 * handling (design §7): a match drifts the template, a new device stores a fresh
 * one, a review writes nothing.
 */

import type { Candidate, CandidateSource } from './state'
import type { ScoreOutcome } from './types'

/** A `templates` row as recalled for scoring. */
interface TemplateRow {
  visitor_id: string
  /** Raw component object, JSON-encoded. */
  components: string
}

/** Just the stored component blob, for a drift read-merge. */
interface ComponentsRow {
  components: string
}

/**
 * Recall + persist over D1. Construct once per isolate from the `DB` binding.
 * Holds no state itself — every method is a query against the shared database.
 */
export class D1FingerprintStore implements CandidateSource {
  constructor(private readonly db: D1Database) {}

  /**
   * Union of every stored template sharing any of `blockingKeys` (design §4).
   * Empty keys ⇒ nothing to recall. `DISTINCT` collapses a visitor matched by
   * several keys to one candidate; the JOIN drops any index row whose template
   * was not (yet) written.
   */
  async recall(blockingKeys: string[]): Promise<Candidate[]> {
    if (blockingKeys.length === 0) return []
    const placeholders = blockingKeys.map(() => '?').join(', ')
    const sql =
      'SELECT DISTINCT t.visitor_id AS visitor_id, t.components AS components ' +
      'FROM templates t ' +
      'JOIN blocking_index b ON b.visitor_id = t.visitor_id ' +
      `WHERE b.key IN (${placeholders})`
    const { results } = await this.db
      .prepare(sql)
      .bind(...blockingKeys)
      .all<TemplateRow>()
    return results.map((row) => ({
      visitor_id: row.visitor_id,
      components: JSON.parse(row.components) as Record<string, unknown>,
    }))
  }

  /**
   * Fold the observation in per the verdict (design §7). A review is a no-op
   * (anti-poisoning); a match drifts the matched template toward `components`
   * by a per-component merge (present values overwrite, absent ones are
   * retained — mirroring `RecordStore::observe`); a new device is stored whole.
   * Either write also indexes `blockingKeys` under the resolved id.
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
      .prepare('SELECT components FROM templates WHERE visitor_id = ?')
      .bind(visitorId)
      .first<ComponentsRow>()
    if (row === null) return undefined
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
      .prepare(
        'INSERT INTO templates (visitor_id, components, first_seen, last_seen, observation_count) ' +
          'VALUES (?, ?, ?, ?, 1) ' +
          'ON CONFLICT(visitor_id) DO UPDATE SET ' +
          'components = excluded.components, ' +
          'last_seen = excluded.last_seen, ' +
          'observation_count = templates.observation_count + 1',
      )
      .bind(visitorId, JSON.stringify(components), nowMs, nowMs)
    const index = blockingKeys.map((key) =>
      this.db
        .prepare(
          'INSERT OR IGNORE INTO blocking_index (key, visitor_id) VALUES (?, ?)',
        )
        .bind(key, visitorId),
    )
    await this.db.batch([upsert, ...index])
  }
}
