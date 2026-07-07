-- fingerprintd edge state schema (D1) — the externalized half of the native
-- in-process store (docs/design-fuzzy-matching.md §3/§4/§9/§11).
--
-- A Worker isolate is ephemeral, so the fingerprint library, the blocking
-- inverted index, and the frequency material that `fp_core::fuzzy` keeps in
-- memory must live in D1 to survive and coordinate across isolates. The
-- one-time nonce is the exception — it needs atomic check-and-burn, which D1's
-- eventual replication cannot give, so it lives in a Durable Object instead.
--
-- Value privacy: only salted digests reach the client-facing compute. The
-- `templates.components` blob keeps the RAW component object because the WASM
-- engine re-salts it deterministically on every recall (the salt secret is a
-- Worker Secret, not stored here); `value_frequency` keys on salted hashes.

-- The fingerprint library: `visitorId -> template` (design §3/§11), mirroring
-- `fp_core::fuzzy::record::FingerprintRecord`. `components` is the raw JSON
-- component object the host recalls and hands to the WASM scorer, which re-salts
-- it. Drift (design §7) upserts this row on a confirmed match; a review-band hit
-- never touches it (anti-poisoning).
CREATE TABLE IF NOT EXISTS templates (
  visitor_id        TEXT    PRIMARY KEY,
  components        TEXT    NOT NULL,           -- raw component object, JSON
  first_seen        INTEGER NOT NULL,           -- Unix ms
  last_seen         INTEGER NOT NULL,           -- Unix ms
  observation_count INTEGER NOT NULL
);

-- The `key -> set<visitorId>` blocking inverted index (design §4), the D1 form
-- of `fp_core::fuzzy::blocking::BlockingIndex`. Stage-one recall unions the
-- visitors sharing any of a probe's blocking keys. `key` is the hex blocking
-- key the WASM engine derives; the composite primary key makes re-indexing an
-- already-known (key, visitor) pair idempotent.
CREATE TABLE IF NOT EXISTS blocking_index (
  key        TEXT NOT NULL,                     -- hex blocking key
  visitor_id TEXT NOT NULL,
  PRIMARY KEY (key, visitor_id)
);

-- Recall queries `WHERE key IN (...)`; index the key column for it.
CREATE INDEX IF NOT EXISTS idx_blocking_index_key ON blocking_index (key);

-- Per-value frequency material for the `u_i` rarity estimate (design §9),
-- keyed by salted value hash so no plaintext component value is stored. The
-- native scorer reads this global table; the WASM `score` currently approximates
-- `u_i` over the recalled candidate block instead. Feeding this global snapshot
-- into the scorer (and populating it on observe via a WASM-exposed hasher) is
-- the PCF5 parity refinement — the table is provisioned here so that wiring is a
-- pure addition, not a migration.
CREATE TABLE IF NOT EXISTS value_frequency (
  value_hash TEXT    PRIMARY KEY,               -- hex salted value digest
  count      INTEGER NOT NULL
);
