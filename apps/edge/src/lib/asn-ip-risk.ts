/**
 * ASN-based IP-risk band classifier for the edge Worker. Mirrors fp-core's
 * auto-degrade philosophy: the ASN is authoritative, and a coarse
 * `asOrganization` substring check is a conservative net that only fires when
 * the ASN is not decisive.
 *
 * The curated ASN set and org keywords below are **illustrative**, not
 * authoritative — exactly like fp-core's `StaticIpIntel` 4-CIDR table. A real
 * deployment swaps this for an IP-reputation feed (GeoLite2 / Spur-style ASN &
 * proxy reputation). No real-data detection here. (future TODO — real feed.)
 */

/**
 * Curated set of well-known hosting / datacenter / VPN ASNs. Illustrative, not
 * authoritative — extend from a real feed in production. Each entry is cited:
 *
 * - 16509, 14618 — Amazon AWS
 * - 15169, 396982 — Google (GCP)
 * - 8075 — Microsoft (Azure)
 * - 14061 — DigitalOcean
 * - 16276 — OVH
 * - 24940 — Hetzner
 * - 63949 — Akamai/Linode
 * - 20473 — The Constant Company (Vultr/Choopa)
 * - 13335 — Cloudflare
 */
const HOSTING_ASNS: ReadonlySet<number> = new Set([
  16509, 14618, 15169, 396982, 8075, 14061, 16276, 24940, 63949, 20473, 13335,
])

/**
 * Case-insensitive substring keywords for the coarse `asOrganization` fallback.
 * Conservative on purpose: only fires when the ASN is missing/unknown, so it
 * never overrides an authoritative ASN decision. Illustrative, not exhaustive.
 */
const HOSTING_ORG_KEYWORDS: readonly string[] = [
  'amazon',
  'google',
  'microsoft',
  'digitalocean',
  'ovh',
  'hetzner',
  'linode',
  'vultr',
  'cloud',
  'hosting',
  'datacenter',
  'data center',
]

/**
 * Classify an IP's network into a coarse risk band from its Cloudflare ASN and
 * AS organization.
 *
 * - `asn` is the primary, authoritative key: a curated hosting/datacenter/VPN
 *   ASN → `'high'`.
 * - `asOrganization` is a coarse fallback used **only** when `asn` is not
 *   decisive (unknown or absent) — a case-insensitive substring match against
 *   {@link HOSTING_ORG_KEYWORDS}.
 * - Absent `asn` and no org match → `'low'` (no adverse evidence).
 */
export function asnIpRisk(
  asn?: number,
  asOrganization?: string,
): 'low' | 'high' {
  if (asn !== undefined && HOSTING_ASNS.has(asn)) {
    return 'high'
  }

  if (asOrganization !== undefined) {
    const org = asOrganization.toLowerCase()
    if (HOSTING_ORG_KEYWORDS.some((keyword) => org.includes(keyword))) {
      return 'high'
    }
  }

  return 'low'
}
