import { describe, expect, it } from 'vitest'
import { asnIpRisk } from '../src/asn-ip-risk'

describe('asnIpRisk', () => {
  it('flags a known hosting ASN as high', () => {
    expect(asnIpRisk(16509)).toBe('high') // AWS
  })

  it('treats a residential ASN as low', () => {
    expect(asnIpRisk(3320)).toBe('low') // Deutsche Telekom
    expect(asnIpRisk(7922)).toBe('low') // Comcast
  })

  it('returns low when both asn and org are absent', () => {
    expect(asnIpRisk(undefined, undefined)).toBe('low')
    expect(asnIpRisk()).toBe('low')
  })

  it('falls back to a case-insensitive org substring match', () => {
    expect(asnIpRisk(undefined, 'Amazon.com, Inc.')).toBe('high')
    expect(asnIpRisk(undefined, 'HETZNER ONLINE GMBH')).toBe('high')
  })

  it('does not flag a residential org via the fallback', () => {
    expect(asnIpRisk(undefined, 'Deutsche Telekom AG')).toBe('low')
  })

  it('lets the authoritative ASN win over a residential-looking org', () => {
    expect(asnIpRisk(16509, 'Comcast Cable')).toBe('high')
  })
})
