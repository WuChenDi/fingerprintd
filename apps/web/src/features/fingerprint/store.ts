import { create } from 'zustand'
import type { AssessResponse, FlowResult } from './api'
import { assessCheckin, runFlow } from './api'

type FlowStatus = 'idle' | 'running' | 'done' | 'error'

interface FingerprintState {
  baseUrl: string
  signingKey: string
  accountId: string
  status: FlowStatus
  error?: string
  result?: FlowResult
  checkinStatus: FlowStatus
  checkinError?: string
  checkin?: AssessResponse
  setBaseUrl: (value: string) => void
  setSigningKey: (value: string) => void
  setAccountId: (value: string) => void
  run: () => Promise<void>
  reset: () => void
}

export const useFingerprintStore = create<FingerprintState>((set, get) => ({
  baseUrl: 'https://fingerprintd-edge.cdlab.workers.dev',
  signingKey: '',
  accountId: 'user-123',
  status: 'idle',
  checkinStatus: 'idle',

  setBaseUrl: (value) => set({ baseUrl: value }),
  setSigningKey: (value) => set({ signingKey: value }),
  setAccountId: (value) => set({ accountId: value }),

  run: async () => {
    const { baseUrl, signingKey, accountId } = get()
    const trimmed = baseUrl.trim()
    if (trimmed === '') {
      set({ status: 'error', error: 'Enter a server base URL first.' })
      return
    }
    set({
      status: 'running',
      error: undefined,
      checkinStatus: 'idle',
      checkinError: undefined,
      checkin: undefined,
    })
    let result: FlowResult
    try {
      result = await runFlow(trimmed, signingKey)
      set({ status: 'done', result })
    } catch (err) {
      set({
        status: 'error',
        error: err instanceof Error ? err.message : String(err),
      })
      return
    }

    // Separate step: score the check-in against the same origin, reusing the
    // IdentifyResponse just obtained. A missing/failing endpoint is surfaced
    // inline and never fails the fingerprint flow above.
    set({ checkinStatus: 'running' })
    try {
      const checkin = await assessCheckin(
        trimmed,
        accountId.trim(),
        result.identity,
      )
      set({ checkinStatus: 'done', checkin })
    } catch (err) {
      set({
        checkinStatus: 'error',
        checkinError: err instanceof Error ? err.message : String(err),
      })
    }
  },

  reset: () =>
    set({
      status: 'idle',
      error: undefined,
      result: undefined,
      checkinStatus: 'idle',
      checkinError: undefined,
      checkin: undefined,
    }),
}))
