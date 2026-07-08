import { Fingerprint } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { EvidenceLanes } from './components/EvidenceLanes'
import { IdentityCard } from './components/IdentityCard'
import { RunPanel } from './components/RunPanel'
import { SignatureCard } from './components/SignatureCard'
import { useFingerprintStore } from './store'

export function FingerprintPlayground() {
  const { t } = useTranslation()
  const status = useFingerprintStore((s) => s.status)
  const error = useFingerprintStore((s) => s.error)
  const result = useFingerprintStore((s) => s.result)

  return (
    <div className="mx-auto grid max-w-5xl gap-6 px-4 py-8 md:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
      <div className="space-y-6">
        <RunPanel />
        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
            <span className="font-semibold">{t('Flow failed')}: </span>
            {error}
          </div>
        )}
        {result && <IdentityCard identity={result.identity} />}
        {result && <SignatureCard signature={result.signature} />}
      </div>

      <div className="space-y-6">
        {result ? (
          <EvidenceLanes
            challenge={result.challenge}
            collected={result.collected}
          />
        ) : (
          status !== 'running' && (
            <div className="flex h-full min-h-64 flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-border p-8 text-center">
              <Fingerprint className="size-8 text-muted-foreground/50" />
              <div>
                <p className="text-sm font-medium">{t('No run yet')}</p>
                <p className="text-xs text-muted-foreground">
                  {t(
                    'Fill in a server base URL and run the flow to see the result here.',
                  )}
                </p>
              </div>
            </div>
          )
        )}
      </div>
    </div>
  )
}
