import { useTranslation } from 'react-i18next'

const steps = [
  {
    n: '01',
    title: 'Challenge',
    body: 'Server issues a nonce and the list of signals to collect.',
  },
  {
    n: '02',
    title: 'Collect',
    body: 'Client gathers stable components and computes an HMAC probe in WASM.',
  },
  {
    n: '03',
    title: 'Identify',
    body: 'Server judges the evidence and returns a verdict with confidence.',
  },
]

/** Shown before a run: the flow that "Run flow" will drive, as a typed pipeline. */
export function EmptyPipeline() {
  const { t } = useTranslation()

  return (
    <div className="flex h-full min-h-72 flex-col justify-center rounded-lg border border-dashed border-border bg-muted/20 p-6">
      <p className="mb-5 text-xs font-medium uppercase tracking-[0.16em] text-muted-foreground">
        {t('No run yet')}
      </p>
      <ol className="space-y-4">
        {steps.map((s, i) => (
          <li key={s.n} className="flex gap-4">
            <div className="flex flex-col items-center">
              <span className="font-mono text-sm font-semibold text-primary">
                {s.n}
              </span>
              {i < steps.length - 1 && (
                <span className="mt-1 h-full w-px flex-1 bg-border" />
              )}
            </div>
            <div className="pb-1">
              <p className="font-heading text-sm font-semibold">{t(s.title)}</p>
              <p className="text-xs leading-relaxed text-muted-foreground">
                {t(s.body)}
              </p>
            </div>
          </li>
        ))}
      </ol>
    </div>
  )
}
