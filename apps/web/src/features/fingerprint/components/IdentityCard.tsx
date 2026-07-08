import type { IdentifyResponse } from '@cdlab/fingerprintd-client'
import { useTranslation } from 'react-i18next'
import { Card, CardContent } from '@/shared/components/ui/card'
import { cn } from '@/shared/lib/utils'
import { RidgeMeter } from './RidgeMeter'

const verdictAccent: Record<IdentifyResponse['decision'], string> = {
  match: 'text-match',
  review: 'text-review',
  new_device: 'text-newdev',
}

function Signal({
  label,
  value,
  tone,
}: {
  label: string
  value: React.ReactNode
  tone?: 'default' | 'muted'
}) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-border/60 py-2 text-sm last:border-0">
      <span className="text-muted-foreground">{label}</span>
      <span
        className={cn(
          'font-medium',
          tone === 'muted' && 'text-muted-foreground',
        )}
      >
        {value}
      </span>
    </div>
  )
}

export function IdentityCard({ identity }: { identity: IdentifyResponse }) {
  const { t } = useTranslation()

  return (
    <Card className="overflow-hidden pt-0">
      {/* Verdict header rail — the meter is the readout, the rail names it. */}
      <div
        className={cn(
          'flex items-center justify-between border-b bg-muted/30 px-4 py-3',
          verdictAccent[identity.decision],
        )}
      >
        <span className="text-[0.7rem] font-medium uppercase tracking-[0.18em] text-muted-foreground">
          {t('Identity')}
        </span>
        <span className="flex items-center gap-2 text-sm font-semibold text-current">
          <span className="size-2 rounded-full bg-current" />
          {t(identity.decision)}
        </span>
      </div>

      <CardContent className="space-y-5">
        <div className="flex justify-center pt-1">
          <RidgeMeter
            value={identity.confidence}
            decision={identity.decision}
            label={t('Confidence')}
          />
        </div>

        <div className="space-y-1.5">
          <span className="text-[0.7rem] uppercase tracking-[0.14em] text-muted-foreground">
            visitorId
          </span>
          <p className="break-all rounded-md border border-border bg-muted/40 px-3 py-2 font-mono text-sm">
            {identity.visitorId}
          </p>
        </div>

        <div>
          <Signal
            label={t('New device')}
            value={identity.is_new_device ? t('Yes') : t('No')}
            tone={identity.is_new_device ? 'default' : 'muted'}
          />
          <Signal
            label={t('Collision risk')}
            value={identity.collision_risk ? t('Yes') : t('No')}
            tone={identity.collision_risk ? 'default' : 'muted'}
          />
          <Signal
            label={t('UA / TLS consistent')}
            value={identity.signals.ua_tls_consistent ? t('Yes') : t('No')}
            tone={identity.signals.ua_tls_consistent ? 'muted' : 'default'}
          />
          <Signal
            label={t('IP risk')}
            value={
              <span className="font-mono">{identity.signals.ip_risk}</span>
            }
          />
        </div>
      </CardContent>
    </Card>
  )
}
