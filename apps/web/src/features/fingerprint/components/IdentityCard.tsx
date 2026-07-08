import type { IdentifyResponse } from '@cdlab/fingerprintd-client'
import { useTranslation } from 'react-i18next'
import { Badge } from '@/shared/components/ui/badge'
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/shared/components/ui/card'
import { Separator } from '@/shared/components/ui/separator'
import { cn } from '@/shared/lib/utils'

const decisionVariant: Record<
  IdentifyResponse['decision'],
  'default' | 'secondary' | 'outline'
> = {
  match: 'default',
  review: 'secondary',
  new_device: 'outline',
}

function Row({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between gap-4 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium">{children}</span>
    </div>
  )
}

export function IdentityCard({ identity }: { identity: IdentifyResponse }) {
  const { t } = useTranslation()
  const pct = Math.round(identity.confidence * 100)

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          {t('Identity')}
          <Badge variant={decisionVariant[identity.decision]}>
            {t(identity.decision)}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1">
          <span className="text-xs text-muted-foreground">visitorId</span>
          <p className="break-all font-mono text-sm">{identity.visitorId}</p>
        </div>

        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">{t('Confidence')}</span>
            <span className="font-mono font-medium">{pct}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
            <div
              className={cn(
                'h-full rounded-full transition-all',
                identity.decision === 'match'
                  ? 'bg-primary'
                  : 'bg-muted-foreground',
              )}
              style={{ width: `${pct}%` }}
            />
          </div>
        </div>

        <Separator />

        <div className="space-y-2">
          <Row label={t('New device')}>
            {identity.is_new_device ? t('Yes') : t('No')}
          </Row>
          <Row label={t('Collision risk')}>
            {identity.collision_risk ? t('Yes') : t('No')}
          </Row>
        </div>

        <Separator />

        <div className="space-y-2">
          <span className="text-xs font-medium text-muted-foreground">
            {t('Signals')}
          </span>
          <Row label={t('UA / TLS consistent')}>
            {identity.signals.ua_tls_consistent ? t('Yes') : t('No')}
          </Row>
          <Row label={t('IP risk')}>
            <span className="font-mono">{identity.signals.ip_risk}</span>
          </Row>
        </div>
      </CardContent>
    </Card>
  )
}
