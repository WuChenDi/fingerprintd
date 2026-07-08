import { useTranslation } from 'react-i18next'
import { Badge } from '@/shared/components/ui/badge'
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/shared/components/ui/card'
import type { SignatureInfo } from '../api'

export function SignatureCard({ signature }: { signature: SignatureInfo }) {
  const { t } = useTranslation()

  if (!signature.signed) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            {t('Response signature')}
            <Badge variant="outline">{t('No')}</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            {t('Server did not sign this response.')}
          </p>
        </CardContent>
      </Card>
    )
  }

  const verified =
    signature.valid === undefined
      ? { variant: 'secondary' as const, label: t('not verified (no key)') }
      : signature.valid
        ? { variant: 'default' as const, label: t('Verified') }
        : { variant: 'destructive' as const, label: t('No') }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          {t('Response signature')}
          <Badge variant={verified.variant}>{verified.label}</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="flex items-center justify-between gap-4">
          <span className="text-muted-foreground">{t('Signed')}</span>
          <Badge variant="default">{t('Yes')}</Badge>
        </div>
        <div className="space-y-1">
          <span className="text-xs text-muted-foreground">
            {t('Timestamp')}
          </span>
          <p className="break-all font-mono text-xs">{signature.timestamp}</p>
        </div>
        <div className="space-y-1">
          <span className="text-xs text-muted-foreground">
            {t('Signature')}
          </span>
          <p className="break-all font-mono text-xs">{signature.signature}</p>
        </div>
      </CardContent>
    </Card>
  )
}
