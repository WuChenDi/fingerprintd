import { CheckIcon, Languages } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/shared/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/shared/components/ui/dropdown-menu'
import { SUPPORTED_LANGUAGES } from '@/shared/i18n'

export function LanguageToggle() {
  const { i18n, t } = useTranslation()
  const current = i18n.resolvedLanguage

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button variant="outline" size="icon" aria-label={t('Language')}>
            <Languages />
          </Button>
        }
      />
      <DropdownMenuContent align="end">
        {SUPPORTED_LANGUAGES.map(({ code, label }) => (
          <DropdownMenuItem
            key={code}
            onClick={() => i18n.changeLanguage(code)}
            data-active={current === code}
            className="data-[active=true]:font-semibold"
          >
            {label}
            {current === code && <CheckIcon className="ml-auto" />}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
