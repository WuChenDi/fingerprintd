import { CheckIcon, Monitor, Moon, Sun } from 'lucide-react'
import type { Theme } from '@/shared/components/theme-provider'
import { useTheme } from '@/shared/components/theme-provider'
import { Button } from '@/shared/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/shared/components/ui/dropdown-menu'

const icon = {
  light: Sun,
  dark: Moon,
  system: Monitor,
} as const

const labels: Record<Theme, string> = {
  light: 'Light',
  dark: 'Dark',
  system: 'System',
}

const themes: Theme[] = ['light', 'dark', 'system']

export function ModeToggle() {
  const { theme, setTheme } = useTheme()
  const Icon = icon[theme]

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button variant="outline" size="icon" aria-label="Theme">
            <Icon />
          </Button>
        }
      />
      <DropdownMenuContent align="end">
        {themes.map((value) => {
          const ItemIcon = icon[value]
          return (
            <DropdownMenuItem
              key={value}
              onClick={() => setTheme(value)}
              data-active={theme === value}
              className="data-[active=true]:font-semibold"
            >
              <ItemIcon />
              {labels[value]}
              {theme === value && <CheckIcon className="ml-auto" />}
            </DropdownMenuItem>
          )
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
