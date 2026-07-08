import { Fingerprint } from 'lucide-react'
import { useEffect, useState } from 'react'
import { LanguageToggle } from '@/shared/components/language-toggle'
import { ModeToggle } from '@/shared/components/mode-toggle'
import { cn } from '@/shared/lib/utils'

export function AppHeader() {
  const [scrolled, setScrolled] = useState(() => window.scrollY > 8)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <header
      className={cn(
        'sticky top-0 z-30 border-b transition-colors duration-200',
        scrolled
          ? 'border-border bg-background/80 backdrop-blur'
          : 'border-transparent bg-transparent',
      )}
    >
      <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-4">
        <span className="flex items-center gap-2 text-sm font-semibold tracking-tight">
          <Fingerprint className="size-5 text-primary" />
          fingerprintd
        </span>
        <div className="flex items-center gap-2">
          <LanguageToggle />
          <ModeToggle />
        </div>
      </div>
    </header>
  )
}
