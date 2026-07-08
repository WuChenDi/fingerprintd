import { FingerprintPlayground } from '@/features/fingerprint'
import { AppFooter } from '@/shared/components/app-footer'
import { AppHeader } from '@/shared/components/app-header'

export function App() {
  return (
    <div className="flex min-h-svh flex-col bg-background text-foreground">
      <AppHeader />
      <main className="flex-1">
        <FingerprintPlayground />
      </main>
      <AppFooter />
    </div>
  )
}
