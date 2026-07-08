import { createContext, use, useEffect, useState } from 'react'

export type Theme = 'dark' | 'light' | 'system'

interface ThemeProviderState {
  theme: Theme
  setTheme: (theme: Theme) => void
}

const STORAGE_KEY = 'nsio-theme'

const ThemeProviderContext = createContext<ThemeProviderState | undefined>(
  undefined,
)

export function ThemeProvider({
  children,
  defaultTheme = 'system',
}: {
  children: React.ReactNode
  defaultTheme?: Theme
}) {
  const [theme, setTheme] = useState<Theme>(
    () => (localStorage.getItem(STORAGE_KEY) as Theme | null) ?? defaultTheme,
  )

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, theme)

    const root = window.document.documentElement
    root.classList.remove('light', 'dark')

    const resolved =
      theme === 'system'
        ? window.matchMedia('(prefers-color-scheme: dark)').matches
          ? 'dark'
          : 'light'
        : theme

    root.classList.add(resolved)
  }, [theme])

  return (
    <ThemeProviderContext value={{ theme, setTheme }}>
      {children}
    </ThemeProviderContext>
  )
}

export function useTheme() {
  const context = use(ThemeProviderContext)
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider')
  }
  return context
}
