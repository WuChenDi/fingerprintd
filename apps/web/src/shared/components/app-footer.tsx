export function AppFooter() {
  return (
    <footer className="border-t border-border">
      <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-6 text-xs text-muted-foreground">
        <span>
          © 2026-PRESENT ·{' '}
          <a
            href="https://github.com/WuChenDi"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-foreground hover:underline"
          >
            wudi
          </a>
        </span>
        <span className="font-mono text-muted-foreground/60">
          React 19 · Vite · Tailwind v4
        </span>
      </div>
    </footer>
  )
}
