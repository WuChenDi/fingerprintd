import { cn } from '@/shared/lib/utils'

/** Pretty-printed, scrollable JSON block for raw evidence. */
export function JsonBlock({
  value,
  className,
}: {
  value: unknown
  className?: string
}) {
  return (
    <pre
      className={cn(
        'max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-muted/40 p-3 font-mono text-xs leading-relaxed text-foreground',
        className,
      )}
    >
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}
