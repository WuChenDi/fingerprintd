'use client'

import { CheckIcon, CopyIcon } from 'lucide-react'
import * as React from 'react'
import { cn } from '@/shared/lib/utils'

type SizeVariant = 'sm' | 'default' | 'lg'

interface CopyButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  value?: string
  size?: SizeVariant
  ref?: React.Ref<HTMLButtonElement>
}

const sizeMap: Record<SizeVariant, { button: string; icon: number }> = {
  sm: { button: 'h-8 w-8', icon: 14 },
  default: { button: 'h-9 w-9', icon: 16 },
  lg: { button: 'h-12 w-12', icon: 20 },
}

function CopyButton({
  value,
  size = 'default',
  className,
  onClick,
  ref,
  ...props
}: CopyButtonProps) {
  const [copied, setCopied] = React.useState<boolean>(false)

  const handleCopy = (event: React.MouseEvent<HTMLButtonElement>) => {
    if (value) {
      navigator.clipboard.writeText(value).catch(() => {})
    }
    setCopied(true)
    setTimeout(setCopied, 1500, false)
    onClick?.(event)
  }

  const { button: buttonSize, icon: iconSize } = sizeMap[size]

  return (
    <button
      ref={ref}
      type="button"
      onClick={handleCopy}
      aria-label={copied ? 'Copied' : 'Copy to clipboard'}
      disabled={copied}
      className={cn(
        'relative cursor-pointer active:scale-[0.97] transition-all ease-out duration-200 inline-flex items-center justify-center rounded-md text-neutral-900 disabled:pointer-events-none disabled:opacity-100 dark:text-neutral-50',
        buttonSize,
        className,
      )}
      {...props}
    >
      <div
        className={cn(
          'transition-all duration-200',
          copied
            ? 'scale-100 opacity-100 blur-none'
            : 'scale-70 opacity-0 blur-[2px]',
        )}
      >
        <CheckIcon size={iconSize} strokeWidth={2} aria-hidden="true" />
      </div>
      <div
        className={cn(
          'absolute transition-all duration-200',
          copied
            ? 'scale-0 opacity-0 blur-[2px]'
            : 'scale-100 opacity-100 blur-none',
        )}
      >
        <CopyIcon size={iconSize} strokeWidth={2} aria-hidden="true" />
      </div>
    </button>
  )
}

export type { CopyButtonProps }
export { CopyButton }
