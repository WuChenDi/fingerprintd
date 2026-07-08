import { Accordion as AccordionPrimitive } from '@base-ui/react/accordion'
import { PlusIcon } from 'lucide-react'

import { cn } from '@/shared/lib/utils'

function Accordion({ className, ...props }: AccordionPrimitive.Root.Props) {
  return (
    <AccordionPrimitive.Root
      data-slot="accordion"
      className={cn(className)}
      {...props}
    />
  )
}

function AccordionItem({ className, ...props }: AccordionPrimitive.Item.Props) {
  return (
    <AccordionPrimitive.Item
      data-slot="accordion-item"
      className={cn('border-b border-border', className)}
      {...props}
    />
  )
}

function AccordionTrigger({
  className,
  children,
  ...props
}: AccordionPrimitive.Trigger.Props) {
  return (
    <AccordionPrimitive.Header className="flex">
      <AccordionPrimitive.Trigger
        data-slot="accordion-trigger"
        className={cn(
          'group flex flex-1 cursor-pointer items-center justify-between gap-4 py-5 text-left text-sm font-medium text-foreground transition-colors hover:text-foreground/70 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 sm:text-base',
          className,
        )}
        {...props}
      >
        {children}
        <PlusIcon className="size-5 shrink-0 text-muted-foreground transition-transform duration-200 group-data-[panel-open]:rotate-45" />
      </AccordionPrimitive.Trigger>
    </AccordionPrimitive.Header>
  )
}

function AccordionContent({
  className,
  children,
  ...props
}: AccordionPrimitive.Panel.Props) {
  return (
    <AccordionPrimitive.Panel
      data-slot="accordion-content"
      className={cn(
        'h-[var(--accordion-panel-height)] overflow-hidden text-sm text-muted-foreground transition-[height] duration-200 ease-out data-[ending-style]:h-0 data-[starting-style]:h-0',
        className,
      )}
      {...props}
    >
      <div className="pb-5 pr-9 leading-relaxed">{children}</div>
    </AccordionPrimitive.Panel>
  )
}

export { Accordion, AccordionContent, AccordionItem, AccordionTrigger }
