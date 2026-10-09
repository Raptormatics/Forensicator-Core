"use client";
import * as React from "react";
import { cn } from "@/lib/utils";

// Native-select implementation.
// Select reads SelectItem options from the child tree synchronously and renders
// a single real <select> element.  SelectTrigger / SelectContent / SelectItem /
// SelectValue are kept as no-op stubs so call sites compile without changes.

type OptionDef = { value: string; label: string; disabled?: boolean };

/** Walk the immediate children of Select looking for SelectContent,
 *  then collect SelectItem props from its children. */
function collectOptions(children: React.ReactNode): OptionDef[] {
  const opts: OptionDef[] = [];
  React.Children.forEach(children, (child) => {
    if (!React.isValidElement(child)) return;
    // Any element whose children contain items with a `value` prop is treated as
    // the content container (i.e. SelectContent).
    const el = child as React.ReactElement<{ children?: React.ReactNode }>;
    React.Children.forEach(el.props.children, (item) => {
      if (!React.isValidElement(item)) return;
      const p = (item as React.ReactElement<SelectItemProps>).props;
      if (p.value !== undefined) {
        opts.push({
          value:    String(p.value),
          label:    String(p.children ?? p.value),
          disabled: p.disabled,
        });
      }
    });
  });
  return opts;
}

/** Extract className from the SelectTrigger child (first child with className). */
function extractTriggerClass(children: React.ReactNode): string {
  let cls = "";
  React.Children.forEach(children, (child) => {
    if (cls || !React.isValidElement(child)) return;
    const p = (child as React.ReactElement<{ className?: string }>).props;
    if (p.className) cls = p.className;
  });
  return cls;
}

export type SelectProps = {
  value?: string;
  defaultValue?: string;
  onValueChange?: (value: string) => void;
  className?: string;
  children?: React.ReactNode;
};

export function Select({ value, defaultValue = "", onValueChange, className, children }: SelectProps) {
  const [internal, setInternal] = React.useState(defaultValue);
  const controlled = value !== undefined;
  const current = controlled ? value! : internal;

  const options      = collectOptions(children);
  const triggerClass = extractTriggerClass(children);

  return (
    <select
      value={current}
      onChange={(e) => {
        if (!controlled) setInternal(e.target.value);
        onValueChange?.(e.target.value);
      }}
      className={cn(
        "flex h-9 w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100",
        "focus:outline-none focus:ring-2 focus:ring-zinc-400",
        "disabled:cursor-not-allowed disabled:opacity-50",
        triggerClass,
        className
      )}
    >
      {options.map((o) => (
        <option key={o.value} value={o.value} disabled={o.disabled} className="bg-zinc-900 text-zinc-100">
          {o.label}
        </option>
      ))}
    </select>
  );
}

// ── No-op stubs kept for API compatibility at call sites ─────────────────────

export function SelectTrigger(_props: { children?: React.ReactNode; className?: string }) {
  return null;
}
export function SelectValue(_props: { placeholder?: string }) {
  return null;
}
export function SelectContent(_props: { children?: React.ReactNode; className?: string }) {
  return null;
}
export type SelectItemProps = {
  value: string;
  children?: React.ReactNode;
  className?: string;
  disabled?: boolean;
};
export function SelectItem(_props: SelectItemProps) {
  return null;
}
export function SelectGroup(_props: { children?: React.ReactNode }) {
  return null;
}
