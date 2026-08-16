import type { ReactNode } from "react";
import type { Tone } from "../../lib/format";

const TONE_CLASSES: Record<Tone, string> = {
  gray: "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300",
  blue: "bg-blue-light-50 text-blue-light-700 dark:bg-blue-light-950 dark:text-blue-light-300",
  amber: "bg-warning-50 text-warning-700 dark:bg-warning-950 dark:text-warning-300",
  orange: "bg-orange-50 text-orange-700 dark:bg-orange-950 dark:text-orange-300",
  red: "bg-error-50 text-error-700 dark:bg-error-950 dark:text-error-300",
  green: "bg-success-50 text-success-700 dark:bg-success-950 dark:text-success-300",
};

export default function ToneBadge({
  tone,
  children,
  className = "",
}: {
  tone: Tone;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${TONE_CLASSES[tone]} ${className}`}
    >
      {children}
    </span>
  );
}
