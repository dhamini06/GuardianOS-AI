import type { ReactNode } from "react";

export default function EmptyState({
  title,
  detail,
  children,
}: {
  title: string;
  detail?: string;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-gray-300 px-4 py-10 text-center dark:border-gray-700">
      <span className="text-sm font-medium text-gray-600 dark:text-gray-300">
        {title}
      </span>
      {detail && <span className="max-w-md text-xs text-gray-500 dark:text-gray-400">{detail}</span>}
      {children}
    </div>
  );
}
