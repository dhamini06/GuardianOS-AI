export default function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <svg
        width={compact ? 28 : 32}
        height={compact ? 28 : 32}
        viewBox="0 0 32 32"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden="true"
      >
        <path
          d="M16 2.5 27 6.5v8.2c0 7.4-4.7 12.4-11 15.3C9.7 27.1 5 22.1 5 14.7V6.5L16 2.5Z"
          className="fill-brand-500 dark:fill-brand-600"
        />
        <path
          d="m11.5 15.8 3 3 6-6.2"
          stroke="#fff"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      {!compact && (
        <div className="leading-tight">
          <span className="block text-base font-semibold tracking-tight text-gray-900 dark:text-white">
            Guardian<span className="text-brand-500 dark:text-brand-400">OS</span>-AI
          </span>
          <span className="block text-[10px] font-medium uppercase tracking-[0.2em] text-gray-400 dark:text-gray-500">
            Kernel Defense
          </span>
        </div>
      )}
    </div>
  );
}
