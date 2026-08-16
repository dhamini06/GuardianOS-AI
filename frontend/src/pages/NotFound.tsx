import { Link } from "react-router";
import PageMeta from "../components/common/PageMeta";

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-white px-4 dark:bg-gray-950">
      <PageMeta title="Not found" description="Page not found." />
      <p className="font-mono text-6xl font-bold text-brand-500">404</p>
      <h1 className="mt-3 text-lg font-semibold text-gray-900 dark:text-white">
        Page not found
      </h1>
      <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
        The route you requested does not exist in GuardianOS-AI.
      </p>
      <Link
        to="/"
        className="mt-5 rounded-md bg-brand-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-700"
      >
        Back to overview
      </Link>
    </div>
  );
}
