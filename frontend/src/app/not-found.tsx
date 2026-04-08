import Link from "next/link";
import { ArrowRight, Search, Upload, Wand2 } from "lucide-react";

export default function NotFound() {
  return (
    <div className="mx-auto flex min-h-[70vh] max-w-3xl items-center justify-center px-4">
      <div className="w-full rounded-[28px] border border-white/[0.08] bg-surface-800/80 p-8 text-center shadow-lg">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-flame-500/10">
          <Search className="h-7 w-7 text-flame-400" strokeWidth={1.5} />
        </div>
        <p className="mt-5 text-sm font-semibold uppercase tracking-[0.22em] text-flame-300/80">Not Found</p>
        <h1 className="mt-2 text-3xl font-bold tracking-tight text-white">That route is not part of the FlameGuard workspace.</h1>
        <p className="mx-auto mt-4 max-w-2xl text-base leading-relaxed text-gray-400">
          Return to the dashboard, open the audit queue, or upload a new export to continue the investigation workflow.
        </p>

        <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
          <Link href="/" className="inline-flex items-center gap-2 rounded-xl bg-white px-4 py-2.5 text-sm font-semibold text-slate-900 transition-colors hover:bg-slate-100">
            Back to Dashboard
            <ArrowRight className="h-4 w-4" />
          </Link>
          <Link href="/audit" className="inline-flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-2.5 text-sm font-semibold text-gray-200 transition-colors hover:bg-white/[0.08]">
            Review Audits
          </Link>
          <Link href="/upload" className="inline-flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-2.5 text-sm font-semibold text-gray-200 transition-colors hover:bg-white/[0.08]">
            <Upload className="h-4 w-4 text-flame-400" />
            Upload Config
          </Link>
          <Link href="/generate" className="inline-flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.04] px-4 py-2.5 text-sm font-semibold text-gray-200 transition-colors hover:bg-white/[0.08]">
            <Wand2 className="h-4 w-4 text-flame-400" />
            Generate Rule
          </Link>
        </div>
      </div>
    </div>
  );
}