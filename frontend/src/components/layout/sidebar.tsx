"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  FileSearch,
  MessageSquare,
  Shield,
  Upload,
  Wand2,
} from "lucide-react";

const navItems = [
  { href: "/", label: "Dashboard", icon: Shield },
  { href: "/upload", label: "Upload", icon: Upload },
  { href: "/audit", label: "Audits", icon: FileSearch },
  { href: "/generate", label: "Generate", icon: Wand2 },
  { href: "/chat", label: "Chat", icon: MessageSquare },
] as const;

export function Sidebar() {
  const pathname = usePathname();

  function isActive(href: string) {
    if (href === "/") return pathname === "/";
    return pathname.startsWith(href);
  }

  return (
    <aside className="fixed inset-y-0 left-0 z-30 flex w-56 flex-col bg-slate-900 text-white">
      {/* Brand */}
      <div className="flex h-14 items-center gap-2 border-b border-slate-700 px-4">
        <span className="text-xl" role="img" aria-label="flame">
          🔥
        </span>
        <span className="text-lg font-semibold tracking-tight">
          FlameGuard
        </span>
      </div>

      {/* Nav links */}
      <nav className="flex flex-1 flex-col gap-1 px-2 py-4">
        {navItems.map(({ href, label, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
              isActive(href)
                ? "bg-slate-700 text-white"
                : "text-slate-300 hover:bg-slate-800 hover:text-white"
            }`}
          >
            <Icon className="h-5 w-5 shrink-0" />
            {label}
          </Link>
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-slate-700 px-4 py-3 text-xs text-slate-400">
        v0.1.0
      </div>
    </aside>
  );
}
