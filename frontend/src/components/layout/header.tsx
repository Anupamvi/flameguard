export function Header() {
  return (
    <header className="flex h-14 items-center border-b bg-white px-6">
      <div className="flex items-center gap-2">
        <span className="text-xl" role="img" aria-label="flame">
          🔥
        </span>
        <h1 className="text-lg font-semibold tracking-tight text-slate-900">
          FlameGuard
        </h1>
      </div>
    </header>
  );
}
