export function LogoMark({ size = 32 }: { size?: number }) {
  return (
    <svg viewBox="0 0 64 64" width={size} height={size} role="img" aria-label="Vitrix">
      <rect width="64" height="64" rx="14" fill="#0B1020" />
      <rect x=".5" y=".5" width="63" height="63" rx="13.5" fill="none" stroke="#2D3560" />
      <path d="M32 12 46 32 32 52 18 32Z" fill="#6D5BF0" fillOpacity=".22" stroke="#8B7CF6" strokeWidth="3" strokeLinejoin="round" />
      <path d="M32 12v40" stroke="#8B7CF6" strokeWidth="2" strokeOpacity=".55" strokeLinecap="round" />
      <path d="M7 32h11" stroke="#22D3EE" strokeWidth="3" strokeLinecap="round" />
      <path d="M46 32 57 21" stroke="#2A78D6" strokeWidth="2.6" strokeLinecap="round" />
      <path d="M46 32h11" stroke="#EB6834" strokeWidth="2.6" strokeLinecap="round" />
      <path d="M46 32 57 43" stroke="#1BAF7A" strokeWidth="2.6" strokeLinecap="round" />
    </svg>
  );
}

export function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <LogoMark size={32} />
      <span className="text-[19px] font-bold tracking-[-0.03em] text-strong">vitrix</span>
    </div>
  );
}
