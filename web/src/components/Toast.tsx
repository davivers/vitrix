import { CheckCircle2, X } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { t } from "../i18n";

interface ToastMsg {
  id: number;
  text: string;
  link?: { to: string; label: string };
}
let seq = 0;

/** Fire a toast from anywhere (polite live region; auto-dismiss after 6 s). */
export function toast(text: string, link?: ToastMsg["link"]) {
  window.dispatchEvent(new CustomEvent("vitrix:toast", { detail: { id: ++seq, text, link } satisfies ToastMsg }));
}

export function Toaster() {
  const [items, setItems] = useState<ToastMsg[]>([]);
  useEffect(() => {
    const on = (e: Event) => {
      const m = (e as CustomEvent<ToastMsg>).detail;
      setItems((cur) => [...cur.slice(-3), m]);
      setTimeout(() => setItems((cur) => cur.filter((x) => x.id !== m.id)), 6000);
    };
    window.addEventListener("vitrix:toast", on);
    return () => window.removeEventListener("vitrix:toast", on);
  }, []);
  return (
    <div role="status" aria-live="polite" className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2 print:hidden">
      {items.map((m) => (
        <div key={m.id} className="pointer-events-auto flex items-start gap-2 rounded-[10px] border border-line bg-surface p-3 text-[13px] text-text shadow-lg">
          <CheckCircle2 size={15} className="mt-0.5 shrink-0 text-accent" aria-hidden />
          <span className="min-w-0 flex-1">
            {m.text}
            {m.link && (
              <Link to={m.link.to} className="ml-2 font-medium text-accent hover:underline">
                {m.link.label}
              </Link>
            )}
          </span>
          <button type="button" aria-label={t("close")} onClick={() => setItems((cur) => cur.filter((x) => x.id !== m.id))} className="text-subtle hover:text-text">
            <X size={14} aria-hidden />
          </button>
        </div>
      ))}
    </div>
  );
}
