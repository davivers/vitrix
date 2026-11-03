import clsx from "clsx";
import { Check, Monitor, Moon, Sun, type LucideIcon } from "lucide-react";
import { LANGS, useLang } from "../i18n";
import { useTheme, type ThemeSetting } from "../theme";
import { t } from "../i18n";

const OPTIONS: { value: ThemeSetting; label: string; Icon: LucideIcon }[] = [
  { value: "light", label: t("l_light"), Icon: Sun },
  { value: "dark", label: t("l_dark"), Icon: Moon },
  { value: "system", label: t("l_system"), Icon: Monitor },
];

/** Appearance: Light / Dark / System. `menu` renders menuitemradio rows for the account menu, otherwise a radio group. */
export function ThemeControl({ menu = false }: { menu?: boolean }) {
  const [theme, setTheme] = useTheme();
  return (
    <div role={menu ? "group" : "radiogroup"} aria-label={t("appearance")} className={clsx(menu ? "py-0.5" : "flex flex-wrap gap-2")}>
      {OPTIONS.map(({ value, label, Icon }) => {
        const checked = theme === value;
        return (
          <button
            key={value}
            type="button"
            role={menu ? "menuitemradio" : "radio"}
            aria-checked={checked}
            onClick={() => setTheme(value)}
            className={clsx(
              menu
                ? "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-[13.5px] hover:bg-surface-2 focus-visible:bg-surface-2"
                : "inline-flex items-center gap-2 rounded-[10px] border px-3 py-2 text-[13.5px] font-medium",
              checked ? (menu ? "font-semibold text-strong" : "border-accent bg-accent-soft text-accent") : menu ? "text-text" : "border-line bg-surface text-text hover:bg-surface-2",
            )}
          >
            <Icon size={16} className="shrink-0" aria-hidden /> {label}
            {checked && <Check size={14} className={clsx("shrink-0", menu && "ml-auto")} aria-hidden />}
          </button>
        );
      })}
    </div>
  );
}

const LANG_LABEL = { en: "English", pt: "Português (Brasil)" } as const;

/** Language / Idioma: English or Brazilian Portuguese (names are shown in their own language). */
export function LanguageControl({ menu = false }: { menu?: boolean }) {
  const [lang, setLang] = useLang();
  return (
    <div role={menu ? "group" : "radiogroup"} aria-label={t("language_label")} className={clsx(menu ? "py-0.5" : "flex flex-wrap gap-2")}>
      {LANGS.map((value) => {
        const checked = lang === value;
        return (
          <button
            key={value}
            type="button"
            role={menu ? "menuitemradio" : "radio"}
            aria-checked={checked}
            onClick={() => setLang(value)}
            className={clsx(
              menu
                ? "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-[13.5px] hover:bg-surface-2 focus-visible:bg-surface-2"
                : "inline-flex items-center gap-2 rounded-[10px] border px-3 py-2 text-[13.5px] font-medium",
              checked ? (menu ? "font-semibold text-strong" : "border-accent bg-accent-soft text-accent") : menu ? "text-text" : "border-line bg-surface text-text hover:bg-surface-2",
            )}
          >
            {LANG_LABEL[value]}
            {checked && <Check size={14} className={clsx("shrink-0", menu && "ml-auto")} aria-hidden />}
          </button>
        );
      })}
    </div>
  );
}
