import { useSyncExternalStore } from "react";

export type ThemeSetting = "light" | "dark" | "system";
const KEY = "vitrix.theme";
const EVENT = "vitrix:theme";

export function readTheme(): ThemeSetting {
  try {
    const v = localStorage.getItem(KEY);
    return v === "dark" || v === "system" ? v : "light";
  } catch {
    return "light";
  }
}

const systemDark = () => window.matchMedia?.("(prefers-color-scheme: dark)").matches === true;

/** Sets data-theme on <html> from the setting (system follows the OS). Keep in sync with the inline script in index.html. */
export function applyTheme(setting: ThemeSetting) {
  const dark = setting === "dark" || (setting === "system" && systemDark());
  const root = document.documentElement;
  root.dataset.theme = dark ? "dark" : "light";
  root.style.colorScheme = dark ? "dark" : "light";
}

export function setTheme(setting: ThemeSetting) {
  try {
    localStorage.setItem(KEY, setting);
  } catch {
    /* storage unavailable: applies for this page only */
  }
  applyTheme(setting);
  window.dispatchEvent(new Event(EVENT));
}

const subscribe = (cb: () => void) => {
  window.addEventListener(EVENT, cb);
  return () => window.removeEventListener(EVENT, cb);
};

export function useTheme(): [ThemeSetting, (t: ThemeSetting) => void] {
  const setting = useSyncExternalStore(subscribe, readTheme);
  return [setting, setTheme];
}

/** Re-apply when the OS preference changes and the setting is "system". */
export function watchSystemTheme() {
  window.matchMedia?.("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (readTheme() === "system") {
      applyTheme("system");
      window.dispatchEvent(new Event(EVENT));
    }
  });
}

/** True when the resolved theme is dark (for things CSS variables cannot reach, like CodeMirror). */
export function useIsDark(): boolean {
  return useSyncExternalStore(subscribe, () => document.documentElement.dataset.theme === "dark");
}
