// Lightweight bilingual (English / Arabic) layer for the dashboard.
//
// Usage in components:  t("Servers", "الخوادم")  -> returns the string for the
// active language. `t` is a plain function (not a hook), so it works inside JSX,
// helpers, and render-time expressions alike. Do NOT call t() at module top-level
// (e.g. in a `const MAP = {...}`): that is evaluated once at import and would
// freeze the language. Apply t() at the render site instead — for maps whose keys
// are the English text, use `t(key, MAP[key])`.
//
// Language changes flip both the strings and the layout direction (rtl/ltr), and
// persist to localStorage("mcp_lang"). The provider keeps the module-level LANG in
// sync BEFORE rendering children, so every t() in a render pass sees the right value.
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

export type Lang = "ar" | "en";

function initialLang(): Lang {
  try { const v = localStorage.getItem("mcp_lang"); if (v === "en" || v === "ar") return v; } catch { /* ignore */ }
  return "ar";
}

// Module-level current language — read by t() everywhere.
let LANG: Lang = initialLang();

export function getLang(): Lang { return LANG; }
export function t(en: string, ar: string): string { return LANG === "ar" ? ar : en; }
export function dirFor(lang: Lang): "rtl" | "ltr" { return lang === "ar" ? "rtl" : "ltr"; }

const LangCtx = createContext<{ lang: Lang; setLang: (l: Lang) => void }>({
  lang: LANG, setLang: () => {},
});

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(LANG);
  LANG = lang;                                   // keep global in sync before children render
  useEffect(() => {
    document.documentElement.setAttribute("dir", dirFor(lang));
    document.documentElement.setAttribute("lang", lang);
    try { localStorage.setItem("mcp_lang", lang); } catch { /* ignore */ }
  }, [lang]);
  const setLang = (l: Lang) => { LANG = l; setLangState(l); };
  return <LangCtx.Provider value={{ lang, setLang }}>{children}</LangCtx.Provider>;
}

export function useLang() { return useContext(LangCtx); }
