// Segmented Match system / Light / Dark switcher. Persists via @/lib/theme,
// under the key the member portal and the home page share, so one choice
// holds on all three of the community's surfaces.
//
// Shown in the console's account menu, in the top bar of the sign-in page,
// and in the member portal's top bar (`signin/SignInLayout.tsx`). The home
// page has a static twin in `website-default/theme.js`.
//
// A radio group: one of three, exactly one chosen. The chosen option is the
// only one in the Tab order; the arrow keys move the choice (and apply it),
// Home and End jump to the ends — the ARIA radio-group pattern.

import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { Monitor, Moon, Sun } from "lucide-react";

import {
  getStoredTheme,
  setTheme,
  subscribeTheme,
  type ThemePreference,
} from "@/lib/theme";
import "@/styles/theme-switcher.css";

export const THEME_OPTIONS: readonly {
  value: ThemePreference;
  icon: typeof Sun;
  label: string;
}[] = [
  { value: "auto", icon: Monitor, label: "Match system" },
  { value: "light", icon: Sun, label: "Light" },
  { value: "dark", icon: Moon, label: "Dark" },
];

export function ThemeSwitcher({ label = "Colour theme" }: { label?: string }) {
  const [pref, setPref] = useState<ThemePreference>(() => getStoredTheme());
  const refs = useRef<(HTMLButtonElement | null)[]>([]);

  useEffect(() => subscribeTheme(setPref), []);

  const choose = (i: number) => {
    const opt = THEME_OPTIONS[(i + THEME_OPTIONS.length) % THEME_OPTIONS.length]!;
    setTheme(opt.value);
    refs.current[THEME_OPTIONS.indexOf(opt)]?.focus();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>, i: number) => {
    switch (e.key) {
      case "ArrowRight":
      case "ArrowDown":
        e.preventDefault();
        choose(i + 1);
        break;
      case "ArrowLeft":
      case "ArrowUp":
        e.preventDefault();
        choose(i - 1);
        break;
      case "Home":
        e.preventDefault();
        choose(0);
        break;
      case "End":
        e.preventDefault();
        choose(THEME_OPTIONS.length - 1);
        break;
    }
  };

  return (
    <div className="theme-switcher" role="radiogroup" aria-label={label}>
      {THEME_OPTIONS.map((opt, i) => {
        const Icon = opt.icon;
        const active = pref === opt.value;
        return (
          <button
            key={opt.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={active}
            aria-label={opt.label}
            title={opt.label}
            tabIndex={active ? 0 : -1}
            onClick={() => setTheme(opt.value)}
            onKeyDown={(e) => onKeyDown(e, i)}
          >
            <Icon aria-hidden="true" />
          </button>
        );
      })}
    </div>
  );
}
