import { resolve } from "node:path";
import { defineConfig, mergeConfig } from "vitest/config";

import viteConfig from "./vite.config.ts";

// Component and unit tests for the console. They run in jsdom against the
// same `@/` alias and React plugin the build uses, so a test imports a plugin
// exactly as `src/plugins/index.ts` does. `npm test` runs them once. The Rust
// build does not run them; CI's `Test (VTC admin UI)` job does, alongside
// `npm run wire:check` and `npm run typecheck`.
export default mergeConfig(
  viteConfig,
  defineConfig({
    // Tests only, never the build (#2430): a test that checks the console
    // against a pinned specification bundle reads the vendored bundle itself,
    // the single source of truth, rather than a copy that could drift. The
    // matching `paths` entry is in `tsconfig.test.json`; the production
    // `tsconfig.json` and `vite.config.ts` reference nothing outside this
    // package, so the console builds from its own directory alone.
    resolve: {
      alias: {
        "@vti-specs-vtc": resolve(__dirname, "../../vti-specs-vtc"),
      },
    },
    test: {
      environment: "jsdom",
      include: ["src/**/*.test.{ts,tsx}"],
      setupFiles: ["src/test/setup.ts"],
      // Vitest turns every stylesheet into an empty module unless told
      // otherwise, `?raw` imports included. The built-in themes are read as
      // text and checked against the theme profile, so they must arrive whole.
      css: { include: [/src\/styles\/themes\//] },
    },
  }),
);
