import { defineConfig, mergeConfig } from "vitest/config";

import viteConfig from "./vite.config.ts";

// Component and unit tests for the console. They run in jsdom against the
// same `@/` alias and React plugin the build uses, so a test imports a plugin
// exactly as `src/plugins/index.ts` does. `npm test` runs them once; the Rust
// build does not, so run it before pushing a console change.
export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "jsdom",
      include: ["src/**/*.test.{ts,tsx}"],
      setupFiles: ["src/test/setup.ts"],
    },
  }),
);
