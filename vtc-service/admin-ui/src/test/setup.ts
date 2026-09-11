// Shared test setup. Testing Library only unmounts between tests on its own
// when Vitest globals are on; they are off here (tests import `describe` and
// `it` explicitly, so `tsc` checks them like any other module), so unmount
// explicitly.

import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

afterEach(() => {
  cleanup();
  // `mockFetch` stubs `fetch`; put the real one back for the next test.
  vi.unstubAllGlobals();
});
