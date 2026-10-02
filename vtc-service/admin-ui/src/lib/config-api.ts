// Writing the runtime configuration: `config/patch`, then `config/reload`.
//
// Kept out of `lib/api.ts` because a patch may need a passkey gesture, and the
// step-up path (`lib/signed-act.ts`) itself sends through `lib/api.ts`.

import { postSignedTrustTask } from "./api";
import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";
import type { ConfigPatchResponse } from "./wire-types";

export const CONFIG_PATCH_TASK = "https://trusttasks.org/spec/config/patch/0.1";
const CONFIG_RELOAD_TASK = "https://trusttasks.org/spec/config/reload/0.1";

/**
 * Write config overrides and put them into effect.
 *
 * Returns the PATCH response so a caller can surface `rejected` — the
 * daemon validates bounds server-side, so a value the console let through
 * can still come back refused, and the reason is worth showing.
 *
 * Lowering `acl.unrestricted_admin_consent_threshold` takes a passkey gesture
 * bound to this patch and the approval of the threshold as it stands
 * (VTI-APV-020); `confirmGesture` answers the first, and for the second the
 * patch is parked as an administrator action and thrown as a `ParkedAction`.
 * A parked patch applied nothing, so no `config/reload` follows it here; the
 * VTC applies the patch when the action completes. Every other key is written
 * at once.
 */
export async function saveConfig(
  overrides: Record<string, unknown>,
  confirmGesture: ConfirmGesture,
): Promise<ConfigPatchResponse> {
  const result = await postSignedWithStepUp<ConfigPatchResponse>(
    CONFIG_PATCH_TASK,
    { overrides },
    confirmGesture,
  );
  if (result.applied.length > 0) {
    await postSignedTrustTask<unknown>(CONFIG_RELOAD_TASK, {});
  }
  return result;
}
