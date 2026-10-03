// Send a signed document whose act may need an operation-bound passkey
// gesture first — granting or promoting to `admin` (`acl/grant`,
// `acl/change-role`).
//
// The VTC runs every check that decides the act, then refuses it with the
// step-up it needs as `details.stepUpRequest`. This asks the operator to
// confirm — its own click, so the passkey ceremony runs inside a fresh user
// gesture and with the act on screen — records the gesture against that one
// operation, and sends the **identical** signed document again (the gesture is
// bound to it; a freshly signed one would be a second act). See
// `lib/bound-step-up.ts`.

import { postSignedDocument, postSignedTrustTask, type ApiError } from "./api";
import { answerStepUp, stepUpRequestOf, type StepUpRequest } from "./bound-step-up";
import type { ConsoleSigningKey } from "./console-key";

/** Ask the operator to confirm the gesture `req` asks for. */
export type ConfirmGesture = (req: StepUpRequest) => Promise<boolean>;

/**
 * A [`ConfirmGesture`] from the console's confirm dialog (`useConfirm`). Its
 * button is the click the passkey ceremony runs in.
 */
export function gestureFromConfirm(
  confirm: (options: { title: string; message?: string; confirmLabel?: string }) => Promise<boolean>,
): ConfirmGesture {
  return (req) =>
    confirm({
      title: "Confirm with your passkey",
      message: req.reason,
      confirmLabel: "Use passkey",
    });
}

/** Thrown when the operator declined the passkey confirmation. */
export class GestureDeclinedError extends Error {
  constructor() {
    super("Cancelled: the passkey confirmation was declined.");
    this.name = "GestureDeclinedError";
  }
}

export async function postSignedWithStepUp<T>(
  typeUri: string,
  payload: unknown,
  confirmGesture: ConfirmGesture,
  key?: ConsoleSigningKey,
): Promise<T> {
  try {
    return await (key
      ? postSignedTrustTask<T>(typeUri, payload, key)
      : postSignedTrustTask<T>(typeUri, payload));
  } catch (e) {
    const req = stepUpRequestOf(e);
    const document = (e as ApiError | null)?.document;
    if (!req || !document) throw e;
    if (!(await confirmGesture(req))) throw new GestureDeclinedError();
    await answerStepUp(req);
    return postSignedDocument<T>(document);
  }
}

/**
 * A consent-gated act (making or removing an unrestricted administrator,
 * lowering the consent threshold, changing an authority policy) is not refused
 * pending consent any more. Once its step-up is answered the VTC parks it as
 * an administrator action and answers with a `trust-task-next-step` reply,
 * which the signed door throws as a [`ParkedAction`]: a success, shown as one,
 * that completes by itself when enough administrators approve
 * (`lib/parked-action.ts`).
 */
export { ParkedAction, parkedOf } from "./parked-action";
