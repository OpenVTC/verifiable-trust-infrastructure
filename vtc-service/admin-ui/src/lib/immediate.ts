// "Remove now" — single-administrator mode only
// (docs/05-design-notes/vtc-action-list.md §8.5).
//
// Removing another unrestricted administrator when nobody else can consent
// waits out a cooling-off, during which the subject is suspended. In
// single-administrator mode the VTC also takes the same removal *now*: the
// payload carries `ext["org.openvtc"].immediate = { confirm, actionId? }`, so
// the passkey gesture it asks for is bound to the immediate variant and never
// to the delayed one (VTI-APV-015). `confirm` is what the administrator typed:
// the subject's DID, or — landing an open cooling-off now — its action id.

/** The confirmation the administrator typed matches what it must. */
export function immediateConfirmMatches(
  typed: string,
  subject: string | undefined,
  actionId?: string,
): boolean {
  const t = typed.trim();
  if (t === "") return false;
  return t === subject || (actionId !== undefined && t === actionId);
}

/**
 * `payload` asking to land now: `ext["org.openvtc"].immediate` added beside
 * whatever extension members it already carries, everything else untouched —
 * the VTC matches the open cooling-off of the same operation by the payload
 * with `immediate` set aside.
 */
export function withImmediate(
  payload: Record<string, unknown>,
  confirm: string,
  actionId?: string,
): Record<string, unknown> {
  const ext = (payload.ext ?? {}) as Record<string, unknown>;
  const ours = (ext["org.openvtc"] ?? {}) as Record<string, unknown>;
  const immediate: Record<string, string> = { confirm: confirm.trim() };
  if (actionId !== undefined) immediate.actionId = actionId;
  return {
    ...payload,
    ext: { ...ext, "org.openvtc": { ...ours, immediate } },
  };
}
