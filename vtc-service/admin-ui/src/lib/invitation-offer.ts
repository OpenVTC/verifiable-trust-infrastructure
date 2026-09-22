// Turning a delivered invitation offer into something a wallet can scan.
//
// `vtc/invitations/deliver` with channel `offer` returns an OID4VCI Credential
// Offer: the community DID, the credential it offers, and a pre-authorized code
// that redeems only for the invited DID's key. It names the credential rather
// than containing it, so it fits a QR code where the signed invitation did not
// (Keyring VTI-32). A wallet reads it through the OID4VCI deep-link scheme.

/** The OID4VCI "credential offer by value" deep link for `offer`. */
export function offerDeepLink(offer: Record<string, unknown>): string {
  return `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}
