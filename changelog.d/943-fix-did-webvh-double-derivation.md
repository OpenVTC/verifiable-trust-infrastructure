### vta-service — fix DID doc key mismatch in non-interactive create-did-webvh (#943)

`vta create-did-webvh --url` derived keys twice (preview + operation),
consuming different BIP-32 path indices. The DID document embedded one
key while the store held another. Non-interactive mode now skips the
preview derivation so document and store agree.
