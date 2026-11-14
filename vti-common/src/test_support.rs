//! Fixtures both services' tests need (feature `test-support`), kept once
//! rather than copied into each service's own `test_support` (#2572).

use std::sync::Arc;

/// Install `jsonwebtoken`'s `aws_lc` crypto provider for the process.
///
/// The workspace compiles `jsonwebtoken` with only the `aws_lc_rs` backend
/// (`rsa` is never pulled in, so nothing is exposed to RUSTSEC-2023-0071).
/// When `cargo test --workspace` unifies features and a sibling crate brings
/// in a second provider, `jsonwebtoken`'s auto-select panics; installing one
/// explicitly avoids that. Idempotent — safe to call from every test file.
pub fn init_jwt_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    });
}

/// A fully-offline [`ATM`](affinidi_tdk::messaging::ATM) for unit tests that
/// need `atm.unpack` without a live mediator.
///
/// No secrets and no network mode are configured, so it can unpack a
/// **plaintext** DIDComm envelope (which needs no keys) but not decrypt a JWE —
/// exactly what a plaintext-forgery regression needs: prove the handler
/// rejects an unauthenticated envelope after unpack.
pub async fn build_offline_atm() -> affinidi_tdk::messaging::ATM {
    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::messaging::config::ATMConfig;

    let tdk = TDKSharedState::new(TDKConfig::builder().build().expect("TDK config"))
        .await
        .expect("TDK shared state");
    affinidi_tdk::messaging::ATM::new(
        ATMConfig::builder().build().expect("ATM config"),
        Arc::new(tdk),
    )
    .await
    .expect("offline ATM")
}
