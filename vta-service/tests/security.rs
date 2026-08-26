//! Security-focused tests for auth enforcement, ACL, seal, and backup.
//!
//! These test the security enforcement logic directly without requiring
//! a full HTTP server or DIDComm stack.

#[cfg(test)]
mod auth_enforcement {
    use vti_common::acl::Role;
    use vti_common::auth::extractor::AuthClaims;

    fn admin_claims() -> AuthClaims {
        AuthClaims {
            did: "did:key:z6MkAdmin".into(),
            role: Role::Admin,
            allowed_contexts: vec![],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    fn scoped_admin_claims() -> AuthClaims {
        AuthClaims {
            did: "did:key:z6MkScoped".into(),
            role: Role::Admin,
            allowed_contexts: vec!["ctx1".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    fn initiator_claims() -> AuthClaims {
        AuthClaims {
            did: "did:key:z6MkInit".into(),
            role: Role::Initiator,
            allowed_contexts: vec![],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    fn application_claims() -> AuthClaims {
        AuthClaims {
            did: "did:key:z6MkApp".into(),
            role: Role::Application,
            allowed_contexts: vec!["ctx1".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    // ── require_admin ──

    #[test]
    fn admin_passes_require_admin() {
        assert!(admin_claims().require_admin().is_ok());
    }

    #[test]
    fn scoped_admin_passes_require_admin() {
        assert!(scoped_admin_claims().require_admin().is_ok());
    }

    #[test]
    fn initiator_fails_require_admin() {
        assert!(initiator_claims().require_admin().is_err());
    }

    #[test]
    fn application_fails_require_admin() {
        assert!(application_claims().require_admin().is_err());
    }

    // ── require_super_admin ──

    #[test]
    fn super_admin_passes_require_super_admin() {
        // Super admin = Admin + empty allowed_contexts
        assert!(admin_claims().require_super_admin().is_ok());
    }

    #[test]
    fn scoped_admin_fails_require_super_admin() {
        // Admin with allowed_contexts is NOT super admin
        assert!(scoped_admin_claims().require_super_admin().is_err());
    }

    #[test]
    fn initiator_fails_require_super_admin() {
        assert!(initiator_claims().require_super_admin().is_err());
    }

    // ── require_manage ──

    #[test]
    fn admin_passes_require_manage() {
        assert!(admin_claims().require_manage().is_ok());
    }

    #[test]
    fn initiator_passes_require_manage() {
        assert!(initiator_claims().require_manage().is_ok());
    }

    #[test]
    fn application_fails_require_manage() {
        assert!(application_claims().require_manage().is_err());
    }

    fn reader_claims() -> AuthClaims {
        AuthClaims {
            did: "did:key:z6MkReader".into(),
            role: Role::Reader,
            allowed_contexts: vec!["ctx1".into()],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    fn monitor_claims() -> AuthClaims {
        AuthClaims {
            did: "did:key:z6MkMonitor".into(),
            role: Role::Monitor,
            allowed_contexts: vec![],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    // ── require_read ──

    #[test]
    fn reader_passes_require_read() {
        assert!(reader_claims().require_read().is_ok());
    }

    #[test]
    fn application_passes_require_read() {
        assert!(application_claims().require_read().is_ok());
    }

    #[test]
    fn admin_passes_require_read() {
        assert!(admin_claims().require_read().is_ok());
    }

    #[test]
    fn monitor_fails_require_read() {
        assert!(monitor_claims().require_read().is_err());
    }

    // ── require_write ──

    #[test]
    fn application_passes_require_write() {
        assert!(application_claims().require_write().is_ok());
    }

    #[test]
    fn admin_passes_require_write() {
        assert!(admin_claims().require_write().is_ok());
    }

    #[test]
    fn initiator_passes_require_write() {
        assert!(initiator_claims().require_write().is_ok());
    }

    #[test]
    fn reader_fails_require_write() {
        assert!(reader_claims().require_write().is_err());
    }

    #[test]
    fn monitor_fails_require_write() {
        assert!(monitor_claims().require_write().is_err());
    }

    // ── reader cannot manage or admin ──

    #[test]
    fn reader_fails_require_manage() {
        assert!(reader_claims().require_manage().is_err());
    }

    #[test]
    fn reader_fails_require_admin() {
        assert!(reader_claims().require_admin().is_err());
    }

    // ── context access ──

    #[test]
    fn super_admin_has_access_to_any_context() {
        let claims = admin_claims(); // empty allowed_contexts = unrestricted
        assert!(claims.has_context_access("ctx1"));
        assert!(claims.has_context_access("ctx2"));
        assert!(claims.has_context_access("any-context"));
    }

    #[test]
    fn scoped_admin_restricted_to_allowed_contexts() {
        let claims = scoped_admin_claims(); // allowed_contexts: ["ctx1"]
        assert!(claims.has_context_access("ctx1"));
        assert!(!claims.has_context_access("ctx2"));
    }

    #[test]
    fn application_restricted_to_allowed_contexts() {
        let claims = application_claims();
        assert!(claims.has_context_access("ctx1"));
        assert!(!claims.has_context_access("ctx2"));
    }
}

#[cfg(test)]
mod acl_validation {
    use vti_common::acl::{Role, validate_role_assignment};
    use vti_common::auth::extractor::AuthClaims;

    fn claims(role: Role) -> AuthClaims {
        AuthClaims {
            did: "did:key:z6MkCaller".into(),
            role,
            allowed_contexts: vec![],
            session_id: "test-session".into(),
            access_expires_at: 0,
            issued_at: 0,
            amr: Vec::new(),
            acr: String::new(),
        }
    }

    #[test]
    fn admin_can_create_initiator() {
        assert!(validate_role_assignment(&claims(Role::Admin), &Role::Initiator).is_ok());
    }

    #[test]
    fn admin_can_create_application() {
        assert!(validate_role_assignment(&claims(Role::Admin), &Role::Application).is_ok());
    }

    #[test]
    fn initiator_cannot_create_admin() {
        // Privilege escalation prevention
        assert!(validate_role_assignment(&claims(Role::Initiator), &Role::Admin).is_err());
    }

    #[test]
    fn initiator_can_create_application() {
        assert!(validate_role_assignment(&claims(Role::Initiator), &Role::Application).is_ok());
    }

    #[test]
    fn application_cannot_create_admin() {
        let app = claims(Role::Application);
        assert!(validate_role_assignment(&app, &Role::Admin).is_err());
    }

    #[test]
    fn reader_cannot_assign_any_role() {
        let reader = claims(Role::Reader);
        assert!(validate_role_assignment(&reader, &Role::Application).is_err());
        assert!(validate_role_assignment(&reader, &Role::Reader).is_err());
        assert!(validate_role_assignment(&reader, &Role::Monitor).is_err());
    }

    #[test]
    fn initiator_can_create_reader() {
        assert!(validate_role_assignment(&claims(Role::Initiator), &Role::Reader).is_ok());
    }

    #[test]
    fn admin_can_create_reader() {
        assert!(validate_role_assignment(&claims(Role::Admin), &Role::Reader).is_ok());
    }
}

#[cfg(test)]
mod backup_security {
    use vta_sdk::protocols::backup_management::types::*;

    #[test]
    fn backup_envelope_rejects_wrong_password() {
        // This is already tested in operations::backup::tests but we verify
        // the error message is appropriate (not leaking internal details)
        let envelope = BackupEnvelope {
            version: 1,
            format: "vta-backup-v1".into(),
            created_at: chrono::Utc::now(),
            source_did: None,
            source_version: "0.2.0".into(),
            kdf: KdfParams {
                algorithm: "argon2id".into(),
                salt: base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    [0u8; 32],
                ),
                m_cost: 65536,
                t_cost: 3,
                p_cost: 4,
            },
            encryption: EncryptionParams {
                algorithm: "aes-256-gcm".into(),
                nonce: base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    [0u8; 12],
                ),
            },
            includes_audit: false,
            ciphertext: base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                [0u8; 48], // garbage ciphertext
            ),
        };

        let result = vta_service::operations::backup::decrypt_backup(&envelope, "any-password!!");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        // Should say "incorrect password", not expose internal crypto details
        assert!(
            err_msg.contains("incorrect backup password"),
            "error should mention password, got: {err_msg}"
        );
    }

    #[test]
    fn backup_rejects_unsupported_version() {
        let envelope = BackupEnvelope {
            version: 99,
            format: "vta-backup-v1".into(),
            created_at: chrono::Utc::now(),
            source_did: None,
            source_version: "0.2.0".into(),
            kdf: KdfParams {
                algorithm: "argon2id".into(),
                salt: "AAAA".into(),
                m_cost: 65536,
                t_cost: 3,
                p_cost: 4,
            },
            encryption: EncryptionParams {
                algorithm: "aes-256-gcm".into(),
                nonce: "AAAA".into(),
            },
            includes_audit: false,
            ciphertext: "AAAA".into(),
        };

        let result = vta_service::operations::backup::decrypt_backup(&envelope, "password12345");
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("unsupported backup format"));
    }
}
