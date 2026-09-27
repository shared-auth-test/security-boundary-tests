#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc4648_vectors_without_padding() {
        assert_eq!(encode_base32(b"foo"), "MZXW6");
        assert_eq!(encode_base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn rfc6238_sha1_vector_is_correct() {
        let secret = b"12345678901234567890";
        assert_eq!(totp_code(secret, 59 / 30), "287082");
    }

    #[test]
    fn totp_ciphertext_is_bound_to_user_and_factor() {
        let key = [7_u8; 32];
        let nonce = [9_u8; 12];
        let user_id = Uuid::new_v4();
        let factor_id = Uuid::new_v4();
        let secret = b"12345678901234567890";
        let ciphertext =
            encrypt_totp_secret(&key, user_id, factor_id, nonce, secret).expect("encrypt");
        assert_eq!(
            decrypt_totp_secret(&key, user_id, factor_id, nonce, &ciphertext).expect("decrypt"),
            secret
        );
        assert!(decrypt_totp_secret(&key, Uuid::new_v4(), factor_id, nonce, &ciphertext).is_err());
        assert!(decrypt_totp_secret(&key, user_id, Uuid::new_v4(), nonce, &ciphertext).is_err());
    }

    #[test]
    fn otp_comparisons_are_exact() {
        let key = b"a sufficiently long test-only OTP pepper";
        let challenge_id = Uuid::new_v4();
        let tag = otp_tag(key, challenge_id, "123456").expect("tag");
        assert!(otp_tag_matches(key, challenge_id, "123456", &tag));
        assert!(!otp_tag_matches(key, challenge_id, "123457", &tag));
        assert!(constant_time_code_eq("654321", "654321", key));
        assert!(!constant_time_code_eq("654321", "654320", key));
    }

    #[test]
    fn otp_destination_tags_are_canonical_bound_and_domain_separated() {
        let key = b"a sufficiently long test-only OTP pepper";
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let canonical = canonical_destination("email_otp", " Person@Example.COM ")
            .expect("canonical email");
        assert_eq!(canonical, "person@example.com");

        let binding = destination_binding_tag(key, first, "email_otp", &canonical)
            .expect("binding tag");
        assert!(destination_binding_matches(
            key,
            first,
            "email_otp",
            &canonical,
            &binding
        ));
        assert!(!destination_binding_matches(
            key,
            second,
            "email_otp",
            &canonical,
            &binding
        ));
        assert!(!destination_binding_matches(
            key,
            first,
            "sms_otp",
            "+14155550100",
            &binding
        ));

        let stable_first =
            destination_budget_key(key, "email_otp", &canonical).expect("budget key");
        let stable_second = destination_budget_key(key, "email_otp", "person@example.com")
            .expect("budget key");
        assert_eq!(stable_first, stable_second);
        assert_ne!(stable_first, binding);
    }

    #[test]
    fn generated_codes_are_six_decimal_digits() {
        for _ in 0..64 {
            let code = generate_code().expect("secure random code");
            assert_eq!(code.len(), 6);
            assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
        }
    }

    async fn insert_otp_test_identity(
        service: &FactorService,
        destination: &str,
    ) -> (Uuid, Uuid, String) {
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let provider_subject = format!("den-3000-{user_id}");
        service
            .db
            .execute_raw(statement(
                "INSERT INTO shared_auth.principals (shared_user_id, status) \
                 VALUES ($1, 'active')",
                vec![user_id.into()],
            ))
            .await
            .expect("insert OTP test principal");
        service
            .db
            .execute_raw(statement(
                "INSERT INTO shared_auth.provider_identities \
                    (shared_user_id, provider, provider_tenant, provider_subject, email, email_verified) \
                 VALUES ($1, 'supabase', 'den-3000-test', $2, $3, true)",
                vec![
                    user_id.into(),
                    provider_subject.clone().into(),
                    destination.to_owned().into(),
                ],
            ))
            .await
            .expect("insert OTP test provider identity");
        service
            .db
            .execute_raw(statement(
                "INSERT INTO shared_auth.sessions \
                    (session_id, shared_user_id, refresh_token_hash, provider, provider_tenant, \
                     provider_subject, expires_at) \
                 VALUES ($1, $2, $3, 'supabase', 'den-3000-test', $4, \
                         now() + interval '1 hour')",
                vec![
                    session_id.into(),
                    user_id.into(),
                    format!("{}{}", session_id.simple(), "x".repeat(11)).into(),
                    provider_subject.clone().into(),
                ],
            ))
            .await
            .expect("insert OTP test session");
        (user_id, session_id, provider_subject)
    }

    fn otp_test_claims(user_id: Uuid, session_id: Uuid, provider_subject: String) -> OreClaims {
        let now = now_secs();
        OreClaims {
            sub: user_id.to_string(),
            iss: "https://auth.test".into(),
            aud: "oresoftware".into(),
            iat: now,
            exp: now + 3600,
            nbf: now.saturating_sub(5),
            jti: Uuid::new_v4().to_string(),
            sid: Some(session_id.to_string()),
            provider: "supabase".into(),
            provider_tenant: "den-3000-test".into(),
            provider_subject,
            project: None,
            supabase_user_id: None,
            email: Some("stale-token-value@example.invalid".into()),
            email_verified: true,
            roles: Vec::new(),
            aal: 1,
            amr: vec!["federated".into()],
            acr: Some(ACR_LOA1.into()),
            auth_time: None,
            webauthn_auth_time: None,
            auth_epoch: 0,
            scope: String::new(),
            azp: None,
            parent_jti: None,
            cred: None,
        }
    }

    #[tokio::test]
    async fn otp_send_budgets_span_sessions_principals_and_exact_provider_state() {
        let Some(url) = std::env::var("AUTH_TEST_DATABASE_URL").ok() else {
            eprintln!("AUTH_TEST_DATABASE_URL unset; skipping OTP budget integration test");
            return;
        };
        let service = FactorService::connect(&DbConfig {
            url,
            max_connections: 3,
            admin_email_search_hmac_key: None,
        })
        .await
        .expect("connect factor service");
        let pepper = b"DEN-3000 integration-only OTP pepper";
        let destination = format!("den-3000-shared-{}@example.invalid", Uuid::new_v4());

        let (user_id, first_session, provider_subject) =
            insert_otp_test_identity(&service, &destination).await;
        let first_claims = otp_test_claims(user_id, first_session, provider_subject.clone());
        let (_, delivered_to, _) = service
            .create_otp_challenge(&first_claims, ChallengeKind::EmailOtp, pepper)
            .await
            .expect("first destination send");
        assert_eq!(delivered_to, destination);
        assert_ne!(
            first_claims.email.as_deref(),
            Some(delivered_to.as_str()),
            "the provider row, not a stale JWT email, is authoritative"
        );

        let second_session = Uuid::new_v4();
        service
            .db
            .execute_raw(statement(
                "INSERT INTO shared_auth.sessions \
                    (session_id, shared_user_id, refresh_token_hash, provider, provider_tenant, \
                     provider_subject, expires_at) \
                 VALUES ($1, $2, $3, 'supabase', 'den-3000-test', $4, \
                         now() + interval '1 hour')",
                vec![
                    second_session.into(),
                    user_id.into(),
                    format!("{}{}", second_session.simple(), "x".repeat(11)).into(),
                    provider_subject.clone().into(),
                ],
            ))
            .await
            .expect("insert second session");
        let second_claims = otp_test_claims(user_id, second_session, provider_subject);
        assert!(matches!(
            service
                .create_otp_challenge(&second_claims, ChallengeKind::EmailOtp, pepper)
                .await,
            Err(AuthError::RateLimited)
        ));

        // Ten different principals can consume the configured shared
        // destination window (the first send above plus nine here); the next
        // principal must fail before any delivery adapter is called.
        for _ in 1..MAX_DESTINATION_OTP_SENDS_PER_WINDOW {
            let (next_user, next_session, next_subject) =
                insert_otp_test_identity(&service, &destination).await;
            let next_claims = otp_test_claims(next_user, next_session, next_subject);
            service
                .create_otp_challenge(&next_claims, ChallengeKind::EmailOtp, pepper)
                .await
                .expect("send within shared destination budget");
        }
        let (blocked_user, blocked_session, blocked_subject) =
            insert_otp_test_identity(&service, &destination).await;
        let blocked_claims = otp_test_claims(blocked_user, blocked_session, blocked_subject);
        assert!(matches!(
            service
                .create_otp_challenge(&blocked_claims, ChallengeKind::EmailOtp, pepper)
                .await,
            Err(AuthError::RateLimited)
        ));
    }

    #[test]
    fn webauthn_configuration_enforces_secure_origin_and_rp_binding() {
        let local = Url::parse("http://localhost:4173").unwrap();
        validate_webauthn_config("localhost", &local, "Local test").unwrap();

        let production = Url::parse("https://login.example.com").unwrap();
        validate_webauthn_config("example.com", &production, "Example").unwrap();

        let insecure = Url::parse("http://login.example.com").unwrap();
        assert!(validate_webauthn_config("example.com", &insecure, "Example").is_err());

        let unrelated = Url::parse("https://attacker.example.net").unwrap();
        assert!(validate_webauthn_config("example.com", &unrelated, "Example").is_err());

        let path = Url::parse("https://login.example.com/webauthn").unwrap();
        assert!(validate_webauthn_config("example.com", &path, "Example").is_err());
    }

    #[test]
    fn destination_masks_do_not_disclose_the_full_value() {
        assert_eq!(mask_destination("alex@example.com"), "a•••@example.com");
        assert_eq!(mask_destination("+14155550100"), "••••0100");
    }

    #[test]
    fn invalid_factor_key_is_rejected() {
        assert!(hex_nibble(b'g').is_err());
    }

    #[test]
    fn verified_credential_id_is_url_safe_no_pad_of_the_verified_bytes() {
        // The stored external_id must be derived from the credential id the
        // WebAuthn library verified (a `CredentialID`), never from the caller's
        // `id` JSON. Its encoding is URL-safe base64 without padding — the same
        // shape a browser sends for `id`/`rawId` — so honest registrations and
        // authentications resolve to the same row without a migration.
        let bytes: Vec<u8> = (1..=10).collect();
        let cred_id = CredentialID::from(bytes);
        assert_eq!(
            verified_credential_id(&cred_id).expect("encode verified credential id"),
            "AQIDBAUGBwgJCg"
        );
    }

    #[test]
    fn capability_document_is_complete_and_revocation_fails_closed() {
        let disabled = capability_document(false, Vec::new());
        assert_eq!(disabled.schema, "shared-auth/capabilities/v1");
        assert!(!disabled.mfa_enabled);
        assert!(disabled.methods.is_empty());
        assert!(disabled.threefa_import_scheme.is_none());
        assert!(disabled.biometric_model.is_none());
        assert_eq!(disabled.capabilities.len(), 13);
        let revocation = disabled
            .capabilities
            .iter()
            .find(|capability| capability.id == "global-session-revocation-by-email")
            .expect("global revocation capability");
        assert_eq!(revocation.state, "contract_only");

        let enabled = capability_document(
            true,
            vec![
                "email_otp".to_owned(),
                "sms_otp".to_owned(),
                "totp".to_owned(),
                "passkey".to_owned(),
            ],
        );
        assert!(enabled.mfa_enabled);
        assert_eq!(enabled.threefa_import_scheme, Some("otpauth"));
        assert_eq!(
            enabled.biometric_model,
            Some("platform_authenticator_webauthn")
        );
        assert_eq!(
            enabled
                .capabilities
                .iter()
                .find(|capability| capability.id == "global-session-revocation-by-email")
                .expect("global revocation capability")
                .state,
            "implemented"
        );
        for id in [
            "external-face-recovery",
            "external-fingerprint-recovery",
            "qr-device-bind",
            "risk-signals",
            "id-verification",
            "age-verification",
        ] {
            assert!(
                enabled
                    .capabilities
                    .iter()
                    .any(|capability| capability.id == id),
                "missing capability {id}"
            );
        }
        for id in ["external-face-recovery", "external-fingerprint-recovery"] {
            let biometric = enabled
                .capabilities
                .iter()
                .find(|capability| capability.id == id)
                .expect("external biometric capability");
            assert_eq!(biometric.state, "disabled");
            assert_eq!(biometric.authority, "none");
            assert_eq!(biometric.custody, "none");
        }

        // This discovery schema is deliberately narrower than the Ores
        // organization-scoped projection. Keep its inputs to the documented
        // bridge stable: candidate -> preview, contract_only -> contract,
        // SSH/Kerberos -> machine_possession, and WebAuthn ->
        // platform_biometric with no server biometric retention.
        let ssh = enabled
            .capabilities
            .iter()
            .find(|capability| capability.id == "ssh")
            .unwrap();
        assert_eq!(ssh.state, "candidate");
        let kerberos = enabled
            .capabilities
            .iter()
            .find(|capability| capability.id == "kerberos")
            .unwrap();
        assert_eq!(kerberos.state, "contract_only");
        let webauthn = enabled
            .capabilities
            .iter()
            .find(|capability| capability.id == "webauthn")
            .unwrap();
        assert_eq!(webauthn.custody, "platform_authenticator");
        let openpgp = enabled
            .capabilities
            .iter()
            .find(|capability| capability.id == "openpgp")
            .unwrap();
        assert_eq!(openpgp.authority, "provenance_only");
    }
}
