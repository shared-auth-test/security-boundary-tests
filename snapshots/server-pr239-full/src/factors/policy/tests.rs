mod factor_management_policy_tests {
    use super::*;

    fn claims(aal: u8, acr: &str, auth_time: Option<u64>, amr: &[&str]) -> OreClaims {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        OreClaims {
            sub: Uuid::from_u128(1).to_string(),
            iss: "https://auth.test".into(),
            aud: "oresoftware".into(),
            iat: now,
            exp: now + 3600,
            nbf: now.saturating_sub(5),
            jti: "factor-policy-test".into(),
            sid: Some(Uuid::from_u128(2).to_string()),
            provider: "local".into(),
            provider_tenant: "default".into(),
            provider_subject: "subject".into(),
            project: None,
            supabase_user_id: None,
            email: None,
            email_verified: false,
            roles: Vec::new(),
            aal,
            amr: amr.iter().map(|method| (*method).to_owned()).collect(),
            acr: Some(acr.to_owned()),
            auth_time,
            webauthn_auth_time: None,
            auth_epoch: 0,
            scope: String::new(),
            azp: None,
            parent_jti: None,
            cred: None,
        }
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn existing_factor_management_requires_fresh_loa2() {
        assert!(require_fresh_factor_management_loa2(&claims(
            2,
            ACR_LOA2,
            Some(now()),
            &["pwd", "totp"],
        ))
        .is_ok());
        assert!(require_fresh_factor_management_loa2(&claims(
            1,
            ACR_LOA1,
            None,
            &["pwd"],
        ))
        .is_err());
        assert!(require_fresh_factor_management_loa2(&claims(
            2,
            ACR_LOA2,
            Some(now() - FACTOR_MANAGEMENT_MAX_AUTH_AGE_SECS - 1),
            &["pwd", "totp"],
        ))
        .is_err());
        assert!(require_fresh_factor_management_loa2(&claims(
            2,
            ACR_LOA2,
            Some(now() + FACTOR_MANAGEMENT_CLOCK_SKEW_SECS + 1),
            &["pwd", "totp"],
        ))
        .is_err());
    }

    #[test]
    fn first_factor_bootstrap_accepts_only_a_fresh_non_refresh_login() {
        assert!(require_fresh_factor_bootstrap(&claims(
            1,
            ACR_LOA1,
            None,
            &["pwd"],
        ))
        .is_ok());

        let mut stale = claims(1, ACR_LOA1, None, &["pwd"]);
        stale.iat = now() - FACTOR_BOOTSTRAP_MAX_TOKEN_AGE_SECS - 1;
        assert!(require_fresh_factor_bootstrap(&stale).is_err());

        assert!(require_fresh_factor_bootstrap(&claims(
            1,
            ACR_LOA1,
            None,
            &["refresh_token"],
        ))
        .is_err());
    }

    #[test]
    fn only_interactive_sessions_can_enter_factor_endpoints() {
        let interactive = claims(1, ACR_LOA1, None, &["pwd"]);
        assert!(require_interactive_factor_token(&interactive).is_ok());

        let mut sandboxed = interactive.clone();
        sandboxed.cred = Some("ssh_key".into());
        assert!(require_interactive_factor_token(&sandboxed).is_err());

        let mut delegated = interactive.clone();
        delegated.scope = "product:read".into();
        delegated.azp = Some("client".into());
        delegated.parent_jti = Some("parent".into());
        assert!(require_interactive_factor_token(&delegated).is_err());

        let mut sessionless = interactive;
        sessionless.sid = None;
        assert!(require_interactive_factor_token(&sessionless).is_err());
    }

    #[test]
    fn sandboxed_and_delegated_tokens_never_manage_factors() {
        let mut sandboxed = claims(2, ACR_LOA2, Some(now()), &["pwd", "totp"]);
        sandboxed.cred = Some("ssh_key".into());
        assert!(require_fresh_factor_management_loa2(&sandboxed).is_err());

        let mut delegated = claims(2, ACR_LOA2, Some(now()), &["pwd", "totp"]);
        delegated.scope = "product:read".into();
        delegated.azp = Some("client".into());
        delegated.parent_jti = Some("parent".into());
        assert!(require_fresh_factor_management_loa2(&delegated).is_err());
    }
}
