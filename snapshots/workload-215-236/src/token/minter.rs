//! Sign unified OreSoftware JWTs and short-lived delegated product tokens (ES256).

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
use p256::SecretKey;

use crate::config::SigningConfig;
use crate::error::AuthError;
use crate::workload::{WorkloadClientBinding, WorkloadPrincipal, WorkloadSessionSnapshot};
use crate::workload_token::{build_workload_claims, WorkloadTokenContext, WorkloadTokenProfileError};

use super::assurance::AuthenticationAssurance;
use super::claims::OreClaims;
use super::jwks::PublicJwks;

const MAX_AUTH_TIME_FUTURE_SKEW_SECS: u64 = 60;

pub struct TokenMinter {
    encoding_key: EncodingKey,
    header: Header,
    issuer: String,
    audience: String,
    ttl_secs: u64,
    jwks: PublicJwks,
    /// Verification side, so this server can also validate the tokens it minted
    /// (`/auth/introspect`, `/auth/verify`) without a network round-trip.
    decoding_key: DecodingKey,
}

/// A freshly minted token and its absolute expiry (unix seconds).
pub struct MintedToken {
    pub token: String,
    pub expires_at: u64,
    pub auth_time: Option<u64>,
    pub amr: Vec<String>,
    pub acr: Option<String>,
}

pub struct MintContext {
    pub shared_user_id: String,
    pub session_id: Option<uuid::Uuid>,
    pub provider: String,
    pub provider_tenant: String,
    pub provider_subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub roles: Vec<String>,
    pub assurance: AuthenticationAssurance,
    pub auth_epoch: u64,
    /// Set only after this server has verified a fresh WebAuthn ceremony.
    pub webauthn_step_up: bool,
}

/// Inputs for a token on the sandboxed credential plane.
///
/// Note what is *not* here: roles, email, and assurance. None of them are the
/// caller's to supply — a credential that proves possession gets base assurance
/// and its registered scopes, nothing more.
pub struct WorkloadMintContext<'a> {
    pub principal: &'a WorkloadPrincipal,
    pub binding: &'a WorkloadClientBinding,
    pub session: &'a WorkloadSessionSnapshot,
    pub oauth_client_allowed_scopes: &'a [String],
}

pub struct SandboxMintContext {
    pub shared_user_id: String,
    /// The revocable session this handshake created. Required, not optional:
    /// without it there is no way to invalidate a token before it expires.
    pub session_id: uuid::Uuid,
    /// Credential class — `ssh_key` today. Recorded as both `provider` and the
    /// `cred` claim so provenance is explicit rather than inferred from `amr`.
    pub credential_class: &'static str,
    /// Which credential of that class authenticated, as a stable non-secret
    /// identifier (a key fingerprint, a certificate subject).
    pub credential_reference: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub ttl_secs: u64,
}

impl TokenMinter {
    pub fn from_config(config: &SigningConfig) -> anyhow::Result<Self> {
        let encoding_key = EncodingKey::from_ec_pem(config.ec_private_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("loading EC signing key: {e}"))?;
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(config.key_id.clone());
        let jwks = PublicJwks::from_ec_pem(&config.ec_private_pem, &config.key_id)?;

        // Derive the public-key PEM once for our own verification side.
        let secret = SecretKey::from_pkcs8_pem(&config.ec_private_pem)
            .map_err(|e| anyhow::anyhow!("parsing EC signing key: {e}"))?;
        let public_pem = secret
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("encoding public key: {e}"))?;
        let decoding_key = DecodingKey::from_ec_pem(public_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("building decoding key: {e}"))?;

        Ok(Self {
            encoding_key,
            header,
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            ttl_secs: config.ttl_secs,
            jwks,
            decoding_key,
        })
    }

    /// Validate a normal shared-auth token this server previously minted.
    pub fn verify(&self, token: &str) -> Result<OreClaims, AuthError> {
        self.verify_for_audience(token, &self.audience)
    }

    /// Validate a token for an exact expected audience. This is used only after
    /// the caller has authenticated to protected introspection; downstream
    /// services should still pin issuer, audience, scope, and authorized party.
    pub fn verify_for_audience(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> Result<OreClaims, AuthError> {
        if expected_audience.is_empty() || expected_audience.len() > 128 {
            return Err(AuthError::Unauthorized);
        }
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[expected_audience]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub", "iat", "nbf"]);
        decode::<OreClaims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|_| AuthError::Unauthorized)
    }

    /// The public JWKS document verifiers fetch.
    pub fn jwks(&self) -> &PublicJwks {
        &self.jwks
    }

    /// Mint a token for a resolved OreSoftware identity.
    ///
    /// A local AAL2 token is minted only after this process completed a verified
    /// step-up ceremony, so its `auth_time` is the current time. Provider
    /// exchanges that need to preserve an upstream factor timestamp use
    /// [`Self::mint_with_auth_time`] instead.
    pub fn mint(&self, context: MintContext) -> Result<MintedToken, AuthError> {
        self.mint_with_auth_time(context, None)
    }

    /// Mint while preserving a verified upstream authentication timestamp.
    ///
    /// `verified_auth_time` is load-bearing only for AAL2. AAL1 tokens never
    /// carry `auth_time`. For local AAL2 flows the caller passes `None`, and the
    /// completion time of the server-owned ceremony is used. Exchange adapters
    /// pass the factor timestamp extracted from the already verified provider
    /// token; if they cannot establish one they must downgrade assurance before
    /// calling this method. A future upstream timestamp is rejected here as a
    /// second line of defense, even if the adapter already checked it.
    pub fn mint_with_auth_time(
        &self,
        context: MintContext,
        verified_auth_time: Option<u64>,
    ) -> Result<MintedToken, AuthError> {
        let now = now_secs();
        let expires_at = now.saturating_add(self.ttl_secs);
        let assurance_level = context.assurance.level();
        let auth_time = if assurance_level >= 2 {
            match (context.assurance.auth_time, verified_auth_time) {
                (Some(assurance_time), Some(upstream_time)) if assurance_time != upstream_time => {
                    tracing::warn!("refusing mismatched AAL2 ceremony timestamps");
                    return Err(AuthError::Unauthorized);
                }
                (Some(assurance_time), _) => Some(assurance_time),
                (None, Some(upstream_time)) => Some(upstream_time),
                (None, None) => {
                    tracing::warn!("refusing to mint AAL2 token without auth_time");
                    return Err(AuthError::Unauthorized);
                }
            }
        } else {
            // Base-assurance and credential-plane tokens never advertise a
            // ceremony time, even if their internal assurance records when a
            // password or proof-of-possession check ran.
            None
        };
        if auth_time.is_some_and(|value| value > now.saturating_add(MAX_AUTH_TIME_FUTURE_SKEW_SECS))
        {
            tracing::warn!("refusing to mint token with future auth_time");
            return Err(AuthError::Unauthorized);
        }

        let is_supabase = context.provider == "supabase";
        let claims = OreClaims {
            sub: context.shared_user_id,
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            iat: now,
            exp: expires_at,
            nbf: now.saturating_sub(5),
            jti: uuid::Uuid::new_v4().to_string(),
            sid: context.session_id.map(|id| id.to_string()),
            project: is_supabase.then(|| context.provider_tenant.clone()),
            supabase_user_id: is_supabase.then(|| context.provider_subject.clone()),
            provider: context.provider,
            provider_tenant: context.provider_tenant,
            provider_subject: context.provider_subject,
            email: context.email,
            email_verified: context.email_verified,
            roles: context.roles,
            // Derived from the ACR so `aal` and `acr` can never disagree.
            aal: assurance_level,
            amr: context.assurance.amr.clone(),
            acr: context.assurance.acr.clone(),
            auth_time,
            webauthn_auth_time: context.webauthn_step_up.then_some(now),
            auth_epoch: context.auth_epoch,
            scope: String::new(),
            azp: None,
            parent_jti: None,
            cred: None,
        };
        let token = self.sign(&claims)?;
        Ok(MintedToken {
            token,
            expires_at,
            auth_time,
            amr: context.assurance.amr,
            acr: context.assurance.acr,
        })
    }

    /// Sign a first-class non-human workload token using the same ES256
    /// authority as every other Shared Auth token.
    ///
    /// The caller supplies only DB-resolved workload lineage and the OAuth
    /// client's reviewed scope ceiling. Issuer, mint time and JTI remain owned
    /// by the minter so handlers cannot manufacture those security fields.
    pub fn mint_workload(
        &self,
        context: WorkloadMintContext<'_>,
    ) -> Result<MintedToken, AuthError> {
        // Workload tokens must never verify on the ordinary human-token
        // audience. Audience separation is enforced at the signing boundary,
        // not left to every downstream consumer to remember.
        if context.binding.audience.is_empty()
            || context.binding.audience == self.audience
            || context.binding.audience.len() > 128
        {
            return Err(AuthError::Forbidden);
        }

        let now = now_secs();
        let jti = uuid::Uuid::new_v4().to_string();
        let claims = build_workload_claims(WorkloadTokenContext {
            principal: context.principal,
            binding: context.binding,
            session: context.session,
            oauth_client_allowed_scopes: context.oauth_client_allowed_scopes,
            issuer: &self.issuer,
            issued_at_unix: now,
            jti: &jti,
        })
        .map_err(|error| match error {
            WorkloadTokenProfileError::InactiveLineage
            | WorkloadTokenProfileError::InvalidExpiry => AuthError::Unauthorized,
            WorkloadTokenProfileError::ScopeMismatch => AuthError::Forbidden,
            WorkloadTokenProfileError::EmptyIssuer | WorkloadTokenProfileError::EmptyJti => {
                tracing::error!(?error, "workload minter generated an invalid signing context");
                AuthError::Internal
            }
        })?;
        let token = self.sign(&claims)?;
        Ok(MintedToken {
            token,
            expires_at: claims.exp,
            auth_time: None,
            amr: claims.amr.clone(),
            acr: None,
        })
    }

    /// Mint a token on the sandboxed credential plane, from proof of possession
    /// of a registered credential rather than an interactive ceremony.
    ///
    /// Everything restrictive about this token class is enforced here, once,
    /// rather than in each credential's handler:
    ///
    /// - **A non-base audience.** A sandboxed token must not verify wherever an
    ///   ordinary shared-auth token does, so services opt in by asking for its
    ///   audience instead of opting out by remembering to check a claim.
    /// - **No roles.** The scope set stored against the credential is the whole
    ///   authority. Inheriting the principal's roles would make a key as
    ///   powerful as its owner, which is the exact failure this plane exists to
    ///   avoid.
    /// - **No control-plane scopes.** Refused by
    ///   [`crate::pubkey::validate_sandbox_scopes`] before anything is signed.
    /// - **Base assurance.** `aal`/`acr` come from
    ///   [`AuthenticationAssurance::credential_possession`], which cannot
    ///   produce LOA2.
    /// - **A bounded lifetime**, matching the delegation ceiling.
    pub fn mint_sandboxed(&self, context: SandboxMintContext) -> Result<MintedToken, AuthError> {
        if context.audience.is_empty()
            || context.audience == self.audience
            || context.audience.len() > 128
            || context.credential_class.is_empty()
            || context.credential_class.len() > 32
            || context.ttl_secs == 0
            || context.ttl_secs > 900
        {
            return Err(AuthError::Forbidden);
        }
        crate::pubkey::validate_sandbox_scopes(&context.scopes).map_err(|error| {
            tracing::warn!(%error, "refused to mint a sandboxed token for control-plane scopes");
            AuthError::Forbidden
        })?;

        let assurance = AuthenticationAssurance::credential_possession(context.credential_class);
        // Defence in depth: the constructor above is the only intended source
        // of this assurance, and it cannot return LOA2. If that ever changes,
        // this plane must not silently start issuing step-up-equivalent tokens.
        if assurance.level() != 1 {
            tracing::error!("sandboxed assurance resolved above base level");
            return Err(AuthError::Internal);
        }

        let now = now_secs();
        let expires_at = now.saturating_add(context.ttl_secs);
        let claims = OreClaims {
            sub: context.shared_user_id,
            iss: self.issuer.clone(),
            aud: context.audience,
            iat: now,
            exp: expires_at,
            nbf: now.saturating_sub(5),
            jti: uuid::Uuid::new_v4().to_string(),
            sid: Some(context.session_id.to_string()),
            provider: context.credential_class.to_owned(),
            provider_tenant: "default".to_owned(),
            provider_subject: context.credential_reference,
            project: None,
            supabase_user_id: None,
            // A machine credential carries no contact identity. Omitting it
            // keeps a mailbox out of every token that rides in CI logs.
            email: None,
            email_verified: false,
            roles: Vec::new(),
            aal: assurance.level(),
            amr: assurance.amr.clone(),
            acr: assurance.acr.clone(),
            auth_time: None,
            webauthn_auth_time: None,
            auth_epoch: 0,
            scope: context.scopes.join(" "),
            azp: None,
            parent_jti: None,
            cred: Some(context.credential_class.to_owned()),
        };
        let token = self.sign(&claims)?;
        Ok(MintedToken {
            token,
            expires_at,
            // Sandboxed tokens are deliberately AAL1. Proof-of-possession time
            // is useful for audit, but it is not an interactive step-up time.
            auth_time: None,
            amr: assurance.amr,
            acr: assurance.acr,
        })
    }

    /// Mint a narrow product token from an already verified, revocation-aware
    /// base token. Delegated tokens cannot be recursively delegated.
    pub fn mint_delegated(
        &self,
        source: &OreClaims,
        audience: &str,
        client_id: &str,
        scopes: &[String],
        ttl_secs: u64,
    ) -> Result<MintedToken, AuthError> {
        // A sandboxed token is refused explicitly, not incidentally. It would
        // already fail `is_delegated()` because it carries scopes, but
        // delegation is precisely how a narrow credential becomes a wide one,
        // so the prohibition should be legible at the point it is enforced and
        // should survive any future change to what `is_delegated` means.
        if source.is_sandboxed()
            || source.is_delegated()
            || source.aud != self.audience
            || audience.is_empty()
            || audience == self.audience
            || audience.len() > 128
            || client_id.is_empty()
            || client_id.len() > 128
            || scopes.is_empty()
            || scopes.len() > 32
            || ttl_secs == 0
            || ttl_secs > 900
        {
            return Err(AuthError::Forbidden);
        }

        let now = now_secs();
        if source.exp <= now {
            return Err(AuthError::Unauthorized);
        }
        let expires_at = source.exp.min(now.saturating_add(ttl_secs));
        if expires_at <= now {
            return Err(AuthError::Unauthorized);
        }
        let scope = scopes.join(" ");
        let claims = OreClaims {
            sub: source.sub.clone(),
            iss: self.issuer.clone(),
            aud: audience.to_owned(),
            iat: now,
            exp: expires_at,
            nbf: now.saturating_sub(5),
            jti: uuid::Uuid::new_v4().to_string(),
            sid: source.sid.clone(),
            provider: source.provider.clone(),
            provider_tenant: source.provider_tenant.clone(),
            provider_subject: source.provider_subject.clone(),
            project: source.project.clone(),
            supabase_user_id: source.supabase_user_id.clone(),
            email: source.email.clone(),
            email_verified: source.email_verified,
            roles: source.roles.clone(),
            aal: source.aal,
            amr: source.amr.clone(),
            acr: source.acr.clone(),
            auth_time: source.auth_time.or(Some(source.iat)),
            webauthn_auth_time: source.webauthn_auth_time,
            auth_epoch: source.auth_epoch,
            scope,
            azp: Some(client_id.to_owned()),
            parent_jti: Some(source.jti.clone()),
            cred: None,
        };
        let token = self.sign(&claims)?;
        Ok(MintedToken {
            token,
            expires_at,
            // report what was actually minted; delegation preserves the source
            // ceremony time rather than presenting a fresh step-up
            auth_time: claims.auth_time,
            amr: source.amr.clone(),
            acr: source.acr.clone(),
        })
    }

    /// Replace one exact same-party delegated scope with another after a
    /// service-authenticated server route has re-authorized the current actor.
    /// This deliberately cannot change audience/client or form an arbitrary
    /// recursive delegation chain.
    // Audience, client, source scope, target scope, and TTL are all explicit
    // constants at the only call site; keeping them separate makes a future
    // privilege expansion visible in review.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_same_party_admin_scope(
        &self,
        source: &OreClaims,
        opaque_subject: &str,
        audience: &str,
        client_id: &str,
        required_source_scope: &str,
        target_scope: &str,
        ttl_secs: u64,
    ) -> Result<MintedToken, AuthError> {
        if !source.is_delegated()
            || source.aud != audience
            || source.azp.as_deref() != Some(client_id)
            || source.scope != required_source_scope
            || audience.is_empty()
            || audience.len() > 128
            || client_id.is_empty()
            || client_id.len() > 128
            || opaque_subject.is_empty()
            || opaque_subject.len() > 128
            || target_scope.is_empty()
            || target_scope.len() > 128
            || target_scope == required_source_scope
            || ttl_secs == 0
            || ttl_secs > 300
        {
            return Err(AuthError::Forbidden);
        }
        let now = now_secs();
        let expires_at = source.exp.min(now.saturating_add(ttl_secs));
        if expires_at <= now {
            return Err(AuthError::Unauthorized);
        }
        let claims = OreClaims {
            sub: opaque_subject.to_owned(),
            iss: self.issuer.clone(),
            aud: audience.to_owned(),
            iat: now,
            exp: expires_at,
            nbf: now.saturating_sub(5),
            jti: uuid::Uuid::new_v4().to_string(),
            sid: source.sid.clone(),
            provider: "shared_auth_admin".into(),
            provider_tenant: "redacted".into(),
            provider_subject: "redacted".into(),
            project: None,
            supabase_user_id: None,
            email: None,
            email_verified: false,
            roles: source.roles.clone(),
            aal: source.aal,
            amr: source.amr.clone(),
            acr: source.acr.clone(),
            auth_time: source.auth_time.or(Some(source.iat)),
            webauthn_auth_time: source.webauthn_auth_time,
            auth_epoch: source.auth_epoch,
            scope: target_scope.to_owned(),
            azp: Some(client_id.to_owned()),
            parent_jti: Some(source.jti.clone()),
            cred: None,
        };
        let token = self.sign(&claims)?;
        Ok(MintedToken {
            token,
            expires_at,
            auth_time: claims.auth_time,
            amr: source.amr.clone(),
            acr: source.acr.clone(),
        })
    }

    fn sign(&self, claims: &OreClaims) -> Result<String, AuthError> {
        encode(&self.header, claims, &self.encoding_key).map_err(|err| {
            tracing::error!(error = %err, "token signing failed");
            AuthError::Internal
        })
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SigningConfig;
    use crate::token::{AuthenticationAssurance, ACR_LOA1, ACR_LOA2};

    use p256::pkcs8::{EncodePrivateKey, LineEnding};

    fn signing_pem() -> String {
        p256::SecretKey::from_slice(&[7u8; 32])
            .unwrap()
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn minter() -> TokenMinter {
        TokenMinter::from_config(&SigningConfig {
            ec_private_pem: signing_pem(),
            key_id: "test-kid".to_string(),
            issuer: "https://auth.test".to_string(),
            audience: "oresoftware".to_string(),
            ttl_secs: 3600,
        })
        .unwrap()
    }

    fn context(assurance: AuthenticationAssurance) -> MintContext {
        MintContext {
            shared_user_id: "shared-42".into(),
            session_id: Some(uuid::Uuid::from_u128(42)),
            provider: "supabase".into(),
            provider_tenant: "fiducia-cloud".into(),
            provider_subject: "sub-1".into(),
            email: Some("a@b.co".into()),
            email_verified: true,
            roles: vec!["user".into()],
            assurance,
            auth_epoch: 0,
            webauthn_step_up: false,
        }
    }

    // Our minted tokens verify against our own key with NO Supabase dependency —
    // the half of tandem-resilience that keeps downstream auth alive even if
    // Supabase is fully down.
    #[test]
    fn mint_then_verify_roundtrip() {
        let m = minter();
        let minted = m
            .mint(context(AuthenticationAssurance::local_password()))
            .unwrap();
        let claims = m.verify(&minted.token).unwrap();
        assert_eq!(claims.sub, "shared-42");
        assert_eq!(claims.project.as_deref(), Some("fiducia-cloud"));
        assert_eq!(claims.supabase_user_id.as_deref(), Some("sub-1"));
        assert_eq!(claims.provider, "supabase");
        assert_eq!(claims.roles, vec!["user"]);
        assert_eq!(claims.email.as_deref(), Some("a@b.co"));
        assert!(claims.email_verified);
        assert_eq!(claims.amr, vec!["pwd"]);
        assert_eq!(claims.acr.as_deref(), Some(ACR_LOA1));
        assert_eq!(claims.auth_time, minted.auth_time);
        assert_eq!(minted.amr, vec!["pwd"]);
        assert_eq!(minted.acr.as_deref(), Some(ACR_LOA1));
        // local_password is AAL1. The contract omits auth_time from AAL1
        // tokens, so stamping one here would let a password session advertise
        // a step-up ceremony it never performed.
        assert!(
            claims.auth_time.is_none(),
            "an AAL1 token must not carry a ceremony time"
        );
        assert!(!claims.is_delegated());
        assert!(claims.exp > claims.iat);
    }

    // The other half of the property: gating auth_time must not suppress it
    // where it is load-bearing, or step-up freshness checks break closed.
    #[test]
    fn aal2_tokens_still_carry_a_ceremony_time() {
        let m = minter();
        let assurance = AuthenticationAssurance::step_up(&["pwd".to_string()], "totp");
        assert!(
            assurance.level() >= 2,
            "fixture must actually reach AAL2 for this to prove anything"
        );
        let minted = m.mint(context(assurance)).unwrap();
        let claims = m.verify(&minted.token).unwrap();
        assert_eq!(claims.aal, 2);
        assert!(
            claims.auth_time.is_some(),
            "an AAL2 token must carry the ceremony time"
        );
    }

    #[test]
    fn only_a_server_verified_webauthn_ceremony_gets_a_freshness_marker() {
        let m = minter();
        let assurance = AuthenticationAssurance::step_up(&["pwd".into()], "passkey");
        let upstream = m.mint(context(assurance.clone())).unwrap();
        assert!(m
            .verify(&upstream.token)
            .unwrap()
            .webauthn_auth_time
            .is_none());

        let mut local = context(assurance);
        local.webauthn_step_up = true;
        let local = m.mint(local).unwrap();
        let claims = m.verify(&local.token).unwrap();
        assert_eq!(claims.webauthn_auth_time, claims.auth_time);
    }

    #[test]
    fn delegation_preserves_subject_session_and_assurance_but_narrows_authority() {
        let m = minter();
        let assurance = AuthenticationAssurance::step_up(&["pwd".into()], "totp");
        let base = m.mint(context(assurance)).unwrap();
        let source = m.verify(&base.token).unwrap();
        let delegated = m
            .mint_delegated(
                &source,
                "cliptown-api",
                "memebank-api",
                &["cliptown:memebank:write".into()],
                300,
            )
            .unwrap();

        assert!(m.verify(&delegated.token).is_err());
        let claims = m
            .verify_for_audience(&delegated.token, "cliptown-api")
            .unwrap();
        assert_eq!(claims.sub, source.sub);
        assert_eq!(claims.sid, source.sid);
        assert_eq!(claims.auth_time, source.auth_time);
        assert_eq!(claims.acr.as_deref(), Some(ACR_LOA2));
        assert!(claims.used_method("totp"));
        assert!(claims.has_scope("cliptown:memebank:write"));
        assert_eq!(claims.azp.as_deref(), Some("memebank-api"));
        assert_eq!(claims.parent_jti.as_deref(), Some(source.jti.as_str()));
        assert_ne!(claims.jti, source.jti);
        assert!(claims.exp <= source.exp);
    }

    #[test]
    fn delegated_token_cannot_be_recursively_exchanged() {
        let m = minter();
        let base = m
            .mint(context(AuthenticationAssurance::local_password()))
            .unwrap();
        let source = m.verify(&base.token).unwrap();
        let first = m
            .mint_delegated(
                &source,
                "cliptown-api",
                "memebank-api",
                &["cliptown:memebank:read".into()],
                300,
            )
            .unwrap();
        let first_claims = m.verify_for_audience(&first.token, "cliptown-api").unwrap();
        assert!(m
            .mint_delegated(
                &first_claims,
                "another-api",
                "other-client",
                &["read".into()],
                60,
            )
            .is_err());
    }

    fn workload_principal() -> crate::workload::WorkloadPrincipal {
        crate::workload::WorkloadPrincipal {
            service_account_id: uuid::Uuid::from_u128(10),
            application_id: uuid::Uuid::from_u128(20),
            status: crate::workload::WorkloadStatus::Active,
            auth_epoch: 7,
        }
    }

    fn workload_binding() -> crate::workload::WorkloadClientBinding {
        crate::workload::WorkloadClientBinding {
            client_id: "svc-build".to_string(),
            service_account_id: uuid::Uuid::from_u128(10),
            application_id: uuid::Uuid::from_u128(20),
            audience: "build-api".to_string(),
            status: crate::workload::WorkloadStatus::Active,
            credential_epoch: 3,
            allowed_scopes: vec!["build:read".to_string(), "build:write".to_string()],
            default_scopes: vec!["build:read".to_string()],
        }
    }

    fn workload_session() -> crate::workload::WorkloadSessionSnapshot {
        crate::workload::WorkloadSessionSnapshot {
            session_id: uuid::Uuid::from_u128(30),
            service_account_id: uuid::Uuid::from_u128(10),
            client_id: "svc-build".to_string(),
            application_id: uuid::Uuid::from_u128(20),
            service_account_auth_epoch: 7,
            credential_epoch: 3,
            audience: "build-api".to_string(),
            scopes: vec!["build:write".to_string(), "build:read".to_string()],
            expires_at_unix: now_secs().saturating_add(300),
            revoked: false,
        }
    }

    #[test]
    fn workload_minter_signs_the_exact_machine_profile() {
        let m = minter();
        let principal = workload_principal();
        let binding = workload_binding();
        let session = workload_session();
        let allowed = vec!["build:read".to_string(), "build:write".to_string()];
        let minted = m
            .mint_workload(WorkloadMintContext {
                principal: &principal,
                binding: &binding,
                session: &session,
                oauth_client_allowed_scopes: &allowed,
            })
            .unwrap();

        assert!(m.verify(&minted.token).is_err());
        let claims = m
            .verify_for_audience(&minted.token, "build-api")
            .unwrap();
        assert!(claims.is_workload());
        assert_eq!(claims.sub, format!("workload:{}", principal.service_account_id));
        assert_eq!(claims.sid.as_deref(), Some(session.session_id.to_string().as_str()));
        assert_eq!(claims.azp.as_deref(), Some(binding.client_id.as_str()));
        assert_eq!(claims.scope, "build:read build:write");
        assert!(claims.email.is_none());
        assert!(claims.roles.is_empty());
        assert_eq!(claims.aal, 0);
        assert!(minted.auth_time.is_none());
        assert!(minted.acr.is_none());
        assert_eq!(minted.amr, vec![crate::workload_token::WORKLOAD_AMR.to_string()]);
        assert!(crate::workload_token::workload_claims_match_session(&claims, &session));
    }

    #[test]
    fn workload_minter_refuses_the_base_human_audience() {
        let m = minter();
        let principal = workload_principal();
        let mut binding = workload_binding();
        binding.audience = "oresoftware".to_string();
        let mut session = workload_session();
        session.audience = binding.audience.clone();
        let allowed = vec!["build:read".to_string(), "build:write".to_string()];

        assert!(matches!(
            m.mint_workload(WorkloadMintContext {
                principal: &principal,
                binding: &binding,
                session: &session,
                oauth_client_allowed_scopes: &allowed,
            }),
            Err(AuthError::Forbidden)
        ));
    }

    #[test]
    fn workload_minter_refuses_inactive_or_scope_mismatched_lineage() {
        let m = minter();
        let principal = workload_principal();
        let binding = workload_binding();
        let mut session = workload_session();
        let allowed = vec!["build:read".to_string(), "build:write".to_string()];
        session.revoked = true;
        assert!(matches!(
            m.mint_workload(WorkloadMintContext {
                principal: &principal,
                binding: &binding,
                session: &session,
                oauth_client_allowed_scopes: &allowed,
            }),
            Err(AuthError::Unauthorized)
        ));

        session.revoked = false;
        let too_narrow = vec!["build:read".to_string()];
        assert!(matches!(
            m.mint_workload(WorkloadMintContext {
                principal: &principal,
                binding: &binding,
                session: &session,
                oauth_client_allowed_scopes: &too_narrow,
            }),
            Err(AuthError::Forbidden)
        ));
    }

    fn sandbox_context(scopes: &[&str]) -> SandboxMintContext {
        SandboxMintContext {
            shared_user_id: "shared-42".into(),
            session_id: uuid::Uuid::from_u128(7),
            credential_class: "ssh_key",
            credential_reference: "SHA256:abc".into(),
            audience: "cliptown-api".into(),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            ttl_secs: 300,
        }
    }

    // The sandboxed token's limits are properties of the token itself, not of
    // any downstream check. This asserts each of them on the decoded claims.
    #[test]
    fn a_sandboxed_token_carries_no_roles_no_email_and_base_assurance_only() {
        let m = minter();
        let minted = m
            .mint_sandboxed(sandbox_context(&["cliptown:memebank:read"]))
            .unwrap();

        // It must not verify as an ordinary shared-auth token.
        assert!(m.verify(&minted.token).is_err());

        let claims = m
            .verify_for_audience(&minted.token, "cliptown-api")
            .unwrap();
        assert_eq!(claims.sub, "shared-42");
        assert!(claims.roles.is_empty());
        assert_eq!(claims.email, None);
        assert!(!claims.email_verified);
        assert_eq!(claims.aal, 1);
        assert_eq!(claims.acr.as_deref(), Some(ACR_LOA1));
        assert_eq!(claims.amr, vec!["ssh_key"]);
        assert_eq!(claims.cred.as_deref(), Some("ssh_key"));
        assert_eq!(claims.provider_subject, "SHA256:abc");
        assert_eq!(
            claims.sid.as_deref(),
            Some(uuid::Uuid::from_u128(7).to_string().as_str())
        );
        assert!(claims.has_scope("cliptown:memebank:read"));
        assert!(claims.is_sandboxed());
    }

    // Refusal happens at mint time. A handler that forgets to check, or a
    // registration row written before the policy tightened, still cannot
    // produce a control-plane token.
    #[test]
    fn control_plane_scopes_are_refused_by_the_minter_itself() {
        let m = minter();
        for scope in [
            "shared-auth:factors:enroll",
            "cliptown:admin:write",
            "cliptown:keys:add",
        ] {
            assert!(
                m.mint_sandboxed(sandbox_context(&[scope])).is_err(),
                "{scope} must not mint"
            );
        }
    }

    #[test]
    fn a_sandboxed_token_cannot_target_the_base_audience_or_outlive_the_ceiling() {
        let m = minter();
        let mut context = sandbox_context(&["cliptown:memebank:read"]);
        context.audience = "oresoftware".into();
        assert!(m.mint_sandboxed(context).is_err());

        let mut context = sandbox_context(&["cliptown:memebank:read"]);
        context.ttl_secs = 901;
        assert!(m.mint_sandboxed(context).is_err());

        let mut context = sandbox_context(&["cliptown:memebank:read"]);
        context.scopes.clear();
        assert!(m.mint_sandboxed(context).is_err());
    }

    // Delegation is how a narrow credential becomes a wide one, so it is the
    // one exchange this plane must never reach.
    #[test]
    fn a_sandboxed_token_cannot_be_delegated() {
        let m = minter();
        let minted = m
            .mint_sandboxed(sandbox_context(&["cliptown:memebank:read"]))
            .unwrap();
        let claims = m
            .verify_for_audience(&minted.token, "cliptown-api")
            .unwrap();
        assert!(m
            .mint_delegated(
                &claims,
                "quaestor-api",
                "cliptown-api",
                &["quaestor:billing:read".into()],
                300,
            )
            .is_err());
    }

    // Fail-closed direction of `is_sandboxed`: an unrecognized credential class
    // in a token we did not mint this build must still read as restricted.
    #[test]
    fn an_unknown_credential_class_still_reads_as_sandboxed() {
        let m = minter();
        let base = m
            .mint(context(AuthenticationAssurance::local_password()))
            .unwrap();
        let mut claims = m.verify(&base.token).unwrap();
        assert!(!claims.is_sandboxed());
        claims.cred = Some("some-future-credential".into());
        assert!(claims.is_sandboxed());
    }

    #[test]
    fn tampered_token_is_rejected() {
        let m = minter();
        let minted = m
            .mint(MintContext {
                shared_user_id: "s".into(),
                session_id: None,
                provider: "local".into(),
                provider_tenant: "default".into(),
                provider_subject: "u".into(),
                email: None,
                email_verified: false,
                roles: vec![],
                assurance: AuthenticationAssurance::local_password(),
                auth_epoch: 0,
                webauthn_step_up: false,
            })
            .unwrap();
        let mut bad = minted.token.clone();
        bad.push('x');
        assert!(m.verify(&bad).is_err());
    }

    #[test]
    fn jwks_advertises_our_kid_and_es256() {
        let m = minter();
        let jwks = m.jwks().as_json();
        let key = &jwks["keys"][0];
        assert_eq!(key["kid"], "test-kid");
        assert_eq!(key["alg"], "ES256");
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["use"], "sig");
    }

    #[test]
    fn future_nbf_is_rejected_even_when_the_claim_is_present() {
        let m = minter();
        let mut claims = m
            .verify(
                &m.mint(context(AuthenticationAssurance::local_password()))
                    .unwrap()
                    .token,
            )
            .unwrap();
        let now = now_secs();
        claims.nbf = now + 3600;
        claims.iat = now;
        claims.exp = now + 7200;
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some("test-kid".into());
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_ec_pem(signing_pem().as_bytes()).unwrap(),
        )
        .unwrap();
        assert!(m.verify(&token).is_err());
    }
}
