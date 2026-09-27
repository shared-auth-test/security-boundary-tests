//! SSH public-key registration and the non-interactive handshake.
//!
//! Registration is a control-plane operation and is gated on an interactive
//! session at LOA2. Authentication is unauthenticated by construction — the key
//! *is* the credential — and is bounded by the per-key open-challenge ceiling in
//! [`crate::pubkey::store`] rather than by a caller's identity.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::AuthenticatedIdentity;
use crate::error::AuthError;
use crate::pubkey::{
    store::{RegisteredKey, MAX_TOKEN_TTL_SECS},
    PublicKeyService, SshPublicKey, SshSignature, AMR_SSH_KEY, SANDBOX_NAMESPACE,
};
use crate::session::RefreshToken;
use crate::state::AppState;
use crate::token::{SandboxMintContext, ACR_LOA2};

use super::bearer;
use super::introspect::active_claims;

/// Registering a credential must not outlive the ceremony that authorized it.
/// The same freshness window the delegation policy defaults to: an AAL2 session
/// several minutes old can browse, but it cannot mint new long-lived authority.
const MAX_CONTROL_PLANE_AUTH_AGE_SECS: u64 = 600;
const MAX_CLOCK_SKEW_SECS: u64 = 60;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    /// One `authorized_keys` line, exactly as `~/.ssh/id_ed25519.pub` contains.
    public_key: String,
    /// The audience tokens from this key will target. Required: a sandboxed
    /// token must never carry the base shared-auth audience, so there is no
    /// safe default to fall back to.
    audience: String,
    scopes: Vec<String>,
    #[serde(default)]
    token_ttl_secs: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    fingerprint: String,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    challenge_id: String,
    /// The exact bytes to sign. Handing back the whole message, rather than a
    /// nonce the client assembles into a message, removes any chance of the two
    /// sides disagreeing about what was signed.
    message: String,
    namespace: &'static str,
    expires_at: String,
    /// The command that produces an acceptable signature, so the contract is
    /// discoverable from the response rather than only from the docs.
    sign_with: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    challenge_id: String,
    /// Armored `SSHSIG` (`-----BEGIN SSH SIGNATURE-----`) or its bare base64.
    signature: String,
}

#[derive(Serialize)]
pub struct SandboxTokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_at: u64,
    audience: String,
    scope: String,
    amr: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acr: Option<String>,
}

/// The gate for key management. Three requirements, each closing a distinct
/// bootstrap path:
///
/// - **not sandboxed** — a key cannot register another key;
/// - **LOA2** — possession of a bearer token alone cannot grow credentials;
/// - **fresh `auth_time`** — a step-up from this morning does not authorize new
///   long-lived authority now. The window matches the delegation policy default
///   for sensitive scopes, and a missing or future `auth_time` fails closed.
fn require_fresh_control_plane_session(claims: &crate::token::OreClaims) -> Result<(), AuthError> {
    if claims.is_sandboxed() || !claims.has_acr(ACR_LOA2) {
        return Err(AuthError::Forbidden);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let Some(auth_time) = claims.auth_time else {
        return Err(AuthError::Forbidden);
    };
    if now == 0
        || auth_time > now.saturating_add(MAX_CLOCK_SKEW_SECS)
        || now.saturating_sub(auth_time) > MAX_CONTROL_PLANE_AUTH_AGE_SECS
    {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}

/// Register a key. Requires a fresh interactive session at LOA2: adding a
/// credential is exactly the control-plane act that tokens minted from this
/// plane are forbidden to perform, so it cannot be bootstrapped by a key.
pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisteredKey>), AuthError> {
    let claims = active_claims(&state, bearer(&headers).ok_or(AuthError::Unauthorized)?).await?;
    require_fresh_control_plane_session(&claims)?;
    let shared_user_id =
        Uuid::parse_str(&claims.sub).map_err(|_| AuthError::BadRequest("invalid subject"))?;
    let service = service(&state)?;

    let key = SshPublicKey::parse(&request.public_key).map_err(|error| {
        // The reason is safe to surface: it is about the key the caller just
        // pasted, and a precise message is the difference between a two-minute
        // fix and a support ticket.
        tracing::info!(%error, "rejected an SSH public key at registration");
        AuthError::BadRequest("unsupported or malformed public key")
    })?;

    let registered = service
        .register(
            shared_user_id,
            &key,
            &request.audience,
            &request.scopes,
            request.token_ttl_secs.unwrap_or(MAX_TOKEN_TTL_SECS),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(registered)))
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<RegisteredKey>>, AuthError> {
    let claims = active_claims(&state, bearer(&headers).ok_or(AuthError::Unauthorized)?).await?;
    if claims.is_sandboxed() {
        return Err(AuthError::Forbidden);
    }
    let shared_user_id =
        Uuid::parse_str(&claims.sub).map_err(|_| AuthError::BadRequest("invalid subject"))?;
    Ok(Json(service(&state)?.list(shared_user_id).await?))
}

/// Remove a key and revoke the tokens it minted. LOA2 for the same reason
/// registration needs it — losing a credential silently is as bad as gaining one.
pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_key_id): Path<String>,
) -> Result<StatusCode, AuthError> {
    let claims = active_claims(&state, bearer(&headers).ok_or(AuthError::Unauthorized)?).await?;
    require_fresh_control_plane_session(&claims)?;
    let shared_user_id =
        Uuid::parse_str(&claims.sub).map_err(|_| AuthError::BadRequest("invalid subject"))?;
    let public_key_id =
        Uuid::parse_str(&raw_key_id).map_err(|_| AuthError::BadRequest("invalid key id"))?;
    service(&state)?
        .revoke(shared_user_id, public_key_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn challenge(
    State(state): State<AppState>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, AuthError> {
    // Redis-backed limiter in front of the durable per-key ceiling. The
    // fingerprint is already a hash of public material, which is what the
    // cache layer requires of identifiers. On Redis loss this degrades to the
    // Postgres cap alone — cache is never the authority.
    if let Some(cache) = &state.cache {
        match cache
            .allow("ssh_challenge", &request.fingerprint, 10, 60)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                count_handshake(&state, "challenge", "rate_limited");
                return Err(AuthError::RateLimited);
            }
            Err(error) => {
                tracing::warn!(%error, "Redis unavailable for ssh challenge rate limit");
            }
        }
    }

    let issued = match service(&state)?.open_challenge(&request.fingerprint).await {
        Ok(issued) => issued,
        Err(error) => {
            count_handshake(&state, "challenge", "rejected");
            return Err(error);
        }
    };
    count_handshake(&state, "challenge", "ok");
    Ok(Json(ChallengeResponse {
        challenge_id: issued.challenge_id.to_string(),
        message: issued.message,
        namespace: SANDBOX_NAMESPACE,
        expires_at: issued.expires_at.to_rfc3339(),
        sign_with: "ssh-keygen -Y sign -n <namespace> -f <private key> <message file>",
    }))
}

/// Complete the handshake: verify the signature, open a revocable session, and
/// mint the sandboxed token.
pub async fn verify(
    State(state): State<AppState>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<SandboxTokenResponse>, AuthError> {
    let challenge_id = Uuid::parse_str(&request.challenge_id)
        .map_err(|_| AuthError::BadRequest("invalid challenge id"))?;
    let signature = SshSignature::parse(&request.signature).map_err(|error| {
        tracing::info!(%error, "rejected a malformed SSH signature");
        AuthError::Unauthorized
    })?;
    let service = service(&state)?;
    let db = state.db.as_ref().ok_or(AuthError::Unavailable)?;

    let verified = match service.verify_challenge(challenge_id, &signature).await {
        Ok(verified) => verified,
        Err(error) => {
            count_handshake(&state, "verify", "rejected");
            return Err(error);
        }
    };

    // The session exists so the token can be revoked, not so it can be
    // refreshed: the refresh secret is generated, hashed, and dropped without
    // ever leaving this function, and the row expires with the token it backs.
    let refresh = RefreshToken::generate();
    let expires_at =
        chrono::Utc::now().fixed_offset() + TimeDelta::seconds(i64::from(verified.token_ttl_secs));
    let session = db
        .create_session(
            AuthenticatedIdentity {
                shared_user_id: verified.shared_user_id,
                provider: AMR_SSH_KEY.to_owned(),
                provider_tenant: "default".to_owned(),
                provider_subject: verified.fingerprint.clone(),
                email: None,
                email_verified: false,
                roles: Vec::new(),
            },
            &refresh.hash,
            expires_at,
            None,
            1,
            &[AMR_SSH_KEY.to_owned()],
        )
        .await?;

    // Without the binding, deleting the key would not reach this session, and
    // the token would outlive the credential that produced it. Revoke and fail
    // rather than issue something unrevocable.
    if let Err(error) = service
        .bind_session(
            session.session_id,
            verified.public_key_id,
            verified.shared_user_id,
        )
        .await
    {
        let _ = db.revoke_by_session_id(session.session_id).await;
        return Err(error);
    }

    let minted = state.minter.mint_sandboxed(SandboxMintContext {
        shared_user_id: verified.shared_user_id.to_string(),
        session_id: session.session_id,
        credential_class: AMR_SSH_KEY,
        credential_reference: verified.fingerprint,
        audience: verified.audience.clone(),
        scopes: verified.scopes.clone(),
        ttl_secs: u64::from(verified.token_ttl_secs),
    });
    let minted = match minted {
        Ok(minted) => minted,
        Err(error) => {
            // A stored row that no longer satisfies mint-time policy must not
            // leave a live session behind.
            let _ = db.revoke_by_session_id(session.session_id).await;
            return Err(error);
        }
    };

    count_handshake(&state, "verify", "ok");
    Ok(Json(SandboxTokenResponse {
        access_token: minted.token,
        token_type: "Bearer",
        expires_at: minted.expires_at,
        audience: verified.audience,
        scope: verified.scopes.join(" "),
        amr: minted.amr,
        acr: minted.acr,
    }))
}

fn service(state: &AppState) -> Result<&PublicKeyService, AuthError> {
    state.pubkeys.as_ref().ok_or(AuthError::Unavailable)
}

fn count_handshake(state: &AppState, stage: &str, outcome: &str) {
    state
        .metrics
        .ssh_handshakes
        .with_label_values(&[stage, outcome])
        .inc();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{OreClaims, ACR_LOA1};

    fn loa2_claims(auth_time: Option<u64>) -> OreClaims {
        OreClaims {
            sub: uuid::Uuid::from_u128(1).to_string(),
            iss: "https://auth.test".into(),
            aud: "oresoftware".into(),
            iat: 0,
            exp: u64::MAX,
            nbf: 0,
            jti: "j".into(),
            sid: Some("s".into()),
            provider: "local".into(),
            provider_tenant: "default".into(),
            provider_subject: "u".into(),
            project: None,
            supabase_user_id: None,
            email: None,
            email_verified: false,
            roles: vec![],
            aal: 2,
            amr: vec!["pwd".into(), "totp".into()],
            acr: Some(ACR_LOA2.to_owned()),
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

    // The control-plane gate is the difference between "a stolen AAL2 bearer
    // can add a backdoor key" and "it cannot". Each rejected shape below is a
    // distinct bootstrap path.
    #[test]
    fn key_management_requires_a_fresh_interactive_loa2_ceremony() {
        // Fresh LOA2: allowed.
        assert!(require_fresh_control_plane_session(&loa2_claims(Some(now()))).is_ok());

        // Stale ceremony: the step-up happened this morning.
        assert!(require_fresh_control_plane_session(&loa2_claims(Some(
            now() - MAX_CONTROL_PLANE_AUTH_AGE_SECS - 1
        )))
        .is_err());

        // Missing auth_time fails closed rather than counting as fresh.
        assert!(require_fresh_control_plane_session(&loa2_claims(None)).is_err());

        // auth_time from the future beyond skew is a forged or broken clock.
        assert!(require_fresh_control_plane_session(&loa2_claims(Some(
            now() + MAX_CLOCK_SKEW_SECS + 30
        )))
        .is_err());

        // LOA1 never manages keys, however fresh.
        let mut base = loa2_claims(Some(now()));
        base.acr = Some(ACR_LOA1.to_owned());
        base.aal = 1;
        assert!(require_fresh_control_plane_session(&base).is_err());

        // A sandboxed token never manages keys — a key cannot mint a key.
        let mut sandboxed = loa2_claims(Some(now()));
        sandboxed.cred = Some("ssh_key".into());
        assert!(require_fresh_control_plane_session(&sandboxed).is_err());
    }
}
