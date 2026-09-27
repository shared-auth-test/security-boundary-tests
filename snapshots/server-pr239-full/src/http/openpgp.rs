//! OpenPGP provenance API.
//!
//! Key enrollment is an authenticated control-plane operation. Detached
//! verification is a service-to-service provenance query authenticated with the
//! independent introspection credential. Neither path creates a login session,
//! token, role, or assurance claim.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, KeyInit, Mac};
use rand::{rngs::SysRng, TryRng};
use serde::Deserialize;
use sha2::Sha256;
use uuid::Uuid;

use crate::error::AuthError;
use crate::openpgp::{OpenPgpBinding, OpenPgpService, ProvenanceVerification};
use crate::state::AppState;
use crate::token::ACR_LOA2;

use super::bearer;
use super::introspect::active_claims;

const MAX_CONTROL_PLANE_AUTH_AGE_SECS: u64 = 600;
const MAX_CLOCK_SKEW_SECS: u64 = 60;
const MAX_ENCODED_PAYLOAD_BYTES: usize = 72 * 1024;
const MAX_PAYLOAD_BYTES: usize = 48 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    armored_public_key: String,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    primary_fingerprint: String,
    payload_base64: String,
    armored_signature: String,
}

pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<OpenPgpBinding>), AuthError> {
    let claims = active_claims(&state, bearer(&headers).ok_or(AuthError::Unauthorized)?).await?;
    require_fresh_control_plane_session(&claims)?;
    let shared_user_id = Uuid::parse_str(&claims.sub).map_err(|_| AuthError::Unauthorized)?;
    let binding = service(&state)?
        .register(
            shared_user_id,
            &request.armored_public_key,
            request.label.as_deref(),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(binding)))
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<OpenPgpBinding>>, AuthError> {
    let claims = active_claims(&state, bearer(&headers).ok_or(AuthError::Unauthorized)?).await?;
    if claims.is_delegated() {
        return Err(AuthError::Forbidden);
    }
    let shared_user_id = Uuid::parse_str(&claims.sub).map_err(|_| AuthError::Unauthorized)?;
    Ok(Json(service(&state)?.list(shared_user_id).await?))
}

pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_binding_id): Path<String>,
) -> Result<StatusCode, AuthError> {
    let claims = active_claims(&state, bearer(&headers).ok_or(AuthError::Unauthorized)?).await?;
    require_fresh_control_plane_session(&claims)?;
    let shared_user_id = Uuid::parse_str(&claims.sub).map_err(|_| AuthError::Unauthorized)?;
    let binding_id = Uuid::parse_str(&raw_binding_id)
        .map_err(|_| AuthError::BadRequest("invalid binding id"))?;
    service(&state)?
        .revoke(shared_user_id, binding_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<ProvenanceVerification>, AuthError> {
    authorize_service_credential(
        state.config.introspect_secret.as_deref(),
        bearer(&headers),
    )?;
    if request.payload_base64.len() > MAX_ENCODED_PAYLOAD_BYTES {
        return Err(AuthError::BadRequest("payload too large"));
    }
    let payload = STANDARD
        .decode(request.payload_base64.as_bytes())
        .map_err(|_| AuthError::BadRequest("payload must be standard base64"))?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(AuthError::BadRequest("payload too large"));
    }

    let verification = service(&state)?
        .verify_detached(
            &request.primary_fingerprint,
            &payload,
            &request.armored_signature,
        )
        .await?;
    Ok(Json(verification))
}

fn require_fresh_control_plane_session(
    claims: &crate::token::OreClaims,
) -> Result<(), AuthError> {
    if claims.is_delegated() || !claims.has_acr(ACR_LOA2) {
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

/// Keep provenance verification behind the same independent service credential
/// as introspection without exposing the helper across HTTP modules. A caller
/// holding only an end-user token cannot ask the service to map a certificate
/// to a complete Shared Auth principal.
fn authorize_service_credential(
    expected: Option<&str>,
    presented: Option<&str>,
) -> Result<(), AuthError> {
    let expected = expected.ok_or(AuthError::Unauthorized)?;
    let presented = presented.ok_or(AuthError::Unauthorized)?;
    if credentials_match(expected, presented) {
        Ok(())
    } else {
        Err(AuthError::Unauthorized)
    }
}

fn credentials_match(expected: &str, presented: &str) -> bool {
    let mut key = [0u8; 32];
    if SysRng.try_fill_bytes(&mut key).is_err() {
        return false;
    }
    let tag = |data: &[u8]| {
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(&key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes()
    };
    tag(expected.as_bytes()) == tag(presented.as_bytes())
}

fn service(state: &AppState) -> Result<&OpenPgpService, AuthError> {
    state.openpgp.as_ref().ok_or(AuthError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::{authorize_service_credential, require_fresh_control_plane_session};
    use crate::token::OreClaims;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn claims(aal: u8, acr: Option<&str>, auth_time: Option<u64>, scope: &str) -> OreClaims {
        OreClaims {
            iss: "issuer".into(),
            sub: "00000000-0000-0000-0000-000000000001".into(),
            aud: "audience".into(),
            exp: u64::MAX,
            iat: 1,
            nbf: 1,
            jti: "jti".into(),
            auth_time,
            sid: Some("00000000-0000-0000-0000-000000000002".into()),
            provider: "local".into(),
            provider_tenant: "default".into(),
            provider_subject: "subject".into(),
            project: None,
            supabase_user_id: None,
            email: None,
            email_verified: false,
            roles: Vec::new(),
            aal,
            amr: vec!["pwd".into(), "totp".into()],
            acr: acr.map(ToOwned::to_owned),
            scope: scope.into(),
            azp: None,
            parent_jti: None,
        }
    }

    #[test]
    fn provenance_key_management_rejects_delegated_authority() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let delegated = claims(2, Some("urn:oresoftware:loa:2"), Some(now), "sandbox:gpg");
        assert!(require_fresh_control_plane_session(&delegated).is_err());
    }

    #[test]
    fn provenance_verification_requires_the_independent_service_secret() {
        assert!(authorize_service_credential(None, Some(SECRET)).is_err());
        assert!(authorize_service_credential(Some(SECRET), None).is_err());
        assert!(authorize_service_credential(Some(SECRET), Some("wrong")).is_err());
        assert!(authorize_service_credential(Some(SECRET), Some(SECRET)).is_ok());
    }
}
