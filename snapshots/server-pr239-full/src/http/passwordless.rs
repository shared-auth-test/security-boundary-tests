//! RDS-backed passwordless email-code login.
//!
//! Requests are enumeration-resistant: a syntactically valid address always
//! receives `202 Accepted`, whether or not signup is enabled or a matching
//! account exists. The six-digit OTP is single-use. Legacy bearer-link tokens
//! are not accepted by the JSON API or by the retained browser compatibility
//! handler.

use axum::{extract::State, http::StatusCode, Json};
use chrono::TimeDelta;
use serde::{Deserialize, Serialize};

use crate::db::AuthenticatedIdentity;
use crate::error::AuthError;
use crate::session::{hash_otp, hashed_identifier, MagicLinkToken};
use crate::state::AppState;

use super::local::{enforce_limit, normalize_email, response_from_issued, SessionResponse};

#[derive(Deserialize)]
pub struct PasswordlessRequest {
    email: String,
}

#[derive(Serialize)]
pub struct PasswordlessAccepted {
    accepted: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordlessConsumeRequest {
    email: String,
    otp: String,
}

pub async fn request(
    State(state): State<AppState>,
    Json(request): Json<PasswordlessRequest>,
) -> Result<(StatusCode, Json<PasswordlessAccepted>), AuthError> {
    request_magic_link(&state, &request.email).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(PasswordlessAccepted { accepted: true }),
    ))
}

/// Creates the durable passwordless challenge and sends only its numeric code.
///
/// The name is retained for source compatibility with the first-party browser
/// module. `_link_state` is intentionally ignored: no callback state or action
/// URL is ever sent in a new email.
pub(crate) async fn request_magic_link(
    state: &AppState,
    raw_email: &str,
) -> Result<String, AuthError> {
    if !passwordless_email_otp_is_enabled(state) {
        return Err(AuthError::Unavailable);
    }
    let db = state.db.as_ref().ok_or(AuthError::Unavailable)?;
    let email = normalize_email(raw_email)?;
    // The identifier is hashed inside the limiter. This throttles repeated mail
    // sends without disclosing account existence or placing raw email addresses
    // in Redis keys/logs.
    enforce_limit(state, "passwordless", &email, 5, 900).await?;
    let token = MagicLinkToken::generate();
    let identifier_hash = hashed_identifier(&email);
    let pepper = state
        .config
        .magic_links
        .otp_pepper
        .as_deref()
        .ok_or(AuthError::Unavailable)?;
    let otp_hash = hash_otp(pepper, &email, &token.otp);
    let expires_at = chrono::Utc::now().fixed_offset()
        + TimeDelta::seconds(state.config.magic_links.ttl_secs as i64);
    let should_send = db
        .prepare_magic_link(
            &email,
            state.config.magic_links.allow_signup,
            &token.hash,
            &otp_hash,
            &identifier_hash,
            expires_at,
        )
        .await?;
    if should_send {
        crate::email::send_email_otp(&state.http, &state.config.magic_links, &email, &token.otp)
            .await?;
    }
    Ok(email)
}

pub async fn consume(
    State(state): State<AppState>,
    Json(request): Json<PasswordlessConsumeRequest>,
) -> Result<Json<SessionResponse>, AuthError> {
    let identity = consume_email_otp_identity(&state, &request.email, &request.otp).await?;
    Ok(Json(response_from_issued(&state, identity).await?))
}

/// Fail closed for the retired bearer-link compatibility handler.
///
/// The browser route is removed by the full DEN-4035 cleanup. Keeping this
/// symbol temporarily lets the independently reviewable security slice land on
/// top of the moving authentication branch without permitting a URL token to
/// mint a session in the meantime.
pub(crate) async fn consume_magic_link_identity(
    _state: &AppState,
    _token: &str,
) -> Result<AuthenticatedIdentity, AuthError> {
    Err(AuthError::Unauthorized)
}

pub(crate) async fn consume_email_otp_identity(
    state: &AppState,
    raw_email: &str,
    otp: &str,
) -> Result<AuthenticatedIdentity, AuthError> {
    if otp.len() != 6 || !otp.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AuthError::BadRequest("email otp must contain six digits"));
    }
    let db = state.db.as_ref().ok_or(AuthError::Unavailable)?;
    let email = normalize_email(raw_email)?;
    let pepper = state
        .config
        .magic_links
        .otp_pepper
        .as_deref()
        .ok_or(AuthError::Unavailable)?;
    db.consume_email_otp(&hashed_identifier(&email), &hash_otp(pepper, &email, otp))
        .await
}

fn passwordless_email_otp_is_enabled(state: &AppState) -> bool {
    state
        .config
        .magic_links
        .sendgrid_api_key
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && state
            .config
            .magic_links
            .otp_pepper
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        && state
            .config
            .magic_links
            .from_email
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_body_accepts_only_email_and_otp() {
        let otp: PasswordlessConsumeRequest =
            serde_json::from_str(r#"{"email":"user@example.com","otp":"123456"}"#).unwrap();
        assert_eq!(otp.email, "user@example.com");
        assert_eq!(otp.otp, "123456");

        assert!(serde_json::from_str::<PasswordlessConsumeRequest>(
            r#"{"token":"sat_magic_example"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<PasswordlessConsumeRequest>(
            r#"{"email":"user@example.com","otp":"123456","token":"sat_magic_example"}"#
        )
        .is_err());
    }
}
