//! Supabase Send Email Hook backed by SendGrid.
//!
//! Supabase remains the credential/session authority and supplies the numeric
//! OTP. This handler verifies the Standard Webhooks signature over the exact raw
//! payload, then sends only that code. Redirect URLs, action links, and token
//! hashes are deliberately ignored.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine,
};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;

use crate::{error::AuthError, state::AppState};

use super::local::normalize_email;

const MAX_CLOCK_SKEW_SECS: i64 = 300;
const MAX_WEBHOOK_ID_BYTES: usize = 256;

#[derive(Debug, Deserialize)]
struct SendEmailHookPayload {
    user: HookUser,
    email_data: EmailData,
}

#[derive(Debug, Deserialize)]
struct HookUser {
    email: String,
    #[serde(default)]
    new_email: String,
}

#[derive(Debug, Deserialize)]
struct EmailData {
    token: String,
    #[serde(default)]
    token_new: String,
    email_action_type: String,
}

#[derive(Debug, Eq, PartialEq)]
struct Delivery {
    recipient: String,
    code: String,
}

pub async fn send_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), AuthError> {
    let secret = std::env::var("AUTH_SUPABASE_SEND_EMAIL_HOOK_SECRET")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(AuthError::Unavailable)?;
    verify_standard_webhook(&headers, &body, &secret)?;

    let payload: SendEmailHookPayload =
        serde_json::from_slice(&body).map_err(|_| AuthError::BadRequest("invalid hook payload"))?;
    let deliveries = deliveries_for(payload)?;

    for delivery in deliveries {
        crate::email::send_sign_in_code(
            &state.http,
            &state.config.magic_links,
            &delivery.recipient,
            &delivery.code,
        )
        .await?;
    }

    Ok((StatusCode::OK, Json(json!({}))))
}

fn deliveries_for(payload: SendEmailHookPayload) -> Result<Vec<Delivery>, AuthError> {
    let current_email = normalize_email(&payload.user.email)?;
    let action = payload.email_data.email_action_type.trim();
    if action.is_empty() || action.len() > 64 {
        return Err(AuthError::BadRequest("invalid email action type"));
    }

    if action != "email_change" {
        validate_code(&payload.email_data.token)?;
        return Ok(vec![Delivery {
            recipient: current_email,
            code: payload.email_data.token,
        }]);
    }

    let new_email = normalize_email(&payload.user.new_email)?;
    let token = payload.email_data.token.trim();
    let token_new = payload.email_data.token_new.trim();

    // Secure Email Change supplies both OTPs. Supabase's field names are
    // counterintuitive: `token` belongs to the current address and
    // `token_new` belongs to the new address.
    if !token.is_empty() && !token_new.is_empty() {
        validate_code(token)?;
        validate_code(token_new)?;
        return Ok(vec![
            Delivery {
                recipient: current_email,
                code: token.to_owned(),
            },
            Delivery {
                recipient: new_email,
                code: token_new.to_owned(),
            },
        ]);
    }

    // Non-secure Email Change supplies one OTP for the new address. Depending
    // on the Auth version, it can appear in either token field.
    let code = if !token_new.is_empty() {
        token_new
    } else {
        token
    };
    validate_code(code)?;
    Ok(vec![Delivery {
        recipient: new_email,
        code: code.to_owned(),
    }])
}

pub(crate) fn verify_standard_webhook(
    headers: &HeaderMap,
    body: &[u8],
    configured_secret: &str,
) -> Result<(), AuthError> {
    let webhook_id = required_header(headers, "webhook-id")?;
    if webhook_id.is_empty() || webhook_id.len() > MAX_WEBHOOK_ID_BYTES {
        return Err(AuthError::Unauthorized);
    }
    let timestamp_text = required_header(headers, "webhook-timestamp")?;
    let timestamp = timestamp_text
        .parse::<i64>()
        .map_err(|_| AuthError::Unauthorized)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::Unauthorized)?
        .as_secs() as i64;
    if timestamp < 0 {
        return Err(AuthError::Unauthorized);
    }
    let skew = if now >= timestamp {
        now - timestamp
    } else {
        timestamp - now
    };
    if skew > MAX_CLOCK_SKEW_SECS {
        return Err(AuthError::Unauthorized);
    }

    let key = decode_webhook_secret(configured_secret)?;
    let mut found_versioned_signature = false;
    for value in headers.get_all("webhook-signature").iter() {
        let value = value.to_str().map_err(|_| AuthError::Unauthorized)?;
        for candidate in value.split_whitespace() {
            let Some(encoded) = candidate.strip_prefix("v1,") else {
                continue;
            };
            found_versioned_signature = true;
            let Ok(signature) = decode_base64(encoded) else {
                continue;
            };
            let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| AuthError::Internal)?;
            mac.update(webhook_id.as_bytes());
            mac.update(b".");
            mac.update(timestamp_text.as_bytes());
            mac.update(b".");
            mac.update(body);
            if mac.verify_slice(&signature).is_ok() {
                return Ok(());
            }
        }
    }
    if !found_versioned_signature {
        tracing::warn!("Supabase email hook omitted a v1 signature");
    }
    Err(AuthError::Unauthorized)
}

fn decode_webhook_secret(configured: &str) -> Result<Vec<u8>, AuthError> {
    let encoded = configured
        .trim()
        .strip_prefix("v1,")
        .unwrap_or(configured.trim())
        .strip_prefix("whsec_")
        .ok_or(AuthError::Unavailable)?;
    let decoded = decode_base64(encoded).map_err(|_| AuthError::Unavailable)?;
    if decoded.len() < 32 {
        return Err(AuthError::Unavailable);
    }
    Ok(decoded)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value))
}

fn required_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, AuthError> {
    headers
        .get(name)
        .ok_or(AuthError::Unauthorized)?
        .to_str()
        .map(str::trim)
        .map_err(|_| AuthError::Unauthorized)
}

fn validate_code(code: &str) -> Result<(), AuthError> {
    if code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(())
    } else {
        Err(AuthError::BadRequest(
            "Supabase email token must contain six digits",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(
        action: &str,
        token: &str,
        token_new: &str,
        new_email: &str,
    ) -> SendEmailHookPayload {
        SendEmailHookPayload {
            user: HookUser {
                email: "current@example.com".into(),
                new_email: new_email.into(),
            },
            email_data: EmailData {
                token: token.into(),
                token_new: token_new.into(),
                email_action_type: action.into(),
            },
        }
    }

    #[test]
    fn normal_actions_send_one_code_to_the_current_email() {
        assert_eq!(
            deliveries_for(payload("signup", "123456", "", "")).unwrap(),
            vec![Delivery {
                recipient: "current@example.com".into(),
                code: "123456".into(),
            }]
        );
    }

    #[test]
    fn secure_email_change_maps_both_codes_to_the_correct_address() {
        assert_eq!(
            deliveries_for(payload(
                "email_change",
                "111111",
                "222222",
                "new@example.com",
            ))
            .unwrap(),
            vec![
                Delivery {
                    recipient: "current@example.com".into(),
                    code: "111111".into(),
                },
                Delivery {
                    recipient: "new@example.com".into(),
                    code: "222222".into(),
                },
            ]
        );
    }

    #[test]
    fn non_secure_email_change_targets_only_the_new_address() {
        assert_eq!(
            deliveries_for(payload("email_change", "333333", "", "new@example.com")).unwrap(),
            vec![Delivery {
                recipient: "new@example.com".into(),
                code: "333333".into(),
            }]
        );
    }

    #[test]
    fn standard_webhook_signature_is_verified_over_the_raw_body() {
        let key = [7_u8; 32];
        let secret = format!("v1,whsec_{}", STANDARD.encode(key));
        let body = br#"{"user":{"email":"person@example.com"}}"#;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let webhook_id = "msg_test_123";

        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(webhook_id.as_bytes());
        mac.update(b".");
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(body);
        let signature = STANDARD.encode(mac.finalize().into_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("webhook-id", webhook_id.parse().unwrap());
        headers.insert("webhook-timestamp", timestamp.parse().unwrap());
        headers.insert(
            "webhook-signature",
            format!("v1,{signature}").parse().unwrap(),
        );

        assert!(verify_standard_webhook(&headers, body, &secret).is_ok());
        assert!(matches!(
            verify_standard_webhook(&headers, br#"{"tampered":true}"#, &secret),
            Err(AuthError::Unauthorized)
        ));
    }

    #[test]
    fn malformed_or_short_hook_secrets_fail_closed() {
        assert!(matches!(
            decode_webhook_secret("not-a-standard-webhook-secret"),
            Err(AuthError::Unavailable)
        ));
        assert!(matches!(
            decode_webhook_secret(&format!("v1,whsec_{}", STANDARD.encode([1_u8; 8]))),
            Err(AuthError::Unavailable)
        ));
    }
}
