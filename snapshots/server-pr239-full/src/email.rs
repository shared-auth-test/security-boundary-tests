//! OTP-only SendGrid delivery for passwordless and Supabase Auth email flows.
//!
//! The raw six-digit code is never logged or stored by this module. No action
//! link, callback URL, token hash, or redirect target is placed in either the
//! plain-text or HTML message.

use serde_json::json;

use crate::config::MagicLinkConfig;
use crate::error::AuthError;

const SENDGRID_MAIL_SEND_URL: &str = "https://api.sendgrid.com/v3/mail/send";

pub async fn send_email_otp(
    http: &reqwest::Client,
    config: &MagicLinkConfig,
    recipient: &str,
    otp: &str,
) -> Result<(), AuthError> {
    send_email_otp_to(http, config, SENDGRID_MAIL_SEND_URL, recipient, otp).await
}

/// Provider-hook spelling retained for the Supabase Send Email Hook. Both
/// authorities deliberately share the exact same branded, link-free message.
pub async fn send_sign_in_code(
    http: &reqwest::Client,
    config: &MagicLinkConfig,
    recipient: &str,
    otp: &str,
) -> Result<(), AuthError> {
    send_email_otp(http, config, recipient, otp).await
}

async fn send_email_otp_to(
    http: &reqwest::Client,
    config: &MagicLinkConfig,
    endpoint: &str,
    recipient: &str,
    otp: &str,
) -> Result<(), AuthError> {
    let api_key = required_nonempty(config.sendgrid_api_key.as_deref())?;
    let from_email = required_nonempty(config.from_email.as_deref())?;
    let brand = validated_brand(&config.from_name)?;
    validate_otp(otp)?;

    let escaped_brand = escape_html(brand);
    let ttl_minutes = (config.ttl_secs / 60).max(1);
    let text = format!(
        "Your {brand} sign-in code is {otp}.\n\n\
         This one-time code expires in {ttl_minutes} minutes. If you did not \
         request it, you can safely ignore this email."
    );
    let html = format!(
        "<!doctype html><html><body style=\"margin:0;background:#f5f7fb;font-family:Arial,sans-serif;color:#172033\">\
         <table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"background:#f5f7fb;padding:32px 16px\"><tr><td align=\"center\">\
         <table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"max-width:560px;background:#fff;border:1px solid #e3e8f2;border-radius:16px;padding:36px\">\
         <tr><td style=\"font-size:14px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#6554c0\">{escaped_brand}</td></tr>\
         <tr><td style=\"padding-top:18px;font-size:28px;font-weight:700\">Your sign-in code</td></tr>\
         <tr><td style=\"padding-top:12px;font-size:16px;line-height:1.6;color:#4c5870\">Enter this six-digit code to sign in.</td></tr>\
         <tr><td align=\"center\" style=\"padding:28px 0 24px\"><div style=\"display:inline-block;padding:16px 22px;border-radius:12px;background:#f0edff;font-family:monospace;font-size:32px;font-weight:700;letter-spacing:.22em;color:#4936a8\">{otp}</div></td></tr>\
         <tr><td style=\"font-size:14px;line-height:1.6;color:#69758b\">This code expires in {ttl_minutes} minutes and can be used only once. {escaped_brand} support will never ask you to share it. This email deliberately contains no sign-in link.</td></tr>\
         </table></td></tr></table></body></html>"
    );
    let payload = json!({
        "personalizations": [{
            "to": [{ "email": recipient }]
        }],
        "from": {
            "email": from_email,
            "name": brand
        },
        "subject": format!("Your {brand} sign-in code"),
        "content": [
            { "type": "text/plain", "value": text },
            { "type": "text/html", "value": html }
        ]
    });

    let response = http
        .post(endpoint)
        .bearer_auth(api_key)
        .json(&payload)
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(%error, "SendGrid email-OTP request failed");
            AuthError::Upstream
        })?;
    if response.status() != reqwest::StatusCode::ACCEPTED {
        tracing::warn!(
            status = response.status().as_u16(),
            "SendGrid rejected email-OTP message"
        );
        return Err(AuthError::Upstream);
    }
    Ok(())
}

fn required_nonempty(value: Option<&str>) -> Result<&str, AuthError> {
    value
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
        .ok_or(AuthError::Unavailable)
}

fn validated_brand(value: &str) -> Result<&str, AuthError> {
    let brand = value.trim();
    if brand.is_empty() || brand.len() > 80 || brand.chars().any(char::is_control) {
        Err(AuthError::Unavailable)
    } else {
        Ok(brand)
    }
}

fn validate_otp(otp: &str) -> Result<(), AuthError> {
    if otp.len() == 6 && otp.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(())
    } else {
        Err(AuthError::BadRequest(
            "verification code must contain six digits",
        ))
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
#[path = "email_tests.rs"]
mod tests;
