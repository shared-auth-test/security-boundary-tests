//! Deterministic Supabase session issuance for isolated automated test realms.
//!
//! This endpoint is disabled by default and fails closed unless every guard is
//! present: an explicitly test-scoped deployment, an exact `*-test` Supabase
//! project and issuer, a separate bearer secret, fail-closed rate limiting, and
//! an exact synthetic identity allowlist. It uses Supabase's admin
//! `generate_link` endpoint only to mint a real single-use OTP, then immediately
//! verifies that OTP with Supabase. No service-role/secret key ever reaches a
//! Flutter or browser client.

use std::{
    collections::HashMap,
    fmt::Write as _,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::Method;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use url::Url;
use uuid::Uuid;

use crate::{
    config::{AppConfig, SupabaseProject},
    error::AuthError,
    state::AppState,
};

use super::{
    bearer,
    local::{enforce_limit, normalize_email},
    supabase_hooks::verify_standard_webhook,
};

const DEFAULT_TEST_CODE: &str = "424242";
const MIN_BEARER_SECRET_BYTES: usize = 32;
const CAPTURED_SMS_TTL_SECS: u64 = 300;
const MAX_CAPTURED_SMS_ENTRIES: usize = 64;

#[derive(Clone)]
struct CapturedSmsOtp {
    code: String,
    captured_at: u64,
}

type SmsOtpKey = (Uuid, String);
type SmsOtpStore = HashMap<SmsOtpKey, CapturedSmsOtp>;

static CAPTURED_SMS_OTPS: OnceLock<Mutex<SmsOtpStore>> = OnceLock::new();

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestSessionRequest {
    email: String,
    code: String,
    project: String,
    #[serde(default)]
    assurance: TestAssurance,
    #[serde(default)]
    phone: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TestAssurance {
    #[default]
    Aal1,
    Aal2Totp,
    Aal2Phone,
}

impl TestAssurance {
    fn audit_label(self) -> &'static str {
        match self {
            Self::Aal1 => "test_bypass_email_otp",
            Self::Aal2Totp => "test_bypass_totp",
            Self::Aal2Phone => "test_bypass_phone",
        }
    }
}

struct TestAuthConfig {
    bearer_secret: String,
    code: String,
    project: String,
    issuer: String,
    local_mode: bool,
    allowed_emails: Vec<String>,
    allowed_domains: Vec<String>,
    allowed_phones: Vec<String>,
    sms_hook_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TestSmsHookPayload {
    #[serde(default)]
    metadata: Value,
    user: TestSmsHookUser,
    sms: TestSmsHookData,
}

#[derive(Debug, Deserialize)]
struct TestSmsHookUser {
    id: Uuid,
    email: String,
}

#[derive(Debug, Deserialize)]
struct TestSmsHookData {
    otp: String,
    sms_type: String,
    phone: String,
}

/// Validate the deterministic-auth boundary before the listener is opened.
///
/// A deployment that explicitly enables the endpoint but misconfigures even one
/// guard must fail startup. Disabled deployments remain unaffected.
pub(crate) fn validate_startup(app: &AppConfig) -> Result<(), AuthError> {
    let Some(config) = TestAuthConfig::from_env_if_enabled()? else {
        return Ok(());
    };
    let project = bound_project(app, &config)?;

    if !config.local_mode && (app.redis.is_none() || app.sessions.rate_limit_fail_open) {
        tracing::error!("deterministic auth requires Redis/Valkey and fail-closed rate limiting");
        return Err(AuthError::Unavailable);
    }

    tracing::warn!(
        project = %project.name,
        issuer = %config.issuer,
        verification_method = "test_bypass",
        "deterministic test authentication is enabled for an isolated realm"
    );
    Ok(())
}

pub async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TestSessionRequest>,
) -> Result<Json<Value>, AuthError> {
    let config = TestAuthConfig::from_env()?;
    let presented_secret = bearer(&headers).ok_or(AuthError::Unauthorized)?;
    if !constant_time_matches(&config.bearer_secret, presented_secret)
        || !constant_time_matches(&config.code, request.code.trim())
    {
        return Err(AuthError::Unauthorized);
    }

    let project_name = request.project.trim();
    if project_name != config.project {
        return Err(AuthError::Forbidden);
    }
    let email = normalize_email(&request.email)?;
    if !email_is_allowed(&email, &config.allowed_emails, &config.allowed_domains) {
        return Err(AuthError::Forbidden);
    }
    let phone = match request.assurance {
        TestAssurance::Aal2Phone => {
            if !config.local_mode {
                // Fixed phone OTPs are a self-hosted GoTrue test facility. Do
                // not risk sending an SMS from a hosted or production-adjacent
                // project even when every other test-auth guard is present.
                return Err(AuthError::Forbidden);
            }
            let phone = normalize_phone(request.phone.as_deref().unwrap_or_default())?;
            if !config
                .allowed_phones
                .iter()
                .any(|candidate| candidate == &phone)
            {
                return Err(AuthError::Forbidden);
            }
            Some(phone)
        }
        TestAssurance::Aal1 | TestAssurance::Aal2Totp => {
            if request
                .phone
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            {
                return Err(AuthError::BadRequest(
                    "phone is accepted only for aal2_phone test sessions",
                ));
            }
            None
        }
    };

    let project = bound_project(&state.config, &config)?;
    if !config.local_mode
        && (state.config.redis.is_none() || state.config.sessions.rate_limit_fail_open)
    {
        return Err(AuthError::Unavailable);
    }

    // Keep both a per-identity and a per-project ceiling. Identifiers are hashed
    // by `enforce_limit`, so raw addresses never become Redis keys.
    enforce_limit(&state, "test-supabase-session-email", &email, 10, 300).await?;
    enforce_limit(
        &state,
        "test-supabase-session-project",
        project_name,
        60,
        300,
    )
    .await?;

    let generated = generate_test_otp(&state, project, &email).await?;
    let first_factor = verify_generated_otp(&state, project, &email, &generated).await?;
    validate_session_response(&first_factor, &email).inspect_err(|_| {
        tracing::warn!(
            project = %project.name,
            "Supabase test first-factor response failed session-shape validation"
        );
    })?;
    let verified = match request.assurance {
        TestAssurance::Aal1 => first_factor,
        TestAssurance::Aal2Totp => step_up_totp(&state, project, first_factor).await?,
        TestAssurance::Aal2Phone => {
            step_up_phone(
                &state,
                project,
                first_factor,
                phone.as_deref().ok_or(AuthError::Forbidden)?,
            )
            .await?
        }
    };
    validate_verified_session(&state, &verified, project, &email, request.assurance).await?;

    tracing::warn!(
        project = %project.name,
        subject = %audit_subject(&config.bearer_secret, &email),
        verification_method = request.assurance.audit_label(),
        "issued isolated deterministic Supabase test session"
    );
    Ok(Json(verified))
}

/// Signed local Supabase Send SMS Hook used only by the deterministic test
/// build. GoTrue's MFA phone path does not consult `auth.sms.test_otp`; it
/// generates a random challenge code and sends it through a provider or hook.
/// Capturing that generated code lets the server complete a genuine phone MFA
/// verification without delivering an SMS or exposing the provider code to a
/// Flutter/browser test client.
pub async fn capture_sms(
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), AuthError> {
    tracing::info!(
        header_count = headers.len(),
        body_bytes = body.len(),
        "received isolated Supabase phone MFA hook"
    );
    let config = TestAuthConfig::from_env()?;
    if !config.local_mode {
        return Err(AuthError::Forbidden);
    }
    let secret = config.sms_hook_secret.ok_or(AuthError::Unavailable)?;
    verify_standard_webhook(&headers, &body, &secret).inspect_err(|_| {
        tracing::warn!("Supabase test SMS hook signature was rejected");
    })?;

    let payload: TestSmsHookPayload = serde_json::from_slice(&body).map_err(|error| {
        tracing::warn!(%error, "Supabase test SMS hook payload was invalid");
        AuthError::BadRequest("invalid hook payload")
    })?;
    let _ = payload.metadata;
    let email = normalize_email(&payload.user.email).inspect_err(|_| {
        tracing::warn!("Supabase test SMS hook email was malformed");
    })?;
    let email_allowed = email_is_allowed(&email, &config.allowed_emails, &config.allowed_domains);
    if !email_allowed {
        tracing::warn!("Supabase test SMS hook email was outside the allowlist");
        return Err(AuthError::Forbidden);
    }
    let phone = normalize_hook_phone(&payload.sms.phone).inspect_err(|_| {
        tracing::warn!("Supabase test SMS hook phone was malformed");
    })?;
    let phone_allowed = config
        .allowed_phones
        .iter()
        .any(|candidate| candidate == &phone);
    if !phone_allowed {
        tracing::warn!("Supabase test SMS hook phone was outside the allowlist");
        return Err(AuthError::Forbidden);
    }
    if payload.sms.sms_type != "mfa" {
        tracing::warn!("Supabase test SMS hook was not an MFA event");
        return Err(AuthError::Forbidden);
    }
    validate_six_digit_value(&payload.sms.otp)?;

    let now = unix_timestamp()?;
    let store = CAPTURED_SMS_OTPS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut entries = store.lock().map_err(|_| AuthError::Unavailable)?;
    entries.retain(|_, value| now.saturating_sub(value.captured_at) <= CAPTURED_SMS_TTL_SECS);
    if entries.len() >= MAX_CAPTURED_SMS_ENTRIES {
        return Err(AuthError::RateLimited);
    }
    entries.insert(
        (payload.user.id, phone),
        CapturedSmsOtp {
            code: payload.sms.otp,
            captured_at: now,
        },
    );

    tracing::info!(
        subject = %audit_subject(&config.bearer_secret, &email),
        verification_method = "test_bypass_phone_sms_hook",
        "captured isolated Supabase phone MFA challenge"
    );
    Ok((StatusCode::OK, Json(json!({}))))
}

impl TestAuthConfig {
    fn from_env() -> Result<Self, AuthError> {
        Self::from_env_if_enabled()?.ok_or(AuthError::Unavailable)
    }

    fn from_env_if_enabled() -> Result<Option<Self>, AuthError> {
        if !env_truthy("AUTH_TEST_AUTH_ENABLED") {
            return Ok(None);
        }

        let deployment = required_env("AUTH_REALM_DEPLOYMENT")?;
        let development_dbless = env_truthy("AUTH_ALLOW_DBLESS");
        let local_mode = local_test_deployment(&deployment, development_dbless);
        if !test_deployment_isolated(&deployment, development_dbless) {
            tracing::error!(
                deployment,
                "refusing to enable deterministic auth outside an isolated test deployment"
            );
            return Err(AuthError::Forbidden);
        }

        let bearer_secret = required_env("AUTH_TEST_AUTH_SECRET")?;
        if bearer_secret.len() < MIN_BEARER_SECRET_BYTES {
            return Err(AuthError::Unavailable);
        }
        let code = std::env::var("AUTH_TEST_AUTH_CODE")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_TEST_CODE.to_owned());
        validate_six_digit_value(&code)?;

        let project = required_env("AUTH_TEST_AUTH_PROJECT")?;
        if !test_project_name(&project) {
            tracing::error!(
                project,
                "deterministic auth project must have an explicit test name"
            );
            return Err(AuthError::Forbidden);
        }

        let issuer =
            normalize_test_issuer(&required_env("AUTH_TEST_AUTH_SUPABASE_ISSUER")?, local_mode)?;

        let allowed_emails = csv_env("AUTH_TEST_AUTH_ALLOWED_EMAILS")
            .into_iter()
            .map(|email| normalize_allowed_email(&email))
            .collect::<Result<Vec<_>, _>>()?;
        let allowed_domains = csv_env("AUTH_TEST_AUTH_ALLOWED_DOMAINS")
            .into_iter()
            .map(|domain| normalize_domain(&domain))
            .collect::<Result<Vec<_>, _>>()?;
        let allowed_phones = csv_env("AUTH_TEST_AUTH_ALLOWED_PHONES")
            .into_iter()
            .map(|phone| normalize_phone(&phone))
            .collect::<Result<Vec<_>, _>>()?;
        let sms_hook_secret = std::env::var("AUTH_TEST_AUTH_SUPABASE_SMS_HOOK_SECRET")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        if !allowed_phones.is_empty() && sms_hook_secret.is_none() {
            tracing::error!(
                "AUTH_TEST_AUTH_SUPABASE_SMS_HOOK_SECRET is required when phone allowlists are configured"
            );
            return Err(AuthError::Unavailable);
        }
        if allowed_emails.is_empty() && allowed_domains.is_empty() {
            return Err(AuthError::Unavailable);
        }

        Ok(Some(Self {
            bearer_secret,
            code,
            project,
            issuer,
            local_mode,
            allowed_emails,
            allowed_domains,
            allowed_phones,
            sms_hook_secret,
        }))
    }
}

fn bound_project<'a>(
    app: &'a AppConfig,
    config: &TestAuthConfig,
) -> Result<&'a SupabaseProject, AuthError> {
    let project = app
        .projects
        .iter()
        .find(|candidate| candidate.name == config.project)
        .ok_or_else(|| {
            tracing::error!(
                project = %config.project,
                "deterministic auth project is missing from the provider registry"
            );
            AuthError::Unavailable
        })?;
    if !test_project_name(&project.name) {
        return Err(AuthError::Forbidden);
    }

    let issuer = normalize_test_issuer(&project.issuer(), config.local_mode)?;
    if issuer != config.issuer {
        tracing::error!(
            project = %project.name,
            configured_issuer = %config.issuer,
            project_issuer = %issuer,
            "deterministic auth issuer does not match the selected Supabase project"
        );
        return Err(AuthError::Forbidden);
    }

    let has_admin_key = project
        .api_keys
        .service_role_key
        .as_deref()
        .or(project.api_keys.secret_key.as_deref())
        .is_some_and(|value| !value.trim().is_empty());
    let has_public_key = project
        .api_keys
        .publishable_key
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    if !has_admin_key || !has_public_key {
        tracing::error!(
            project = %project.name,
            has_admin_key,
            has_public_key,
            "deterministic auth project credentials are incomplete"
        );
        return Err(AuthError::Unavailable);
    }
    Ok(project)
}

#[derive(Debug)]
struct GeneratedOtp {
    code: String,
    verification_type: String,
}

async fn generate_test_otp(
    state: &AppState,
    project: &SupabaseProject,
    email: &str,
) -> Result<GeneratedOtp, AuthError> {
    let admin_key = project
        .api_keys
        .service_role_key
        .as_deref()
        .or(project.api_keys.secret_key.as_deref())
        .filter(|value| !value.trim().is_empty())
        .ok_or(AuthError::Unavailable)?;
    let endpoint = format!(
        "{}/admin/generate_link",
        project.issuer().trim_end_matches('/')
    );
    let response = state
        .http
        .post(endpoint)
        .header("apikey", admin_key)
        .bearer_auth(admin_key)
        .json(&json!({
            "type": "magiclink",
            "email": email,
            "data": {
                "shared_auth_test": true,
                "verification_method": "test_bypass"
            }
        }))
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(%error, project = %project.name, "Supabase test OTP generation failed");
            AuthError::Upstream
        })?;
    if !response.status().is_success() {
        tracing::warn!(
            status = response.status().as_u16(),
            project = %project.name,
            "Supabase rejected test OTP generation"
        );
        return Err(AuthError::Upstream);
    }
    let response: Value = response.json().await.map_err(|_| AuthError::Upstream)?;
    let properties = response.get("properties").unwrap_or(&response);
    let code = properties
        .get("email_otp")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(AuthError::Upstream)?;
    validate_six_digit_value(code).map_err(|_| AuthError::Upstream)?;
    let verification_type = properties
        .get("verification_type")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(AuthError::Upstream)?;
    if !matches!(
        verification_type,
        "signup" | "invite" | "magiclink" | "recovery"
    ) {
        return Err(AuthError::Upstream);
    }
    Ok(GeneratedOtp {
        code: code.to_owned(),
        verification_type: verification_type.to_owned(),
    })
}

async fn verify_generated_otp(
    state: &AppState,
    project: &SupabaseProject,
    email: &str,
    generated: &GeneratedOtp,
) -> Result<Value, AuthError> {
    let client_key = project
        .api_keys
        .publishable_key
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(AuthError::Unavailable)?;
    let endpoint = format!("{}/verify", project.issuer().trim_end_matches('/'));
    let response = state
        .http
        .post(endpoint)
        .header("apikey", client_key)
        .bearer_auth(client_key)
        .json(&json!({
            "type": generated.verification_type.as_str(),
            "email": email,
            "token": generated.code.as_str()
        }))
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(%error, project = %project.name, "Supabase test OTP verification failed");
            AuthError::Upstream
        })?;
    if !response.status().is_success() {
        tracing::warn!(
            status = response.status().as_u16(),
            project = %project.name,
            "Supabase rejected generated test OTP"
        );
        return Err(AuthError::Upstream);
    }
    response.json().await.map_err(|_| AuthError::Upstream)
}

const TEST_FACTOR_PREFIX: &str = "shared-auth-test:";

async fn step_up_totp(
    state: &AppState,
    project: &SupabaseProject,
    session: Value,
) -> Result<Value, AuthError> {
    cleanup_test_factors(state, project, &session).await?;
    let access_token = session_access_token(&session)?;
    let friendly_name = format!("{TEST_FACTOR_PREFIX}{}", Uuid::new_v4());
    let enrollment = supabase_user_json(
        state,
        project,
        access_token,
        Method::POST,
        "/factors",
        Some(json!({
            "factor_type": "totp",
            "friendly_name": friendly_name
        })),
        "TOTP test factor enrollment",
    )
    .await?;
    let factor_id = response_uuid(&enrollment, "id")?;
    let secret = enrollment
        .get("totp")
        .and_then(|totp| totp.get("secret"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or(AuthError::Upstream)?;
    let challenge = challenge_factor(state, project, access_token, factor_id, None).await?;
    let code = totp_at(
        secret,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthError::Upstream)?
            .as_secs(),
    )?;
    verify_factor(state, project, access_token, factor_id, challenge, &code).await
}

async fn step_up_phone(
    state: &AppState,
    project: &SupabaseProject,
    session: Value,
    phone: &str,
) -> Result<Value, AuthError> {
    cleanup_test_factors(state, project, &session).await?;
    let access_token = session_access_token(&session)?;
    let friendly_name = format!("{TEST_FACTOR_PREFIX}{}", Uuid::new_v4());
    let enrollment = supabase_user_json(
        state,
        project,
        access_token,
        Method::POST,
        "/factors",
        Some(json!({
            "factor_type": "phone",
            "friendly_name": friendly_name,
            "phone": phone
        })),
        "phone test factor enrollment",
    )
    .await?;
    let factor_id = response_uuid(&enrollment, "id")?;
    let user_id = session_user_id(&session)?;
    clear_captured_sms_otp(user_id, phone)?;
    let challenge = challenge_factor(state, project, access_token, factor_id, Some("sms")).await?;
    let provider_code = take_captured_sms_otp(user_id, phone)?;
    verify_factor(
        state,
        project,
        access_token,
        factor_id,
        challenge,
        &provider_code,
    )
    .await
}

fn session_user_id(session: &Value) -> Result<Uuid, AuthError> {
    session
        .get("user")
        .and_then(|user| user.get("id"))
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(AuthError::Upstream)
}

fn clear_captured_sms_otp(user_id: Uuid, phone: &str) -> Result<(), AuthError> {
    let store = CAPTURED_SMS_OTPS.get_or_init(|| Mutex::new(HashMap::new()));
    store
        .lock()
        .map_err(|_| AuthError::Unavailable)?
        .remove(&(user_id, phone.to_owned()));
    Ok(())
}

fn take_captured_sms_otp(user_id: Uuid, phone: &str) -> Result<String, AuthError> {
    let now = unix_timestamp()?;
    let store = CAPTURED_SMS_OTPS.get_or_init(|| Mutex::new(HashMap::new()));
    let captured = store
        .lock()
        .map_err(|_| AuthError::Unavailable)?
        .remove(&(user_id, phone.to_owned()))
        .ok_or(AuthError::Upstream)?;
    if now.saturating_sub(captured.captured_at) > CAPTURED_SMS_TTL_SECS {
        return Err(AuthError::Upstream);
    }
    Ok(captured.code)
}

fn unix_timestamp() -> Result<u64, AuthError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AuthError::Unavailable)
}

async fn challenge_factor(
    state: &AppState,
    project: &SupabaseProject,
    access_token: &str,
    factor_id: Uuid,
    channel: Option<&str>,
) -> Result<Uuid, AuthError> {
    let body = channel.map_or_else(|| json!({}), |channel| json!({ "channel": channel }));
    let response = supabase_user_json(
        state,
        project,
        access_token,
        Method::POST,
        &format!("/factors/{factor_id}/challenge"),
        Some(body),
        "test factor challenge",
    )
    .await?;
    response_uuid(&response, "id")
}

async fn verify_factor(
    state: &AppState,
    project: &SupabaseProject,
    access_token: &str,
    factor_id: Uuid,
    challenge_id: Uuid,
    code: &str,
) -> Result<Value, AuthError> {
    supabase_user_json(
        state,
        project,
        access_token,
        Method::POST,
        &format!("/factors/{factor_id}/verify"),
        Some(json!({
            "challenge_id": challenge_id,
            "code": code
        })),
        "test factor verification",
    )
    .await
}

async fn cleanup_test_factors(
    state: &AppState,
    project: &SupabaseProject,
    session: &Value,
) -> Result<(), AuthError> {
    let user_id = session
        .get("user")
        .and_then(|user| user.get("id"))
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(AuthError::Upstream)?;
    let path = format!("/admin/users/{user_id}/factors");
    let response = supabase_admin_json(
        state,
        project,
        Method::GET,
        &path,
        None,
        "test factor inventory",
    )
    .await?;
    let factors = response
        .as_array()
        .or_else(|| response.get("factors").and_then(Value::as_array))
        .ok_or(AuthError::Upstream)?;
    if factors.len() > 64 {
        return Err(AuthError::Forbidden);
    }

    for factor in factors {
        let friendly_name = factor
            .get("friendly_name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !friendly_name.starts_with(TEST_FACTOR_PREFIX) {
            // A deterministic identity is contaminated if a human-owned factor
            // appears on it. Never delete or work around an untagged factor.
            return Err(AuthError::Forbidden);
        }
        let factor_id = response_uuid(factor, "id")?;
        supabase_admin_json(
            state,
            project,
            Method::DELETE,
            &format!("{path}/{factor_id}"),
            None,
            "stale test factor cleanup",
        )
        .await?;
    }
    Ok(())
}

async fn supabase_user_json(
    state: &AppState,
    project: &SupabaseProject,
    access_token: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
    operation: &'static str,
) -> Result<Value, AuthError> {
    let public_key = project
        .api_keys
        .publishable_key
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(AuthError::Unavailable)?;
    send_supabase_json(
        state,
        project,
        method,
        path,
        public_key,
        access_token,
        body,
        operation,
    )
    .await
}

async fn supabase_admin_json(
    state: &AppState,
    project: &SupabaseProject,
    method: Method,
    path: &str,
    body: Option<Value>,
    operation: &'static str,
) -> Result<Value, AuthError> {
    let admin_key = project
        .api_keys
        .service_role_key
        .as_deref()
        .or(project.api_keys.secret_key.as_deref())
        .filter(|value| !value.trim().is_empty())
        .ok_or(AuthError::Unavailable)?;
    send_supabase_json(
        state, project, method, path, admin_key, admin_key, body, operation,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_supabase_json(
    state: &AppState,
    project: &SupabaseProject,
    method: Method,
    path: &str,
    api_key: &str,
    bearer_token: &str,
    body: Option<Value>,
    operation: &'static str,
) -> Result<Value, AuthError> {
    let endpoint = format!("{}{}", project.issuer().trim_end_matches('/'), path);
    let mut request = state
        .http
        .request(method, endpoint)
        .header("apikey", api_key)
        .bearer_auth(bearer_token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.map_err(|error| {
        tracing::warn!(%error, project = %project.name, operation, "Supabase test ceremony request failed");
        AuthError::Upstream
    })?;
    if !response.status().is_success() {
        tracing::warn!(
            status = response.status().as_u16(),
            project = %project.name,
            operation,
            "Supabase rejected test ceremony request"
        );
        return Err(AuthError::Upstream);
    }
    response.json().await.map_err(|_| AuthError::Upstream)
}

fn response_uuid(response: &Value, field: &str) -> Result<Uuid, AuthError> {
    response
        .get(field)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(AuthError::Upstream)
}

fn session_access_token(session: &Value) -> Result<&str, AuthError> {
    session
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 16 * 1024)
        .ok_or(AuthError::Upstream)
}

async fn validate_verified_session(
    state: &AppState,
    session: &Value,
    project: &SupabaseProject,
    requested_email: &str,
    assurance: TestAssurance,
) -> Result<(), AuthError> {
    validate_session_response(session, requested_email).inspect_err(|_| {
        tracing::warn!(
            project = %project.name,
            "Supabase test verified response failed session-shape validation"
        );
    })?;
    let access_token = session_access_token(session)?;
    let identity = state
        .supabase
        .verify(&state.http, access_token)
        .await
        .map_err(|error| {
            tracing::warn!(
                %error,
                project = %project.name,
                "Supabase test access token failed cryptographic verification"
            );
            AuthError::Upstream
        })?;
    let verified_email = identity
        .email
        .as_deref()
        .ok_or(AuthError::Upstream)
        .and_then(|email| normalize_email(email).map_err(|_| AuthError::Upstream))?;
    if identity.project != project.name
        || verified_email != requested_email
        || !identity.email_verified
        || identity
            .auth_methods
            .iter()
            .any(|method| method == "password")
    {
        tracing::warn!(
            project = %project.name,
            project_matches = identity.project == project.name,
            email_matches = verified_email == requested_email,
            identity.email_verified,
            contains_password = identity
                .auth_methods
                .iter()
                .any(|method| method == "password"),
            "Supabase test access token failed identity validation"
        );
        return Err(AuthError::Upstream);
    }

    let valid_assurance = match assurance {
        TestAssurance::Aal1 => identity.auth_level == 1,
        TestAssurance::Aal2Totp => {
            identity.auth_level == 2 && identity.auth_methods.iter().any(|method| method == "totp")
        }
        TestAssurance::Aal2Phone => {
            identity.auth_level == 2
                && identity
                    .auth_methods
                    .iter()
                    .any(|method| method == "mfa/phone")
        }
    };
    if !valid_assurance {
        tracing::warn!(
            project = %project.name,
            requested_assurance = ?assurance,
            actual_auth_level = identity.auth_level,
            actual_auth_methods = ?identity.auth_methods,
            "Supabase test access token failed assurance validation"
        );
        return Err(AuthError::Upstream);
    }
    Ok(())
}

fn normalize_phone(value: &str) -> Result<String, AuthError> {
    let phone = value.trim();
    let digits = phone
        .strip_prefix('+')
        .ok_or(AuthError::BadRequest("test phone must use E.164 format"))?;
    if !(8..=15).contains(&digits.len())
        || digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(AuthError::BadRequest("test phone must use E.164 format"));
    }
    Ok(phone.to_owned())
}

fn normalize_hook_phone(value: &str) -> Result<String, AuthError> {
    let value = value.trim();
    if value.starts_with('+') {
        return normalize_phone(value);
    }
    if (8..=15).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && !value.starts_with('0')
    {
        return normalize_phone(&format!("+{value}"));
    }
    Err(AuthError::BadRequest("phone must use E.164 format"))
}

fn totp_at(base32_secret: &str, unix_seconds: u64) -> Result<String, AuthError> {
    let secret = decode_base32(base32_secret)?;
    let counter = unix_seconds / 30;
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&secret).map_err(|_| AuthError::Upstream)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let value = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(format!("{:06}", value % 1_000_000))
}

fn decode_base32(value: &str) -> Result<Vec<u8>, AuthError> {
    let value = value.trim().trim_end_matches('=');
    if value.is_empty() || value.len() > 256 {
        return Err(AuthError::Upstream);
    }
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes() {
        let symbol = match byte.to_ascii_uppercase() {
            b'A'..=b'Z' => u32::from(byte.to_ascii_uppercase() - b'A'),
            b'2'..=b'7' => u32::from(byte - b'2' + 26),
            _ => return Err(AuthError::Upstream),
        };
        accumulator = (accumulator << 5) | symbol;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1_u32 << bits).saturating_sub(1);
        }
    }
    if output.len() < 16 || (bits > 0 && accumulator != 0) {
        return Err(AuthError::Upstream);
    }
    Ok(output)
}

fn validate_session_response(value: &Value, requested_email: &str) -> Result<(), AuthError> {
    for field in ["access_token", "refresh_token"] {
        let present = value
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|candidate| !candidate.trim().is_empty());
        if !present {
            return Err(AuthError::Upstream);
        }
    }
    let returned_email = value
        .get("user")
        .and_then(|user| user.get("email"))
        .and_then(Value::as_str)
        .ok_or(AuthError::Upstream)?;
    let returned_email = normalize_email(returned_email).map_err(|_| AuthError::Upstream)?;
    if returned_email != requested_email {
        return Err(AuthError::Upstream);
    }
    Ok(())
}

fn constant_time_matches(expected: &str, presented: &str) -> bool {
    const COMPARISON_KEY: &[u8] = b"shared-auth:test-comparison:v1";
    let mut expected_mac =
        Hmac::<Sha256>::new_from_slice(COMPARISON_KEY).expect("fixed HMAC key is valid");
    expected_mac.update(expected.as_bytes());
    let expected_tag = expected_mac.finalize().into_bytes();

    let mut presented_mac =
        Hmac::<Sha256>::new_from_slice(COMPARISON_KEY).expect("fixed HMAC key is valid");
    presented_mac.update(presented.as_bytes());
    presented_mac.verify_slice(&expected_tag).is_ok()
}

fn email_is_allowed(email: &str, emails: &[String], domains: &[String]) -> bool {
    if emails.iter().any(|candidate| candidate == email) {
        return true;
    }
    let Some((_, domain)) = email.rsplit_once('@') else {
        return false;
    };
    domains.iter().any(|candidate| candidate == domain)
}

fn test_deployment_isolated(deployment: &str, development_dbless: bool) -> bool {
    let parts = deployment_parts(deployment);
    let production = parts
        .iter()
        .any(|part| matches!(part.as_str(), "prod" | "production"));
    if production {
        return false;
    }
    parts
        .iter()
        .any(|part| matches!(part.as_str(), "test" | "testing" | "e2e"))
        || local_test_deployment(deployment, development_dbless)
}

fn local_test_deployment(deployment: &str, development_dbless: bool) -> bool {
    development_dbless
        && deployment_parts(deployment)
            .iter()
            .any(|part| matches!(part.as_str(), "local" | "dev" | "development"))
}

fn deployment_parts(deployment: &str) -> Vec<String> {
    deployment
        .to_ascii_lowercase()
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn test_project_name(project: &str) -> bool {
    let project = project.to_ascii_lowercase();
    project.ends_with("-test") || project.ends_with("_test")
}

fn required_env(key: &'static str) -> Result<String, AuthError> {
    let value = std::env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if value.is_none() {
        tracing::error!(
            key,
            "deterministic auth requires a non-empty environment variable"
        );
    }
    value.ok_or(AuthError::Unavailable)
}

fn csv_env(key: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn normalize_allowed_email(value: &str) -> Result<String, AuthError> {
    let email = normalize_email(value)?;
    let domain = email
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .ok_or(AuthError::BadRequest("invalid test email"))?;
    if !reserved_test_domain(domain) {
        return Err(AuthError::BadRequest(
            "test bypass identities must use a reserved test namespace",
        ));
    }
    Ok(email)
}

fn normalize_domain(value: &str) -> Result<String, AuthError> {
    let domain = value.trim().trim_start_matches('@').to_ascii_lowercase();
    if domain.is_empty()
        || domain.len() > 253
        || !domain.contains('.')
        || domain.chars().any(char::is_whitespace)
        || !reserved_test_domain(&domain)
    {
        Err(AuthError::BadRequest(
            "wildcard test email domains must use a reserved test namespace",
        ))
    } else {
        Ok(domain)
    }
}

fn reserved_test_domain(domain: &str) -> bool {
    domain == "example.com"
        || domain == "example.net"
        || domain == "example.org"
        || domain.ends_with(".test")
        || domain.ends_with(".example")
        || domain.ends_with(".invalid")
}

fn normalize_test_issuer(value: &str, allow_loopback_http: bool) -> Result<String, AuthError> {
    let parsed = Url::parse(value).map_err(|_| AuthError::Unavailable)?;
    let loopback_http = allow_loopback_http
        && parsed.scheme() == "http"
        && parsed
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    if (parsed.scheme() != "https" && !loopback_http)
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.host_str().is_none()
    {
        return Err(AuthError::Unavailable);
    }
    let path = parsed.path().trim_end_matches('/');
    if path != "/auth/v1" {
        return Err(AuthError::Unavailable);
    }
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

fn validate_six_digit_value(value: &str) -> Result<(), AuthError> {
    if value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(())
    } else {
        Err(AuthError::Unavailable)
    }
}

fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn audit_subject(secret: &str, email: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts keys of any non-empty length");
    mac.update(email.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut result = String::with_capacity(24);
    for byte in digest.iter().take(12) {
        write!(&mut result, "{byte:02x}").expect("writing to a string cannot fail");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_comparison_accepts_only_exact_values() {
        assert!(constant_time_matches("424242", "424242"));
        assert!(!constant_time_matches("424242", "424241"));
        assert!(!constant_time_matches("long-secret", "long-secret "));
    }

    #[test]
    fn captured_phone_otp_is_identity_scoped_and_single_use() {
        let user_id = Uuid::new_v4();
        let other_user_id = Uuid::new_v4();
        let phone = "+15005550006";
        let store = CAPTURED_SMS_OTPS.get_or_init(|| Mutex::new(HashMap::new()));
        store.lock().unwrap().insert(
            (user_id, phone.to_owned()),
            CapturedSmsOtp {
                code: "123456".to_owned(),
                captured_at: unix_timestamp().unwrap(),
            },
        );

        assert!(take_captured_sms_otp(other_user_id, phone).is_err());
        assert_eq!(take_captured_sms_otp(user_id, phone).unwrap(), "123456");
        assert!(take_captured_sms_otp(user_id, phone).is_err());
    }

    #[test]
    fn allowlist_is_exact_for_email_or_reserved_domain() {
        let emails = vec!["device@example.com".to_owned()];
        let domains = vec!["automation.example".to_owned()];
        assert!(email_is_allowed("device@example.com", &emails, &domains));
        assert!(email_is_allowed(
            "any@automation.example",
            &emails,
            &domains
        ));
        assert!(!email_is_allowed(
            "device@example.com.evil.test",
            &emails,
            &domains
        ));
        assert_eq!(
            normalize_domain("@automation.example").unwrap(),
            "automation.example"
        );
        assert_eq!(
            normalize_allowed_email("Device@Example.com").unwrap(),
            "device@example.com"
        );
        assert!(normalize_allowed_email("device@sonusauris.app").is_err());
        assert!(normalize_domain("users.sonusauris.app").is_err());
    }

    #[test]
    fn deterministic_auth_is_confined_to_test_or_explicit_local_names() {
        assert!(test_deployment_isolated("shared-auth-customer-test", false));
        assert!(test_deployment_isolated("shared-auth-customer-local", true));
        assert!(!test_deployment_isolated("", true));
        assert!(!test_deployment_isolated(
            "shared-auth-customer-prod-test",
            false
        ));
        assert!(!test_deployment_isolated(
            "shared-auth-customer-prod",
            false
        ));
        assert!(test_project_name("sonus-auris-test"));
        assert!(!test_project_name("sonus-auris"));
    }

    #[test]
    fn test_issuer_is_exact_and_https_except_for_explicit_loopback() {
        assert_eq!(
            normalize_test_issuer("https://example.supabase.co/auth/v1/", false).unwrap(),
            "https://example.supabase.co/auth/v1"
        );
        assert!(normalize_test_issuer("http://example.supabase.co/auth/v1", true).is_err());
        assert!(normalize_test_issuer("https://example.supabase.co/auth/v1?x=1", false).is_err());
        assert!(normalize_test_issuer("https://example.supabase.co/other", false).is_err());
        assert_eq!(
            normalize_test_issuer("http://127.0.0.1:54321/auth/v1", true).unwrap(),
            "http://127.0.0.1:54321/auth/v1"
        );
    }

    #[test]
    fn test_assurance_and_phone_inputs_are_exact() {
        assert_eq!(
            serde_json::from_value::<TestAssurance>(json!("aal2_totp")).unwrap(),
            TestAssurance::Aal2Totp
        );
        assert_eq!(
            serde_json::from_value::<TestAssurance>(json!("aal2_phone")).unwrap(),
            TestAssurance::Aal2Phone
        );
        assert!(serde_json::from_value::<TestAssurance>(json!("aal2")).is_err());
        assert_eq!(normalize_phone(" +15005550006 ").unwrap(), "+15005550006");
        assert_eq!(normalize_hook_phone("15005550006").unwrap(), "+15005550006");
        assert!(normalize_phone("15005550006").is_err());
        assert!(normalize_hook_phone("05005550006").is_err());
        assert!(normalize_phone("+05005550006").is_err());
        assert!(normalize_phone("+1 500 555 0006").is_err());
    }

    #[test]
    fn totp_matches_rfc_6238_sha1_vector_at_six_digits() {
        // RFC 6238's 20-byte ASCII secret, represented as Base32. The RFC's
        // eight-digit value at t=59 is 94287082; Supabase uses the final six.
        assert_eq!(
            totp_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap(),
            "287082"
        );
        assert!(totp_at("not base32!", 59).is_err());
    }

    #[test]
    fn session_response_requires_real_supabase_tokens_and_exact_identity() {
        let good = json!({
            "access_token": "header.payload.signature",
            "refresh_token": "refresh",
            "user": { "email": "device@example.com" }
        });
        assert!(validate_session_response(&good, "device@example.com").is_ok());
        assert!(validate_session_response(&json!({}), "device@example.com").is_err());
        assert!(validate_session_response(
            &json!({
                "access_token": "token",
                "refresh_token": "refresh",
                "user": { "email": "other@example.com" }
            }),
            "device@example.com",
        )
        .is_err());
        assert!(validate_session_response(
            &json!({
                "access_token": "token",
                "refresh_token": "refresh",
                "user": {}
            }),
            "device@example.com",
        )
        .is_err());
    }

    #[test]
    fn audit_subject_is_stable_but_does_not_reveal_the_email() {
        let first = audit_subject(
            "test-secret-at-least-thirty-two-bytes",
            "device@example.com",
        );
        let second = audit_subject(
            "test-secret-at-least-thirty-two-bytes",
            "device@example.com",
        );
        assert_eq!(first, second);
        assert_eq!(first.len(), 24);
        assert!(!first.contains("device"));
    }
}
