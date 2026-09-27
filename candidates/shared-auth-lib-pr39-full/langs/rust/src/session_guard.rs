//! Session-aware Shared Auth guard.
//!
//! Stateless consumers only need [`crate::AuthGuard`]. Browser applications also
//! need the newly exchanged Shared Auth access token so they can rotate away
//! from a raw provider token. This opt-in guard returns that access token without
//! changing the existing guard API or exposing refresh credentials.

use std::fmt;
use std::future::Future;
use std::time::{Duration, Instant};

use axum::http::{header, HeaderMap};
use base64::Engine;
use serde::Deserialize;
use shared_auth_interfaces::{AuthOutcome, Authority, Identity};

use crate::{
    verify_at_supabase, AccessPolicy, ArmFailure, AuthGuard, AuthGuardConfig, AuthorityConfig,
};

const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// A newly issued Shared Auth access token suitable for a host-only HttpOnly
/// session cookie. No refresh credential is returned by this API.
pub struct SessionUpgrade {
    access_token: String,
    session_id: Option<String>,
}

impl SessionUpgrade {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub fn into_access_token(self) -> String {
        self.access_token
    }
}

impl fmt::Debug for SessionUpgrade {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionUpgrade")
            .field("access_token", &"[redacted]")
            .field("session_id", &self.session_id)
            .finish()
    }
}

/// Authentication result plus an optional browser-session rotation.
#[derive(Debug)]
pub struct SessionDecision {
    pub outcome: AuthOutcome,
    pub session_upgrade: Option<SessionUpgrade>,
}

impl SessionDecision {
    fn without_upgrade(outcome: AuthOutcome) -> Self {
        Self {
            outcome,
            session_upgrade: None,
        }
    }
}

#[derive(Deserialize)]
struct ExchangeResponse {
    access_token: String,
    shared_user_id: String,
    provider: String,
    provider_tenant: String,
    provider_subject: String,
    roles: Vec<String>,
}

#[derive(Deserialize)]
struct IntrospectResponse {
    active: bool,
    sub: String,
    provider: String,
    provider_tenant: String,
    provider_subject: String,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    supabase_user_id: Option<String>,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    amr: Vec<String>,
    #[serde(default)]
    acr: Option<String>,
    #[serde(default)]
    cred: Option<String>,
}

struct ExchangedSession {
    identity: Identity,
    upgrade: SessionUpgrade,
}

/// Exchange a provider token, introspect the issued Shared Auth JWT, and retain
/// the short-lived access token for a safe browser-cookie rotation.
///
/// The expected project is pinned independently of role policy. A token routed
/// through another provider tenant is invalid for this guard even when a role
/// name overlaps.
pub async fn exchange_session_at_shared_auth(
    http: &reqwest::Client,
    provider_token: &str,
    expected_project: &str,
    config: &AuthorityConfig,
) -> Result<(Identity, SessionUpgrade), ArmFailure> {
    if provider_token.is_empty()
        || provider_token.len() > MAX_TOKEN_BYTES
        || expected_project.is_empty()
    {
        return Err(ArmFailure::Invalid);
    }

    let base = config.shared_auth_base.trim_end_matches('/');
    let response = http
        .post(format!("{base}/auth/exchange"))
        .bearer_auth(provider_token)
        .timeout(config.arm_timeout)
        .send()
        .await
        .map_err(|_| ArmFailure::Unavailable)?;

    if matches!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    ) {
        return Err(ArmFailure::Invalid);
    }
    if !response.status().is_success() {
        return Err(ArmFailure::Unavailable);
    }
    let exchange: ExchangeResponse = response.json().await.map_err(|_| ArmFailure::Unavailable)?;
    if exchange.access_token.is_empty() || exchange.access_token.len() > MAX_TOKEN_BYTES {
        return Err(ArmFailure::Unavailable);
    }

    let mut introspection = http
        .post(format!("{base}/auth/introspect"))
        .json(&crate::authority::protected_introspection_body(
            &exchange.access_token,
            &config.audience,
        ))
        .timeout(config.arm_timeout);
    if let Some(secret) = config.introspect_secret.as_deref() {
        introspection = introspection.bearer_auth(secret);
    }
    let response = introspection
        .send()
        .await
        .map_err(|_| ArmFailure::Unavailable)?;
    if !response.status().is_success() {
        return Err(ArmFailure::Unavailable);
    }
    let claims: IntrospectResponse = response.json().await.map_err(|_| ArmFailure::Unavailable)?;

    if !coherent_exchange(&exchange, &claims, expected_project) {
        return Err(ArmFailure::Invalid);
    }

    let identity = Identity {
        shared_user_id: claims.sub,
        provider: claims.provider,
        provider_tenant: claims.provider_tenant,
        provider_subject: claims.provider_subject,
        project: claims.project,
        supabase_user_id: claims.supabase_user_id,
        session_id: claims.sid.clone(),
        email: claims.email,
        email_verified: claims.email_verified,
        roles: claims.roles,
        amr: claims.amr,
        acr: claims.acr,
        cred: claims.cred,
        authority: Authority::SharedAuth,
    };
    let upgrade = SessionUpgrade {
        access_token: exchange.access_token,
        session_id: claims.sid,
    };
    Ok((identity, upgrade))
}

fn coherent_exchange(
    exchange: &ExchangeResponse,
    claims: &IntrospectResponse,
    expected_project: &str,
) -> bool {
    claims.active
        && claims.sub == exchange.shared_user_id
        && claims.provider == exchange.provider
        && claims.provider_tenant == exchange.provider_tenant
        && claims.provider_subject == exchange.provider_subject
        && same_roles(&claims.roles, &exchange.roles)
        && claims.provider == "supabase"
        && claims.provider_tenant == expected_project
        && claims.project.as_deref() == Some(expected_project)
        && claims.supabase_user_id.as_deref() == Some(claims.provider_subject.as_str())
}

/// Role/email-authorizing guard that also returns a browser session upgrade.
pub struct SessionAwareAuthGuard {
    inner: AuthGuard,
    config: AuthGuardConfig,
    http: reqwest::Client,
}

impl SessionAwareAuthGuard {
    pub fn from_config(config: &AuthGuardConfig) -> Option<Self> {
        Some(Self {
            inner: AuthGuard::from_config(config)?,
            config: config.clone(),
            http: reqwest::Client::new(),
        })
    }

    /// Authenticate and authorize a request. Existing Shared Auth JWTs take the
    /// cached-JWKS path. Provider tokens race a session-retaining exchange
    /// against direct verification at exactly one configured provider project.
    pub async fn authorize_with_upgrade(&self, headers: &HeaderMap) -> SessionDecision {
        match select_credential(headers, &self.config.guard.authority.issuer) {
            Credential::Missing => SessionDecision::without_upgrade(AuthOutcome::Anonymous),
            Credential::Invalid => SessionDecision::without_upgrade(AuthOutcome::Unauthenticated),
            Credential::Shared(token) => self.authorize_shared_token(&token).await,
            Credential::Provider(token) => self.authorize_provider_token(&token).await,
        }
    }

    fn expected_project(&self) -> &str {
        self.config.guard.supabase_project.as_deref().unwrap_or("")
    }

    async fn authorize_shared_token(&self, token: &str) -> SessionDecision {
        let mut isolated = HeaderMap::new();
        let Ok(value) = format!("Bearer {token}").parse() else {
            return SessionDecision::without_upgrade(AuthOutcome::Unauthenticated);
        };
        isolated.insert(header::AUTHORIZATION, value);
        let outcome = self.inner.authorize(&isolated).await;
        SessionDecision::without_upgrade(restrict_outcome_to_project(
            outcome,
            self.expected_project(),
        ))
    }

    async fn authorize_provider_token(&self, token: &str) -> SessionDecision {
        let started = Instant::now();
        let authority = &self.config.guard.authority;
        let project = self.expected_project();
        let policy = &self.config.policy;

        let shared = async {
            let (identity, upgrade) =
                exchange_session_at_shared_auth(&self.http, token, project, authority).await?;
            let identity = enforce_policy_and_project(identity, policy, project)?;
            Ok(ExchangedSession { identity, upgrade })
        };
        let provider = async {
            let identity = verify_at_supabase(&self.http, token, project, authority).await?;
            enforce_policy_and_project(identity, policy, project)
        };

        race_session_arms(shared, provider, self.config.guard.race_deadline, started).await
    }
}

async fn race_session_arms<S, P>(
    shared: S,
    provider: P,
    deadline: Duration,
    started: Instant,
) -> SessionDecision
where
    S: Future<Output = Result<ExchangedSession, ArmFailure>> + Send,
    P: Future<Output = Result<Identity, ArmFailure>> + Send,
{
    tokio::pin!(shared);
    tokio::pin!(provider);

    let race = async {
        let mut shared_done = false;
        let mut provider_done = false;
        let mut failures = Vec::with_capacity(2);

        loop {
            tokio::select! {
                result = &mut shared, if !shared_done => {
                    shared_done = true;
                    match result {
                        Ok(mut exchanged) => {
                            exchanged.identity.authority = Authority::SharedAuth;
                            return SessionDecision {
                                outcome: AuthOutcome::Authenticated {
                                    identity: Box::new(exchanged.identity),
                                    authority: Authority::SharedAuth,
                                    elapsed_ms: started.elapsed().as_millis() as u64,
                                },
                                session_upgrade: Some(exchanged.upgrade),
                            };
                        }
                        Err(failure) => failures.push(failure),
                    }
                }
                result = &mut provider, if !provider_done => {
                    provider_done = true;
                    match result {
                        Ok(mut identity) => {
                            identity.authority = Authority::Supabase;
                            return SessionDecision::without_upgrade(AuthOutcome::Authenticated {
                                identity: Box::new(identity),
                                authority: Authority::Supabase,
                                elapsed_ms: started.elapsed().as_millis() as u64,
                            });
                        }
                        Err(failure) => failures.push(failure),
                    }
                }
                else => break,
            }
            if shared_done && provider_done {
                break;
            }
        }

        let outcome = if failures.len() == 2
            && failures
                .iter()
                .all(|failure| *failure == ArmFailure::Invalid)
        {
            AuthOutcome::Unauthenticated
        } else {
            AuthOutcome::Degraded {
                reason: "no authority could verify the credential".into(),
            }
        };
        SessionDecision::without_upgrade(outcome)
    };

    tokio::time::timeout(deadline, race)
        .await
        .unwrap_or_else(|_| {
            SessionDecision::without_upgrade(AuthOutcome::Degraded {
                reason: "auth race deadline exceeded".into(),
            })
        })
}

fn restrict_outcome_to_project(outcome: AuthOutcome, expected_project: &str) -> AuthOutcome {
    match outcome {
        AuthOutcome::Authenticated {
            identity,
            authority,
            elapsed_ms,
        } if identity_matches_project(&identity, expected_project) => AuthOutcome::Authenticated {
            identity,
            authority,
            elapsed_ms,
        },
        AuthOutcome::Authenticated { .. } => AuthOutcome::Unauthenticated,
        other => other,
    }
}

fn enforce_policy_and_project(
    identity: Identity,
    policy: &AccessPolicy,
    expected_project: &str,
) -> Result<Identity, ArmFailure> {
    if !identity_matches_project(&identity, expected_project)
        || !valid_identifier(&identity.shared_user_id)
        || !valid_identifier(&identity.provider_subject)
    {
        return Err(ArmFailure::Invalid);
    }

    let email_allowed = identity.email_verified
        && identity.email.as_deref().is_some_and(|email| {
            let email = email.trim();
            !email.is_empty()
                && email.len() <= 320
                && policy
                    .allowed_emails
                    .iter()
                    .any(|allowed| allowed.trim().eq_ignore_ascii_case(email))
        });
    let role_allowed = identity
        .roles
        .iter()
        .any(|role| policy.allowed_roles.iter().any(|allowed| allowed == role));

    (email_allowed || role_allowed)
        .then_some(identity)
        .ok_or(ArmFailure::Invalid)
}

fn identity_matches_project(identity: &Identity, expected_project: &str) -> bool {
    !expected_project.is_empty()
        && identity.provider == "supabase"
        && identity.provider_tenant == expected_project
        && identity.project.as_deref() == Some(expected_project)
        && identity.supabase_user_id.as_deref() == Some(identity.provider_subject.as_str())
}

fn valid_identifier(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 200
        && !value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
}

fn same_roles(left: &[String], right: &[String]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort_unstable();
    left.dedup();
    right.sort_unstable();
    right.dedup();
    left == right
}

enum Credential {
    Missing,
    Invalid,
    Shared(String),
    Provider(String),
}

fn select_credential(headers: &HeaderMap, shared_issuer: &str) -> Credential {
    if headers.contains_key(header::AUTHORIZATION) {
        return match single_bearer(headers) {
            Some(token) if unverified_iss(&token).as_deref() == Some(shared_issuer) => {
                Credential::Shared(token)
            }
            Some(token) => Credential::Provider(token),
            None => Credential::Invalid,
        };
    }

    match unique_cookie(headers, crate::ORE_SESSION_COOKIE) {
        CookieSelection::Value(token) => return Credential::Shared(token),
        CookieSelection::Invalid => return Credential::Invalid,
        CookieSelection::Missing => {}
    }

    if headers.contains_key(crate::SUPABASE_TOKEN_HEADER) {
        return match single_header(headers, crate::SUPABASE_TOKEN_HEADER) {
            Some(token) => Credential::Provider(token),
            None => Credential::Invalid,
        };
    }

    match unique_cookie(headers, crate::SUPABASE_TOKEN_COOKIE) {
        CookieSelection::Value(token) => Credential::Provider(token),
        CookieSelection::Invalid => Credential::Invalid,
        CookieSelection::Missing => Credential::Missing,
    }
}

fn single_bearer(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty() && token.len() <= MAX_TOKEN_BYTES)
        .map(str::to_string)
}

fn single_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?.trim();
    if values.next().is_some() || value.is_empty() || value.len() > MAX_TOKEN_BYTES {
        return None;
    }
    Some(value.to_string())
}

enum CookieSelection {
    Missing,
    Invalid,
    Value(String),
}

fn unique_cookie(headers: &HeaderMap, expected_name: &str) -> CookieSelection {
    let mut found = None;
    for raw in headers.get_all(header::COOKIE) {
        let Ok(raw) = raw.to_str() else {
            return CookieSelection::Invalid;
        };
        for pair in raw.split(';').map(str::trim) {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if name != expected_name {
                continue;
            }
            let value = value.trim();
            if value.is_empty() || value.len() > MAX_TOKEN_BYTES || found.is_some() {
                return CookieSelection::Invalid;
            }
            found = Some(value.to_string());
        }
    }
    match found {
        Some(value) => CookieSelection::Value(value),
        None => CookieSelection::Missing,
    }
}

fn unverified_iss(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("iss")?.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::to_bytes;
    use axum::extract::{Request, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::{Json, Router};
    use serde_json::json;

    use super::*;

    #[derive(Clone, Copy)]
    enum Scenario {
        SharedWins,
        DirectWins,
        WrongProject,
    }

    async fn handler(State(scenario): State<Scenario>, request: Request) -> Response {
        let path = request.uri().path().to_string();
        let headers = request.headers().clone();
        let (_, body) = request.into_parts();
        let body = to_bytes(body, 64 * 1024).await.unwrap();

        match path.as_str() {
            "/shared/auth/exchange" => exchange_response(scenario),
            "/shared/auth/introspect" => {
                assert_eq!(
                    headers.get("authorization").unwrap().to_str().unwrap(),
                    "Bearer introspect-secret"
                );
                let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(value["contract"], "IntrospectionRequest");
                assert_eq!(value["payload"]["token"], "secret-new-shared-token");
                assert_eq!(value["payload"]["audience"], "fiducia");
                assert_eq!(value["payload"]["requiredScopes"], json!([]));
                introspection_response(scenario)
            }
            "/supabase/auth/v1/user" => provider_response(scenario).await,
            _ => panic!("unexpected path {path}"),
        }
    }

    fn exchange_response(scenario: Scenario) -> Response {
        if matches!(scenario, Scenario::DirectWins) {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let project = project_for(scenario);
        (
            StatusCode::OK,
            Json(json!({
                "access_token": "secret-new-shared-token",
                "shared_user_id": "shared-1",
                "provider": "supabase",
                "provider_tenant": project,
                "provider_subject": "11111111-1111-4111-8111-111111111111",
                "roles": ["customer"]
            })),
        )
            .into_response()
    }

    fn introspection_response(scenario: Scenario) -> Response {
        let project = project_for(scenario);
        (
            StatusCode::OK,
            Json(json!({
                "active": true,
                "sub": "shared-1",
                "provider": "supabase",
                "provider_tenant": project,
                "provider_subject": "11111111-1111-4111-8111-111111111111",
                "project": project,
                "supabase_user_id": "11111111-1111-4111-8111-111111111111",
                "sid": "00000000-0000-4000-8000-000000000001",
                "email": "customer@example.invalid",
                "email_verified": true,
                "roles": ["customer"]
            })),
        )
            .into_response()
    }

    async fn provider_response(scenario: Scenario) -> Response {
        if matches!(scenario, Scenario::WrongProject) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        if matches!(scenario, Scenario::SharedWins) {
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
        (
            StatusCode::OK,
            Json(json!({
                "id": "11111111-1111-4111-8111-111111111111",
                "email": "customer@example.invalid",
                "email_confirmed_at": "2026-08-02T12:00:00Z"
            })),
        )
            .into_response()
    }

    fn project_for(scenario: Scenario) -> &'static str {
        if matches!(scenario, Scenario::WrongProject) {
            "fiducia-admin"
        } else {
            "fiducia-customer"
        }
    }

    async fn server(scenario: Scenario) -> String {
        let app = Router::new().fallback(handler).with_state(scenario);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{address}")
    }

    fn provider_token() -> String {
        let encode = |value: serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
        };
        format!(
            "{}.{}.fixture",
            encode(json!({"alg":"ES256"})),
            encode(json!({"iss":"https://customer.supabase.co/auth/v1"}))
        )
    }

    fn config(base: &str, policy: AccessPolicy) -> AuthGuardConfig {
        AuthGuardConfig {
            guard: crate::GuardConfig {
                authority: AuthorityConfig {
                    shared_auth_base: format!("{base}/shared"),
                    issuer: "https://auth.example.invalid".into(),
                    audience: "fiducia".into(),
                    supabase_url: Some(format!("{base}/supabase")),
                    supabase_api_key: Some("publishable-key".into()),
                    introspect_secret: Some("introspect-secret".into()),
                    arm_timeout: Duration::from_millis(300),
                    ..Default::default()
                },
                supabase_project: Some("fiducia-customer".into()),
                race_deadline: Duration::from_secs(1),
                ..Default::default()
            },
            policy,
        }
    }

    fn provider_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", provider_token()).parse().unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn shared_exchange_returns_a_redacted_session_upgrade() {
        let base = server(Scenario::SharedWins).await;
        let guard = SessionAwareAuthGuard::from_config(&config(
            &base,
            AccessPolicy {
                allowed_roles: vec!["customer".into()],
                allowed_emails: vec![],
            },
        ))
        .unwrap();

        let decision = guard.authorize_with_upgrade(&provider_headers()).await;
        assert!(matches!(
            decision.outcome,
            AuthOutcome::Authenticated {
                authority: Authority::SharedAuth,
                ..
            }
        ));
        let upgrade = decision.session_upgrade.unwrap();
        assert_eq!(upgrade.access_token(), "secret-new-shared-token");
        assert_eq!(
            upgrade.session_id(),
            Some("00000000-0000-4000-8000-000000000001")
        );
        let debug = format!("{upgrade:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("secret-new-shared-token"));
    }

    #[tokio::test]
    async fn direct_provider_success_never_manufactures_a_session_upgrade() {
        let base = server(Scenario::DirectWins).await;
        let guard = SessionAwareAuthGuard::from_config(&config(
            &base,
            AccessPolicy {
                allowed_roles: vec![],
                allowed_emails: vec!["customer@example.invalid".into()],
            },
        ))
        .unwrap();

        let decision = guard.authorize_with_upgrade(&provider_headers()).await;
        assert!(matches!(
            decision.outcome,
            AuthOutcome::Authenticated {
                authority: Authority::Supabase,
                ..
            }
        ));
        assert!(decision.session_upgrade.is_none());
    }

    #[tokio::test]
    async fn wrong_provider_plane_is_rejected_even_when_the_role_matches() {
        let base = server(Scenario::WrongProject).await;
        let guard = SessionAwareAuthGuard::from_config(&config(
            &base,
            AccessPolicy {
                allowed_roles: vec!["customer".into()],
                allowed_emails: vec![],
            },
        ))
        .unwrap();

        let decision = guard.authorize_with_upgrade(&provider_headers()).await;
        assert_eq!(decision.outcome, AuthOutcome::Unauthenticated);
        assert!(decision.session_upgrade.is_none());
    }

    #[tokio::test]
    async fn no_credential_remains_anonymous() {
        let base = server(Scenario::SharedWins).await;
        let guard = SessionAwareAuthGuard::from_config(&config(
            &base,
            AccessPolicy {
                allowed_roles: vec!["customer".into()],
                allowed_emails: vec![],
            },
        ))
        .unwrap();
        let decision = guard.authorize_with_upgrade(&HeaderMap::new()).await;
        assert_eq!(decision.outcome, AuthOutcome::Anonymous);
        assert!(decision.session_upgrade.is_none());
    }
}
