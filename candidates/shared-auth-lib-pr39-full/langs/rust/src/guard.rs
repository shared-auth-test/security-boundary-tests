//! The guard — what a service actually calls.
//!
//! [`Guard::check`] turns request headers into an [`AuthOutcome`]:
//!
//! 1. **Extract** a credential: `Authorization: Bearer`, the `ore_session`
//!    cookie (a shared-auth token), the `sb-access-token` cookie or
//!    `x-supabase-token` header (a Supabase token). Nothing → `Anonymous`.
//! 2. **Route by unverified `iss`.** Our issuer → verify locally against the
//!    shared-auth JWKS (no network on a warm cache; works with Supabase fully
//!    down). Any other issuer → the **dual-auth race**: exchange at shared-auth
//!    vs. verify directly at Supabase, first success wins.
//! 3. `Degraded` is preserved end-to-end: "could not decide" is never rendered
//!    as "logged out".
//!
//! [`Guard::require`] is the ergonomic form for handlers: `Ok(Identity)` or a
//! ready-made limited response (HTML for browsers, JSON otherwise). It is the
//! **human-page** guard — a sandboxed (machine) identity is rejected with a JSON
//! 403; endpoints that intend to serve the non-interactive credential plane use
//! [`Guard::require_any`] instead.
//!
//! ```ignore
//! let guard = Guard::new(GuardConfig { login_url: "/auth/sign-in".into(), ..Default::default() });
//! async fn dashboard(State(guard): State<Arc<Guard>>, headers: HeaderMap) -> Response {
//!     let identity = match guard.require(&headers, Some("/dashboard")).await {
//!         Ok(identity) => identity,
//!         Err(limited) => return limited, // 401/503 + limited HTML or JSON
//!     };
//!     // ... render for identity ...
//! }
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::{header, HeaderMap};
use axum::response::Response;
use jsonwebtoken::jwk::JwkSet;
use shared_auth_interfaces::{AuthOutcome, Authority, Identity, LimitedPage};
use tokio::sync::{Mutex as AsyncMutex, RwLock};

use crate::authority::{
    exchange_at_shared_auth, verify_at_supabase, verify_shared_auth_token, AuthorityConfig,
};
use crate::limited;
use crate::race::{race, ArmFailure};

/// Session cookie carrying a shared-auth token (set by the edge worker / app).
pub const ORE_SESSION_COOKIE: &str = "ore_session";
/// Cookie/header carrying a raw Supabase access token.
pub const SUPABASE_TOKEN_COOKIE: &str = "sb-access-token";
pub const SUPABASE_TOKEN_HEADER: &str = "x-supabase-token";

#[derive(Clone, Debug)]
pub struct GuardConfig {
    /// Endpoints + issuer/audience for both authorities.
    pub authority: AuthorityConfig,
    /// Tenant slug for the direct-Supabase arm (e.g. `fiducia-cloud`).
    /// `None` disables that arm; the race then has only shared-auth.
    pub supabase_project: Option<String>,
    /// Where the limited page sends the user.
    pub login_url: String,
    /// Overall dual-race deadline (SPEC default 1500 ms).
    pub race_deadline: Duration,
    /// JWKS endpoint; defaults to `{shared_auth_base}/.well-known/jwks.json`.
    pub jwks_url: Option<String>,
    /// Fresh window for the cached JWKS.
    pub jwks_ttl: Duration,
    /// Serve a stale JWKS up to this age when a refresh fails (tandem grace).
    pub jwks_grace: Duration,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            authority: AuthorityConfig::default(),
            supabase_project: None,
            login_url: "/auth/sign-in".into(),
            race_deadline: Duration::from_millis(1500),
            jwks_url: None,
            jwks_ttl: Duration::from_secs(600),
            jwks_grace: Duration::from_secs(3600),
        }
    }
}

/// Explicit authorization grants layered over authentication.
///
/// Email grants require a verified address and are compared
/// case-insensitively. Role grants are exact and case-sensitive.
#[derive(Clone, Debug, Default)]
pub struct AccessPolicy {
    pub allowed_emails: Vec<String>,
    pub allowed_roles: Vec<String>,
}

impl AccessPolicy {
    pub fn is_configured(&self) -> bool {
        !self.allowed_emails.is_empty() || !self.allowed_roles.is_empty()
    }

    fn enforce(&self, identity: Identity) -> Result<Identity, ArmFailure> {
        if !valid_identifier(&identity.shared_user_id)
            || !valid_identifier(&identity.provider_subject)
        {
            return Err(ArmFailure::Invalid);
        }

        // A sandboxed (machine) identity never satisfies a human email/role
        // policy. It fails the email/role checks below anyway (empty roles, no
        // verified email), but reject it explicitly so a future sandboxed token
        // that somehow carried a role could not slip through this path.
        if identity.is_sandboxed() {
            return Err(ArmFailure::Invalid);
        }

        let email_allowed = identity.email_verified
            && identity.email.as_deref().is_some_and(|email| {
                let email = email.trim();
                !email.is_empty()
                    && email.len() <= 320
                    && self
                        .allowed_emails
                        .iter()
                        .any(|allowed| allowed.trim().eq_ignore_ascii_case(email))
            });
        let role_allowed = identity
            .roles
            .iter()
            .any(|role| self.allowed_roles.iter().any(|allowed| allowed == role));

        (email_allowed || role_allowed)
            .then_some(identity)
            .ok_or(ArmFailure::Invalid)
    }
}

/// Fail-closed consumer guard configuration.
///
/// Unlike [`GuardConfig`], this requires both authorities and at least one
/// authorization grant. Partial configuration never becomes allow-all.
#[derive(Clone, Debug, Default)]
pub struct AuthGuardConfig {
    pub guard: GuardConfig,
    pub policy: AccessPolicy,
}

impl AuthGuardConfig {
    pub fn is_enabled(&self) -> bool {
        !self.guard.authority.shared_auth_base.trim().is_empty()
            && self
                .guard
                .authority
                .supabase_url
                .as_deref()
                .is_some_and(|url| !url.trim().is_empty())
            && self
                .guard
                .supabase_project
                .as_deref()
                .is_some_and(|project| !project.trim().is_empty())
            && !self.guard.authority.arm_timeout.is_zero()
            && !self.guard.race_deadline.is_zero()
            && self.policy.is_configured()
    }
}

struct JwksCache {
    fetched_at: Instant,
    set: Arc<JwkSet>,
}

pub struct Guard {
    config: GuardConfig,
    http: reqwest::Client,
    /// Pinned key set (config-provided). When set, no fetching ever happens.
    static_jwks: Option<Arc<JwkSet>>,
    cache: RwLock<Option<JwksCache>>,
    refresh_lock: AsyncMutex<()>,
}

impl Guard {
    pub fn new(config: GuardConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
            static_jwks: None,
            cache: RwLock::new(None),
            refresh_lock: AsyncMutex::new(()),
        }
    }

    /// A guard with a pinned JWKS — no network fetches. Useful for tests and for
    /// services that ship the key set via config/secret instead of over HTTP.
    pub fn with_static_jwks(config: GuardConfig, jwks: JwkSet) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
            static_jwks: Some(Arc::new(jwks)),
            cache: RwLock::new(None),
            refresh_lock: AsyncMutex::new(()),
        }
    }

    /// Headers in, [`AuthOutcome`] out. Never panics, never blocks past the
    /// race deadline + one JWKS fetch.
    #[tracing::instrument(name = "shared_auth.guard_check", skip_all)]
    pub async fn check(&self, headers: &HeaderMap) -> AuthOutcome {
        let started = Instant::now();
        let bearer = bearer(headers);
        let ore_cookie = cookie(headers, ORE_SESSION_COOKIE);
        let supa_credential = header_value(headers, SUPABASE_TOKEN_HEADER)
            .or_else(|| cookie(headers, SUPABASE_TOKEN_COOKIE));

        // Split the bearer by unverified issuer: ours verifies locally, anything
        // else is treated as a provider token and raced.
        let (ore_token, foreign_bearer) = match bearer {
            Some(token)
                if unverified_iss(&token).as_deref() == Some(&self.config.authority.issuer) =>
            {
                (Some(token), None)
            }
            Some(token) => (None, Some(token)),
            None => (None, None),
        };
        let ore_token = ore_token.or(ore_cookie);
        let supa_token = supa_credential.or(foreign_bearer);

        if ore_token.is_none() && supa_token.is_none() {
            return AuthOutcome::Anonymous;
        }

        // Fast path: a shared-auth token verified against the (cached) JWKS.
        let mut ore_failure: Option<ArmFailure> = None;
        if let Some(token) = &ore_token {
            match self.verify_ours(token).await {
                Ok(identity) => {
                    return AuthOutcome::Authenticated {
                        identity: Box::new(identity),
                        authority: Authority::SharedAuth,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    };
                }
                Err(failure) => ore_failure = Some(failure),
            }
        }

        // Race path: a provider token, decided by whichever authority answers first.
        if let Some(token) = &supa_token {
            let cfg = &self.config.authority;
            let project = self.config.supabase_project.as_deref().unwrap_or("");
            let shared_arm = exchange_at_shared_auth(&self.http, token, cfg);
            let supabase_arm = async {
                if self.config.supabase_project.is_none() {
                    // Arm disabled: indefinite, so it can never turn a shared-auth
                    // outage into "logged out".
                    Err(ArmFailure::Unavailable)
                } else {
                    verify_at_supabase(&self.http, token, project, cfg).await
                }
            };
            return race(shared_arm, supabase_arm, self.config.race_deadline).await;
        }

        // Only a shared-auth token was presented and it did not verify.
        match ore_failure {
            Some(ArmFailure::Invalid) => AuthOutcome::Unauthenticated,
            _ => AuthOutcome::Degraded {
                reason: "shared-auth key set unavailable".into(),
            },
        }
    }

    /// Human-page guard: `Ok(identity)` for an **interactive** identity, or a
    /// finished limited response.
    ///
    /// A **sandboxed** identity (a machine credential — SSH key, etc.) is
    /// rejected here with a JSON 403, *not* an HTML sign-in page: it is
    /// authenticated but cannot sign in, and a human-only resource is not its to
    /// reach. This is the safe default — an endpoint that intentionally serves
    /// the sandboxed plane must opt in via [`Self::require_any`] or inspect
    /// [`Identity::is_sandboxed`] after [`Self::check`]. (401 unauthenticated /
    /// 503 degraded; HTML for browsers, JSON otherwise.)
    // Axum's concrete Response is intentionally the public rejection type.
    #[allow(clippy::result_large_err)]
    pub async fn require(
        &self,
        headers: &HeaderMap,
        return_to: Option<&str>,
    ) -> Result<Identity, Response> {
        match self.check(headers).await {
            AuthOutcome::Authenticated { identity, .. } if identity.is_sandboxed() => {
                Err(limited::forbidden_sandboxed(identity.cred.as_deref()))
            }
            AuthOutcome::Authenticated { identity, .. } => Ok(*identity),
            AuthOutcome::Anonymous | AuthOutcome::Unauthenticated => Err(limited::response(
                headers,
                &LimitedPage {
                    status_code: 401,
                    login_url: self.config.login_url.clone(),
                    return_to: return_to.map(str::to_string),
                    reason: "This page requires an account.".into(),
                },
            )),
            AuthOutcome::Degraded { .. } => Err(limited::response(
                headers,
                &LimitedPage {
                    status_code: 503,
                    login_url: self.config.login_url.clone(),
                    return_to: return_to.map(str::to_string),
                    reason: "Sign-in is temporarily unavailable. Please try again shortly.".into(),
                },
            )),
        }
    }

    /// Like [`Self::require`], but also accepts a **sandboxed** identity. For the
    /// endpoints that intentionally serve the non-interactive credential plane
    /// (a machine calling with a registered key). The caller is expected to
    /// authorize by `scope`/`cred` itself — this only asserts authentication.
    // Keep the same stable response-shaped API as `require`.
    #[allow(clippy::result_large_err)]
    pub async fn require_any(
        &self,
        headers: &HeaderMap,
        return_to: Option<&str>,
    ) -> Result<Identity, Response> {
        match self.check(headers).await {
            AuthOutcome::Authenticated { identity, .. } => Ok(*identity),
            AuthOutcome::Anonymous | AuthOutcome::Unauthenticated => Err(limited::response(
                headers,
                &LimitedPage {
                    status_code: 401,
                    login_url: self.config.login_url.clone(),
                    return_to: return_to.map(str::to_string),
                    reason: "This resource requires authentication.".into(),
                },
            )),
            AuthOutcome::Degraded { .. } => Err(limited::response(
                headers,
                &LimitedPage {
                    status_code: 503,
                    login_url: self.config.login_url.clone(),
                    return_to: return_to.map(str::to_string),
                    reason: "Authentication is temporarily unavailable. Please try again shortly."
                        .into(),
                },
            )),
        }
    }

    /// Verify one of our tokens, refreshing the JWKS once on an unknown `kid`.
    async fn verify_ours(&self, token: &str) -> Result<Identity, ArmFailure> {
        let (jwks, just_fetched) = match self.current_jwks(false).await {
            Some(pair) => pair,
            None => return Err(ArmFailure::Unavailable),
        };
        match verify_shared_auth_token(token, &jwks, &self.config.authority) {
            // Unknown kid on a cached set may just mean rotation — refetch once.
            Err(ArmFailure::Unavailable) if !just_fetched && self.static_jwks.is_none() => {
                match self.current_jwks(true).await {
                    Some((fresh, _)) => {
                        verify_shared_auth_token(token, &fresh, &self.config.authority)
                    }
                    None => Err(ArmFailure::Unavailable),
                }
            }
            other => other,
        }
    }

    /// The JWKS to verify with: pinned set, fresh cache, fetched, or
    /// stale-within-grace. The bool reports whether this call fetched.
    async fn current_jwks(&self, force_fetch: bool) -> Option<(Arc<JwkSet>, bool)> {
        if let Some(pinned) = &self.static_jwks {
            return Some((pinned.clone(), false));
        }

        if !force_fetch {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.as_ref() {
                if entry.fetched_at.elapsed() < self.config.jwks_ttl {
                    return Some((entry.set.clone(), false));
                }
            }
        }

        let _guard = self.refresh_lock.lock().await;
        // Another waiter may have refreshed while we queued on the lock.
        if !force_fetch {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.as_ref() {
                if entry.fetched_at.elapsed() < self.config.jwks_ttl {
                    return Some((entry.set.clone(), false));
                }
            }
        }

        let url = self.jwks_url();
        let fetched = async {
            let resp = self
                .http
                .get(&url)
                .timeout(self.config.authority.arm_timeout)
                .send()
                .await
                .ok()?;
            if !resp.status().is_success() {
                return None;
            }
            resp.json::<JwkSet>().await.ok()
        }
        .await;

        match fetched {
            Some(set) => {
                let set = Arc::new(set);
                *self.cache.write().await = Some(JwksCache {
                    fetched_at: Instant::now(),
                    set: set.clone(),
                });
                Some((set, true))
            }
            None => {
                // Tandem grace: a recent-enough stale set still verifies.
                let cache = self.cache.read().await;
                cache.as_ref().and_then(|entry| {
                    (entry.fetched_at.elapsed() < self.config.jwks_grace)
                        .then(|| (entry.set.clone(), false))
                })
            }
        }
    }

    fn jwks_url(&self) -> String {
        self.config.jwks_url.clone().unwrap_or_else(|| {
            format!(
                "{}/.well-known/jwks.json",
                self.config.authority.shared_auth_base.trim_end_matches('/')
            )
        })
    }
}

/// Authentication plus an explicit verified-email or exact-role policy.
///
/// Policy is enforced independently inside both provider-token race arms, so a
/// fast provider response without roles cannot mask a slightly slower
/// shared-auth response that carries a valid role grant.
pub struct AuthGuard {
    guard: Guard,
    policy: AccessPolicy,
}

impl AuthGuard {
    pub fn from_config(config: &AuthGuardConfig) -> Option<Self> {
        config.is_enabled().then(|| Self {
            guard: Guard::new(config.guard.clone()),
            policy: config.policy.clone(),
        })
    }

    pub fn with_static_jwks(config: &AuthGuardConfig, jwks: JwkSet) -> Option<Self> {
        config.is_enabled().then(|| Self {
            guard: Guard::with_static_jwks(config.guard.clone(), jwks),
            policy: config.policy.clone(),
        })
    }

    /// Authenticate through the configured authorities and apply authorization
    /// before either race arm may win.
    #[tracing::instrument(
        name = "shared_auth.authorize",
        skip_all,
        fields(
            auth.outcome = tracing::field::Empty,
            auth.authority = tracing::field::Empty,
        )
    )]
    pub async fn authorize(&self, headers: &HeaderMap) -> AuthOutcome {
        let started = Instant::now();
        let bearer = bearer(headers);
        let ore_cookie = cookie(headers, ORE_SESSION_COOKIE);
        let provider_credential = header_value(headers, SUPABASE_TOKEN_HEADER)
            .or_else(|| cookie(headers, SUPABASE_TOKEN_COOKIE));

        let (ore_token, foreign_bearer) = match bearer {
            Some(token)
                if unverified_iss(&token).as_deref()
                    == Some(&self.guard.config.authority.issuer) =>
            {
                (Some(token), None)
            }
            Some(token) => (None, Some(token)),
            None => (None, None),
        };
        let ore_token = ore_token.or(ore_cookie);
        let provider_token = provider_credential.or(foreign_bearer);

        if ore_token.is_none() && provider_token.is_none() {
            return self.record_outcome(AuthOutcome::Anonymous);
        }

        let mut ore_failure = None;
        if let Some(token) = &ore_token {
            match self
                .guard
                .verify_ours(token)
                .await
                .and_then(|identity| self.policy.enforce(identity))
            {
                Ok(identity) => {
                    return self.record_outcome(AuthOutcome::Authenticated {
                        identity: Box::new(identity),
                        authority: Authority::SharedAuth,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    });
                }
                Err(failure) => ore_failure = Some(failure),
            }
        }

        if let Some(token) = &provider_token {
            let authority = &self.guard.config.authority;
            let project = self.guard.config.supabase_project.as_deref().unwrap_or("");
            let shared_arm = async {
                self.policy
                    .enforce(exchange_at_shared_auth(&self.guard.http, token, authority).await?)
            };
            let provider_arm = async {
                self.policy
                    .enforce(verify_at_supabase(&self.guard.http, token, project, authority).await?)
            };
            let outcome = race(shared_arm, provider_arm, self.guard.config.race_deadline).await;
            return self.record_outcome(outcome);
        }

        self.record_outcome(match ore_failure {
            Some(ArmFailure::Invalid) => AuthOutcome::Unauthenticated,
            _ => AuthOutcome::Degraded {
                reason: "shared-auth key set unavailable".into(),
            },
        })
    }

    fn record_outcome(&self, outcome: AuthOutcome) -> AuthOutcome {
        let span = tracing::Span::current();
        match &outcome {
            AuthOutcome::Authenticated { authority, .. } => {
                span.record("auth.outcome", "authenticated");
                span.record("auth.authority", tracing::field::debug(authority));
                tracing::info!(auth.authority = ?authority, "shared authorization succeeded");
            }
            AuthOutcome::Anonymous => {
                span.record("auth.outcome", "anonymous");
            }
            AuthOutcome::Unauthenticated => {
                span.record("auth.outcome", "unauthenticated");
                tracing::warn!("shared authorization rejected credential or policy");
            }
            AuthOutcome::Degraded { .. } => {
                span.record("auth.outcome", "degraded");
                tracing::warn!("shared authorization authorities unavailable");
            }
        }
        outcome
    }
}

fn valid_identifier(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 200
        && !value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
}

// ---- header/cookie extraction ----

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)?
        .to_str()
        .ok()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').map(str::trim).find_map(|pair| {
        pair.strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    })
}

/// Read `iss` WITHOUT verifying — routing only. The verifying arm re-pins `iss`,
/// so a forged issuer only ever selects an arm that will reject the signature.
fn unverified_iss(token: &str) -> Option<String> {
    use base64::Engine;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("iss")?.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};

    fn pem() -> String {
        p256::SecretKey::from_slice(&[5u8; 32])
            .unwrap()
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn jwks(kid: &str) -> JwkSet {
        let sk = p256::SecretKey::from_pkcs8_pem(&pem()).unwrap();
        let mut jwk = serde_json::to_value(sk.public_key().to_jwk()).unwrap();
        let o = jwk.as_object_mut().unwrap();
        o.insert("kid".into(), kid.into());
        o.insert("alg".into(), "ES256".into());
        o.insert("use".into(), "sig".into());
        serde_json::from_value(serde_json::json!({ "keys": [jwk] })).unwrap()
    }

    fn ore_token(exp_delta: i64) -> String {
        let mut h = Header::new(Algorithm::ES256);
        h.kid = Some("k1".into());
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": "shared-1",
            "provider": "supabase",
            "provider_tenant": "fiducia-cloud",
            "provider_subject": "sup-1",
            "project": "fiducia-cloud",
            "supabase_user_id": "sup-1",
            "email": "a@b.co", "email_verified": true,
            "roles": ["user"],
            "iss": "https://auth.test", "aud": "ore",
            "iat": now,
            "nbf": now - 5,
            "exp": now + exp_delta,
        });
        jsonwebtoken::encode(
            &h,
            &claims,
            &EncodingKey::from_ec_pem(pem().as_bytes()).unwrap(),
        )
        .unwrap()
    }

    /// A token on the sandboxed plane: `cred=ssh_key`, empty roles, no email —
    /// exactly what the server's `mint_sandboxed` produces.
    fn ore_token_sandboxed(exp_delta: i64) -> String {
        let mut h = Header::new(Algorithm::ES256);
        h.kid = Some("k1".into());
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": "shared-42",
            "provider": "ssh_key",
            "provider_tenant": "default",
            "provider_subject": "SHA256:abc",
            "email_verified": false,
            "roles": [],
            "amr": ["ssh_key"],
            "acr": "urn:oresoftware:loa:1",
            "cred": "ssh_key",
            "iss": "https://auth.test", "aud": "ore",
            "iat": now,
            "nbf": now - 5,
            "exp": now + exp_delta,
        });
        jsonwebtoken::encode(
            &h,
            &claims,
            &EncodingKey::from_ec_pem(pem().as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn guard() -> Guard {
        let config = GuardConfig {
            authority: AuthorityConfig {
                // Dead addresses: any network arm is Unavailable, never a hang.
                shared_auth_base: "http://127.0.0.1:1".into(),
                issuer: "https://auth.test".into(),
                audience: "ore".into(),
                supabase_url: Some("http://127.0.0.1:1".into()),
                supabase_api_key: None,
                introspect_secret: None,
                arm_timeout: Duration::from_millis(200),
                ..Default::default()
            },
            supabase_project: Some("fiducia-cloud".into()),
            login_url: "/auth/sign-in".into(),
            race_deadline: Duration::from_millis(600),
            ..Default::default()
        };
        Guard::with_static_jwks(config, jwks("k1"))
    }

    fn headers(pairs: &[(&str, String)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    #[tokio::test]
    async fn bearer_ore_token_authenticates_offline() {
        let g = guard();
        let h = headers(&[("authorization", format!("Bearer {}", ore_token(3600)))]);
        let outcome = g.check(&h).await;
        match outcome {
            AuthOutcome::Authenticated {
                identity,
                authority,
                ..
            } => {
                assert_eq!(authority, Authority::SharedAuth);
                assert_eq!(identity.shared_user_id, "shared-1");
                assert_eq!(identity.provider_tenant, "fiducia-cloud");
            }
            other => panic!("expected authenticated, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sandboxed_token_authenticates_but_is_marked() {
        let g = guard();
        let h = headers(&[(
            "authorization",
            format!("Bearer {}", ore_token_sandboxed(3600)),
        )]);
        match g.check(&h).await {
            AuthOutcome::Authenticated { identity, .. } => {
                assert!(identity.is_sandboxed());
                assert_eq!(identity.cred.as_deref(), Some("ssh_key"));
                assert!(identity.roles.is_empty());
            }
            other => panic!("expected authenticated, got {other:?}"),
        }
    }

    // The core DEN-2834 guarantee: a machine credential does not reach a
    // human-only guard, and it gets a JSON 403 rather than an HTML sign-in page
    // even when it asks for HTML.
    #[tokio::test]
    async fn require_rejects_a_sandboxed_identity_with_json_403() {
        let g = guard();
        let h = headers(&[
            (
                "authorization",
                format!("Bearer {}", ore_token_sandboxed(3600)),
            ),
            ("accept", "text/html".into()),
        ]);
        let response = g.require(&h, Some("/dashboard")).await.unwrap_err();
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            content_type.contains("application/json"),
            "got {content_type}"
        );
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "forbidden_sandboxed");
        assert_eq!(json["cred"], "ssh_key");
    }

    #[tokio::test]
    async fn require_any_admits_a_sandboxed_identity() {
        let g = guard();
        let h = headers(&[(
            "authorization",
            format!("Bearer {}", ore_token_sandboxed(3600)),
        )]);
        let identity = g.require_any(&h, None).await.unwrap();
        assert!(identity.is_sandboxed());
        assert_eq!(identity.shared_user_id, "shared-42");
        // ...while an interactive identity still passes the strict require().
        let hi = headers(&[("authorization", format!("Bearer {}", ore_token(3600)))]);
        assert!(g.require(&hi, None).await.is_ok());
    }

    #[tokio::test]
    async fn ore_session_cookie_authenticates() {
        let g = guard();
        let h = headers(&[(
            "cookie",
            format!("a=b; {}={}", ORE_SESSION_COOKIE, ore_token(3600)),
        )]);
        assert!(g.check(&h).await.is_authenticated());
    }

    #[tokio::test]
    async fn no_credential_is_anonymous_and_requires_limited_html() {
        let g = guard();
        let outcome = g.check(&HeaderMap::new()).await;
        assert_eq!(outcome, AuthOutcome::Anonymous);

        let h = headers(&[("accept", "text/html".to_string())]);
        let resp = g.require(&h, Some("/dashboard")).await.unwrap_err();
        assert_eq!(resp.status(), 401);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Sign in required"));
        assert!(html.contains("/auth/sign-in?return=/dashboard"));
    }

    #[tokio::test]
    async fn api_callers_get_json_not_html() {
        let g = guard();
        let resp = g.require(&HeaderMap::new(), None).await.unwrap_err();
        assert_eq!(resp.status(), 401);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "unauthorized");
    }

    #[tokio::test]
    async fn expired_ore_token_is_unauthenticated() {
        let g = guard();
        let h = headers(&[("authorization", format!("Bearer {}", ore_token(-7200)))]);
        assert_eq!(g.check(&h).await, AuthOutcome::Unauthenticated);
    }

    // Foreign-issuer bearer + both authorities dead → Degraded (503), and the
    // limited page says "unavailable", never "signed out".
    #[tokio::test]
    async fn provider_token_with_both_authorities_down_is_degraded() {
        let g = guard();
        let h = headers(&[
            ("authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL3guc3VwYWJhc2UuY28vYXV0aC92MSJ9.sig".to_string()),
            ("accept", "text/html".to_string()),
        ]);
        let outcome = g.check(&h).await;
        assert!(
            matches!(outcome, AuthOutcome::Degraded { .. }),
            "got {outcome:?}"
        );

        let resp = g.require(&h, None).await.unwrap_err();
        assert_eq!(resp.status(), 503);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("temporarily unavailable"));
    }

    #[tokio::test]
    async fn cookie_parsing_finds_named_cookie() {
        let h = headers(&[("cookie", "x=1; ore_session=tok; y=2".to_string())]);
        assert_eq!(cookie(&h, ORE_SESSION_COOKIE).as_deref(), Some("tok"));
        assert_eq!(cookie(&h, "missing"), None);
    }

    #[tokio::test]
    async fn unverified_iss_reads_payload() {
        let token = ore_token(3600);
        assert_eq!(unverified_iss(&token).as_deref(), Some("https://auth.test"));
        assert_eq!(unverified_iss("junk"), None);
    }

    fn policy_identity(email: Option<&str>, verified: bool, roles: &[&str]) -> Identity {
        Identity {
            shared_user_id: "shared-user-1".into(),
            provider: "supabase".into(),
            provider_tenant: "fiducia-cloud".into(),
            provider_subject: "provider-user-1".into(),
            project: Some("fiducia-cloud".into()),
            supabase_user_id: Some("provider-user-1".into()),
            session_id: None,
            email: email.map(str::to_string),
            email_verified: verified,
            roles: roles.iter().map(|role| (*role).to_string()).collect(),
            amr: vec![],
            acr: None,
            cred: None,
            authority: Authority::SharedAuth,
        }
    }

    fn auth_guard_config() -> AuthGuardConfig {
        AuthGuardConfig {
            guard: GuardConfig {
                authority: AuthorityConfig {
                    shared_auth_base: "http://127.0.0.1:1".into(),
                    issuer: "https://auth.test".into(),
                    audience: "ore".into(),
                    supabase_url: Some("http://127.0.0.1:1".into()),
                    supabase_api_key: None,
                    introspect_secret: Some("injected-at-runtime".into()),
                    arm_timeout: Duration::from_millis(200),
                    ..Default::default()
                },
                supabase_project: Some("fiducia-cloud".into()),
                race_deadline: Duration::from_millis(600),
                ..Default::default()
            },
            policy: AccessPolicy {
                allowed_emails: vec!["operator@example.com".into(), "a@b.co".into()],
                allowed_roles: vec!["daedalus-operator".into()],
            },
        }
    }

    #[test]
    fn auth_guard_requires_two_authorities_and_an_explicit_policy() {
        let mut candidate = auth_guard_config();
        assert!(candidate.is_enabled());
        assert!(AuthGuard::from_config(&candidate).is_some());

        candidate.guard.authority.shared_auth_base.clear();
        assert!(!candidate.is_enabled());
        candidate = auth_guard_config();
        candidate.guard.authority.supabase_url = None;
        assert!(!candidate.is_enabled());
        candidate = auth_guard_config();
        candidate.policy.allowed_emails.clear();
        candidate.policy.allowed_roles.clear();
        assert!(!candidate.is_enabled());
    }

    #[test]
    fn verified_email_or_exact_role_can_authorize() {
        let policy = auth_guard_config().policy;
        assert!(policy
            .enforce(policy_identity(Some(" Operator@Example.com "), true, &[]))
            .is_ok());
        assert!(policy
            .enforce(policy_identity(None, false, &["daedalus-operator"]))
            .is_ok());
    }

    #[test]
    fn unverified_unlisted_or_malformed_identity_is_rejected() {
        let policy = auth_guard_config().policy;
        assert_eq!(
            policy.enforce(policy_identity(Some("operator@example.com"), false, &[])),
            Err(ArmFailure::Invalid)
        );
        assert_eq!(
            policy.enforce(policy_identity(
                Some("other@example.com"),
                true,
                &["viewer"]
            )),
            Err(ArmFailure::Invalid)
        );

        let mut malformed = policy_identity(None, false, &["daedalus-operator"]);
        malformed.shared_user_id = "../admin".into();
        assert_eq!(policy.enforce(malformed), Err(ArmFailure::Invalid));
    }

    #[tokio::test]
    async fn auth_guard_applies_policy_to_locally_verified_tokens() {
        let guard = AuthGuard::with_static_jwks(&auth_guard_config(), jwks("k1"))
            .expect("complete auth guard config");
        let request = headers(&[("authorization", format!("Bearer {}", ore_token(3600)))]);
        assert!(guard.authorize(&request).await.is_authenticated());
    }
}
