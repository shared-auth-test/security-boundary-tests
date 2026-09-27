//! The two race arms: shared-auth and Supabase.
//!
//! Each returns [`ArmResult`] — an `Identity` on success, or an [`ArmFailure`]
//! that distinguishes **Invalid** (definite: the credential is bad) from
//! **Unavailable** (indefinite: transport/5xx). That distinction is what lets
//! the race tell "logged out" apart from "we couldn't decide".

use std::{fmt, time::Duration};

use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use shared_auth_interfaces::{Authority, Identity};

use crate::race::{ArmFailure, ArmResult};

/// One product-spoke (or hub) Supabase project a consumer may race against.
///
/// Product servers usually have a single backend. Gateways that sit in front of
/// several GitHub orgs populate one entry per `auth.<product-domain>` project.
/// Keys stay in the runtime environment; this type only holds already-resolved
/// values and redacts them in `Debug`.
#[derive(Clone)]
pub struct SupabaseBackend {
    pub name: String,
    pub url: String,
    pub api_key: Option<String>,
}

impl fmt::Debug for SupabaseBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupabaseBackend")
            .field("name", &self.name)
            .field("url", &self.url)
            .field("api_key", &self.api_key.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[derive(Deserialize)]
struct ProjectMeta {
    name: String,
    #[serde(default)]
    project_ref: Option<String>,
    #[serde(default)]
    auth_host: Option<String>,
    #[serde(default)]
    publishable_key_env: Option<String>,
}

impl SupabaseBackend {
    /// Conventional Fiducia/flags-2-env name for a per-org publishable key.
    /// `sonus-auris` → `AUTH_SUPABASE_SONUS_AURIS_PUBLISHABLE_KEY`.
    pub fn conventional_publishable_key_env(name: &str) -> String {
        let slug = name.to_ascii_uppercase().replace('-', "_");
        format!("AUTH_SUPABASE_{slug}_PUBLISHABLE_KEY")
    }

    /// Parse `AUTH_SUPABASE_PROJECTS` metadata. Extra fields (role, org, refs)
    /// are ignored so the same JSON the authority server uses is valid here.
    /// Malformed JSON or an entry without `auth_host` or `project_ref` is an
    /// error so a broken registry cannot start as "no backends".
    pub fn from_projects_json(
        raw: &str,
        mut lookup: impl FnMut(&str) -> Option<String>,
    ) -> Result<Vec<Self>, String> {
        let projects: Vec<ProjectMeta> = serde_json::from_str(raw)
            .map_err(|error| format!("AUTH_SUPABASE_PROJECTS is not valid JSON: {error}"))?;
        let mut backends = Vec::with_capacity(projects.len());
        for project in projects {
            let name = project.name.trim();
            if name.is_empty() {
                return Err("AUTH_SUPABASE_PROJECTS entry is missing name".into());
            }
            let url = origin_from_project_meta(&project)?;
            let env_name = project
                .publishable_key_env
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| Self::conventional_publishable_key_env(name));
            backends.push(Self {
                name: name.to_string(),
                url,
                api_key: lookup(&env_name).filter(|value| !value.is_empty()),
            });
        }
        Ok(backends)
    }
}

fn origin_from_project_meta(project: &ProjectMeta) -> Result<String, String> {
    if let Some(host) = project
        .auth_host
        .as_deref()
        .map(str::trim)
        .filter(|host| !host.is_empty())
    {
        let host = host
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        if host.is_empty() {
            return Err(format!(
                "AUTH_SUPABASE_PROJECTS entry '{}' has an empty auth_host",
                project.name
            ));
        }
        return Ok(format!("https://{host}"));
    }
    if let Some(project_ref) = project
        .project_ref
        .as_deref()
        .map(str::trim)
        .filter(|project_ref| !project_ref.is_empty())
    {
        return Ok(format!("https://{project_ref}.supabase.co"));
    }
    Err(format!(
        "AUTH_SUPABASE_PROJECTS entry '{}' needs auth_host or project_ref",
        project.name
    ))
}

#[derive(Debug, Deserialize)]
struct ExchangeResponse {
    access_token: String,
    shared_user_id: String,
    provider: String,
    provider_tenant: String,
    provider_subject: String,
    roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
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

/// Where the arms point and how patient they are.
#[derive(Clone)]
pub struct AuthorityConfig {
    /// shared-auth base URL, e.g. `https://gateway/shared-auth`.
    pub shared_auth_base: String,
    /// Expected `iss`/`aud` on shared-auth tokens.
    pub issuer: String,
    pub audience: String,
    /// Supabase project URL, e.g. `https://<ref>.supabase.co` or a custom
    /// `https://auth.sonusauris.app`. Prefer `supabase_backends` when more than
    /// one GitHub org is in play.
    pub supabase_url: Option<String>,
    /// Supabase anon/publishable key used by `/auth/v1/user` when required.
    pub supabase_api_key: Option<String>,
    /// Per-product Supabase backends. When empty, `supabase_url` is the sole spoke.
    pub supabase_backends: Vec<SupabaseBackend>,
    /// Service credential for `POST /auth/introspect`.
    ///
    /// This must match the server's `AUTH_INTROSPECT_SECRET` and should be
    /// injected by the runtime secret manager. It is never included in `Debug`.
    pub introspect_secret: Option<String>,
    /// Per-arm timeout (the race also has its own overall deadline).
    pub arm_timeout: Duration,
}

impl AuthorityConfig {
    /// Resolve the spoke (or hub) backend for `project`. Named backends win;
    /// otherwise the single `supabase_url` is used for any project name.
    pub fn supabase_backend(&self, project: &str) -> Option<(&str, Option<&str>)> {
        if let Some(backend) = self
            .supabase_backends
            .iter()
            .find(|backend| backend.name == project)
        {
            return Some((backend.url.as_str(), backend.api_key.as_deref()));
        }
        self.supabase_url
            .as_deref()
            .map(|url| (url, self.supabase_api_key.as_deref()))
    }
}

impl fmt::Debug for AuthorityConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityConfig")
            .field("shared_auth_base", &self.shared_auth_base)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("supabase_url", &self.supabase_url)
            .field(
                "supabase_api_key",
                &self.supabase_api_key.as_ref().map(|_| "[redacted]"),
            )
            .field("supabase_backends", &self.supabase_backends)
            .field(
                "introspect_secret",
                &self.introspect_secret.as_ref().map(|_| "[redacted]"),
            )
            .field("arm_timeout", &self.arm_timeout)
            .finish()
    }
}

impl Default for AuthorityConfig {
    fn default() -> Self {
        Self {
            shared_auth_base: String::new(),
            issuer: "https://auth.oresoftware.dev".into(),
            audience: "oresoftware".into(),
            supabase_url: None,
            supabase_api_key: None,
            supabase_backends: Vec::new(),
            introspect_secret: None,
            arm_timeout: Duration::from_millis(1200),
        }
    }
}

/// Claims we read off a shared-auth token.
#[derive(Debug, Deserialize)]
struct OreClaims {
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

/// Verify a **shared-auth** token locally against its JWKS. No network call when
/// the JWKS is already cached — this is normally the fastest arm, and it works
/// even when Supabase is completely down.
#[tracing::instrument(
    name = "shared_auth.verify_access_token",
    skip(token, jwks, cfg),
    fields(auth.authority = "shared-auth", auth.token_bytes = token.len())
)]
pub fn verify_shared_auth_token(token: &str, jwks: &JwkSet, cfg: &AuthorityConfig) -> ArmResult {
    if token.len() > 16 * 1024 {
        return Err(ArmFailure::Invalid);
    }
    let header = decode_header(token).map_err(|_| ArmFailure::Invalid)?;
    if header.alg != Algorithm::ES256 {
        return Err(ArmFailure::Invalid);
    }
    let kid = header.kid.ok_or(ArmFailure::Invalid)?;
    let key = jwks
        .find(&kid)
        .and_then(|j| DecodingKey::from_jwk(j).ok())
        // A kid we have no key for is not proof the token is bad — we simply
        // cannot decide with what we hold.
        .ok_or(ArmFailure::Unavailable)?;

    let mut v = Validation::new(header.alg);
    v.set_issuer(&[cfg.issuer.as_str()]);
    v.set_audience(&[cfg.audience.as_str()]);
    v.validate_exp = true;
    v.validate_nbf = true;
    v.set_required_spec_claims(&["exp", "iss", "aud", "sub", "iat", "nbf"]);

    let claims = decode::<OreClaims>(token, &key, &v)
        .map_err(|_| ArmFailure::Invalid)?
        .claims;

    Ok(Identity {
        shared_user_id: claims.sub,
        provider: claims.provider,
        provider_tenant: claims.provider_tenant,
        provider_subject: claims.provider_subject,
        project: claims.project,
        supabase_user_id: claims.supabase_user_id,
        session_id: claims.sid,
        email: claims.email,
        email_verified: claims.email_verified,
        roles: claims.roles,
        amr: claims.amr,
        acr: claims.acr,
        cred: claims.cred,
        authority: Authority::SharedAuth,
    })
}

/// Exchange a **Supabase** token at shared-auth (`POST /auth/exchange`). Used when
/// the caller presents a Supabase token rather than one of ours.
#[tracing::instrument(
    name = "shared_auth.exchange",
    skip(http, supabase_token, cfg),
    fields(auth.provider = "supabase", auth.token_bytes = supabase_token.len())
)]
pub async fn exchange_at_shared_auth(
    http: &reqwest::Client,
    supabase_token: &str,
    cfg: &AuthorityConfig,
) -> ArmResult {
    let base = cfg.shared_auth_base.trim_end_matches('/');
    let exchange_url = format!("{}/auth/exchange", base);
    let resp = http
        .post(exchange_url)
        .bearer_auth(supabase_token)
        .timeout(cfg.arm_timeout)
        .send()
        .await
        .map_err(|_| ArmFailure::Unavailable)?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ArmFailure::Invalid);
    }
    if !resp.status().is_success() {
        return Err(ArmFailure::Unavailable);
    }
    let body: ExchangeResponse = resp.json().await.map_err(|_| ArmFailure::Unavailable)?;

    // The exchange response intentionally omits email claims. Introspect the
    // newly minted shared token so email-based consumer policy is evaluated on
    // shared-auth's signed, revocation-aware identity instead of silently
    // depending on the direct provider arm.
    let introspect_url = format!("{base}/auth/introspect");
    let mut request = http
        .post(introspect_url)
        .json(&protected_introspection_body(
            &body.access_token,
            &cfg.audience,
        ))
        .timeout(cfg.arm_timeout);
    if let Some(secret) = cfg.introspect_secret.as_deref() {
        request = request.bearer_auth(secret);
    }
    let resp = request.send().await.map_err(|_| ArmFailure::Unavailable)?;
    if !resp.status().is_success() {
        return Err(ArmFailure::Unavailable);
    }
    let claims: IntrospectResponse = resp.json().await.map_err(|_| ArmFailure::Unavailable)?;
    identity_from_exchange(body, claims)
}

fn identity_from_exchange(exchange: ExchangeResponse, claims: IntrospectResponse) -> ArmResult {
    // A successful exchange followed by inactive or contradictory claims means
    // the authority could not provide a coherent verdict. That is degraded,
    // not evidence that the caller's original credential was invalid.
    if !claims.active
        || claims.sub != exchange.shared_user_id
        || claims.provider != exchange.provider
        || claims.provider_tenant != exchange.provider_tenant
        || claims.provider_subject != exchange.provider_subject
        || !same_roles(&claims.roles, &exchange.roles)
        || (exchange.provider == "supabase"
            && (claims.project.as_deref() != Some(exchange.provider_tenant.as_str())
                || claims.supabase_user_id.as_deref() != Some(exchange.provider_subject.as_str())))
    {
        return Err(ArmFailure::Unavailable);
    }

    Ok(Identity {
        shared_user_id: claims.sub,
        provider: claims.provider,
        provider_tenant: claims.provider_tenant,
        provider_subject: claims.provider_subject,
        project: claims.project,
        supabase_user_id: claims.supabase_user_id,
        session_id: claims.sid,
        email: claims.email,
        email_verified: claims.email_verified,
        roles: claims.roles,
        amr: claims.amr,
        acr: claims.acr,
        cred: claims.cred,
        authority: Authority::SharedAuth,
    })
}

/// Canonical protected-introspection envelope. The server rejects the legacy
/// `{ "token": ... }` body with `deny_unknown_fields`.
pub(crate) fn protected_introspection_body(token: &str, audience: &str) -> serde_json::Value {
    serde_json::json!({
        "contract": "IntrospectionRequest",
        "payload": {
            "token": token,
            "audience": audience,
            "requiredScopes": []
        }
    })
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

/// Validate a Supabase access token **directly against Supabase**
/// (`GET /auth/v1/user`). The independent arm: it holds even if shared-auth is
/// entirely down.
#[tracing::instrument(
    name = "shared_auth.verify_provider",
    skip(http, token, cfg),
    fields(auth.provider = "supabase", auth.provider_tenant = project, auth.token_bytes = token.len())
)]
pub async fn verify_at_supabase(
    http: &reqwest::Client,
    token: &str,
    project: &str,
    cfg: &AuthorityConfig,
) -> ArmResult {
    #[derive(Deserialize)]
    struct SupabaseUser {
        id: String,
        #[serde(default)]
        email: Option<String>,
        #[serde(default)]
        email_confirmed_at: Option<String>,
    }

    let (base, api_key) = cfg
        .supabase_backend(project)
        .ok_or(ArmFailure::Unavailable)?;
    let url = format!("{}/auth/v1/user", base.trim_end_matches('/'));
    let mut request = http.get(url).bearer_auth(token).timeout(cfg.arm_timeout);
    if let Some(api_key) = api_key {
        request = request.header("apikey", api_key);
    }
    let resp = request.send().await.map_err(|_| ArmFailure::Unavailable)?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED
        || resp.status() == reqwest::StatusCode::FORBIDDEN
    {
        return Err(ArmFailure::Invalid);
    }
    if !resp.status().is_success() {
        return Err(ArmFailure::Unavailable);
    }
    let user: SupabaseUser = resp.json().await.map_err(|_| ArmFailure::Unavailable)?;

    Ok(Identity {
        shared_user_id: format!("{}:{}", project, user.id),
        provider: "supabase".into(),
        provider_tenant: project.to_string(),
        provider_subject: user.id.clone(),
        project: Some(project.to_string()),
        supabase_user_id: Some(user.id),
        session_id: None,
        email: user.email,
        email_verified: user.email_confirmed_at.is_some(),
        roles: vec![],
        amr: vec![],
        acr: None,
        cred: None,
        authority: Authority::Supabase,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
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

    fn cfg() -> AuthorityConfig {
        AuthorityConfig {
            issuer: "https://auth.test".into(),
            audience: "ore".into(),
            ..Default::default()
        }
    }

    fn token(kid: &str, exp_delta: i64) -> String {
        signed_token(kid, exp_delta, serde_json::json!({}))
    }

    fn signed_token(kid: &str, exp_delta: i64, extra: serde_json::Value) -> String {
        let mut h = Header::new(Algorithm::ES256);
        h.kid = Some(kid.into());
        let now = chrono::Utc::now().timestamp();
        let mut claims = serde_json::json!({
            "sub": "shared-1", "project": "fiducia-cloud", "supabase_user_id": "sup-1",
            "provider": "supabase", "provider_tenant": "fiducia-cloud", "provider_subject": "sup-1",
            "roles": ["user"], "sid": "00000000-0000-0000-0000-000000000001",
            "email": "a@b.co", "email_verified": true,
            "iss": "https://auth.test", "aud": "ore",
            "iat": now,
            "nbf": now - 5,
            "exp": now + exp_delta,
        });
        if let (Some(base), Some(overlay)) = (claims.as_object_mut(), extra.as_object()) {
            for (key, value) in overlay {
                base.insert(key.clone(), value.clone());
            }
        }
        jsonwebtoken::encode(
            &h,
            &claims,
            &EncodingKey::from_ec_pem(pem().as_bytes()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn verifies_a_shared_auth_token_offline() {
        let id = verify_shared_auth_token(&token("k1", 3600), &jwks("k1"), &cfg()).unwrap();
        assert_eq!(id.shared_user_id, "shared-1");
        assert_eq!(id.project.as_deref(), Some("fiducia-cloud"));
        assert_eq!(id.provider, "supabase");
        assert_eq!(id.authority, Authority::SharedAuth);
        assert!(id.email_verified);
    }

    #[test]
    fn expired_token_is_definitely_invalid() {
        let err = verify_shared_auth_token(&token("k1", -7200), &jwks("k1"), &cfg()).unwrap_err();
        assert_eq!(err, ArmFailure::Invalid);
    }

    // An unknown kid is NOT proof the token is bad — we just can't decide, so the
    // race must be free to let the other authority answer.
    #[test]
    fn unknown_kid_is_unavailable_not_invalid() {
        let err = verify_shared_auth_token(&token("k1", 3600), &jwks("other"), &cfg()).unwrap_err();
        assert_eq!(err, ArmFailure::Unavailable);
    }

    #[test]
    fn wrong_issuer_is_invalid() {
        let bad = AuthorityConfig {
            issuer: "https://evil".into(),
            ..cfg()
        };
        let err = verify_shared_auth_token(&token("k1", 3600), &jwks("k1"), &bad).unwrap_err();
        assert_eq!(err, ArmFailure::Invalid);
    }

    #[test]
    fn garbage_is_invalid() {
        assert_eq!(
            verify_shared_auth_token("not.a.jwt", &jwks("k1"), &cfg()).unwrap_err(),
            ArmFailure::Invalid
        );
    }

    #[test]
    fn wrong_audience_is_invalid() {
        let bad = AuthorityConfig {
            audience: "other".into(),
            ..cfg()
        };
        let err = verify_shared_auth_token(&token("k1", 3600), &jwks("k1"), &bad).unwrap_err();
        assert_eq!(err, ArmFailure::Invalid);
    }

    #[test]
    fn missing_kid_is_invalid() {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = None;
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": "shared-1",
            "provider": "supabase",
            "provider_tenant": "fiducia-cloud",
            "provider_subject": "sup-1",
            "iss": "https://auth.test",
            "aud": "ore",
            "iat": now,
            "nbf": now - 5,
            "exp": now + 3600,
        });
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(pem().as_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verify_shared_auth_token(&token, &jwks("k1"), &cfg()).unwrap_err(),
            ArmFailure::Invalid
        );
    }

    #[test]
    fn future_nbf_is_invalid() {
        let now = chrono::Utc::now().timestamp();
        let token = signed_token(
            "k1",
            7200,
            serde_json::json!({ "nbf": now + 3600, "iat": now, "exp": now + 7200 }),
        );
        assert_eq!(
            verify_shared_auth_token(&token, &jwks("k1"), &cfg()).unwrap_err(),
            ArmFailure::Invalid
        );
    }

    #[test]
    fn hs256_and_unsigned_alg_none_are_invalid() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let hs = {
            let mut header = Header::new(Algorithm::HS256);
            header.kid = Some("k1".into());
            let now = chrono::Utc::now().timestamp();
            jsonwebtoken::encode(
                &header,
                &serde_json::json!({
                    "sub": "shared-1",
                    "iss": "https://auth.test",
                    "aud": "ore",
                    "iat": now,
                    "nbf": now - 5,
                    "exp": now + 3600,
                }),
                &EncodingKey::from_secret(b"not-an-es256-key-material-at-all"),
            )
            .unwrap()
        };
        assert_eq!(
            verify_shared_auth_token(&hs, &jwks("k1"), &cfg()).unwrap_err(),
            ArmFailure::Invalid
        );

        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","kid":"k1"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            r#"{"sub":"shared-1","iss":"https://auth.test","aud":"ore","iat":1,"nbf":1,"exp":9999999999}"#,
        );
        let none = format!("{header}.{payload}.");
        assert_eq!(
            verify_shared_auth_token(&none, &jwks("k1"), &cfg()).unwrap_err(),
            ArmFailure::Invalid
        );
    }

    #[test]
    fn protected_introspection_body_matches_the_server_envelope() {
        let body = protected_introspection_body("issued-token", "oresoftware");
        assert_eq!(body["contract"], "IntrospectionRequest");
        assert_eq!(body["payload"]["token"], "issued-token");
        assert_eq!(body["payload"]["audience"], "oresoftware");
        assert_eq!(body["payload"]["requiredScopes"], serde_json::json!([]));
        assert!(body.get("token").is_none());
    }

    fn exchange_response() -> ExchangeResponse {
        ExchangeResponse {
            access_token: "new-shared-token".into(),
            shared_user_id: "shared-1".into(),
            provider: "supabase".into(),
            provider_tenant: "project".into(),
            provider_subject: "provider-1".into(),
            roles: vec!["operator".into()],
        }
    }

    fn introspected_identity() -> IntrospectResponse {
        IntrospectResponse {
            active: true,
            sub: "shared-1".into(),
            provider: "supabase".into(),
            provider_tenant: "project".into(),
            provider_subject: "provider-1".into(),
            project: Some("project".into()),
            supabase_user_id: Some("provider-1".into()),
            sid: Some("session-1".into()),
            email: Some("operator@example.com".into()),
            email_verified: true,
            roles: vec!["operator".into()],
            amr: vec!["totp".into()],
            acr: Some("urn:oresoftware:loa:2".into()),
            cred: None,
        }
    }

    #[test]
    fn exchange_introspection_preserves_verified_email_and_session_identity() {
        let identity = identity_from_exchange(exchange_response(), introspected_identity())
            .expect("coherent shared identity");
        assert_eq!(identity.email.as_deref(), Some("operator@example.com"));
        assert!(identity.email_verified);
        assert_eq!(identity.session_id.as_deref(), Some("session-1"));
        assert_eq!(identity.amr, ["totp"]);
        assert_eq!(identity.acr.as_deref(), Some("urn:oresoftware:loa:2"));
        assert_eq!(identity.authority, Authority::SharedAuth);
    }

    #[test]
    fn contradictory_or_inactive_introspection_is_degraded() {
        let mut contradictory = introspected_identity();
        contradictory.provider_subject = "other-provider-user".into();
        assert_eq!(
            identity_from_exchange(exchange_response(), contradictory),
            Err(ArmFailure::Unavailable)
        );

        let mut inactive = introspected_identity();
        inactive.active = false;
        assert_eq!(
            identity_from_exchange(exchange_response(), inactive),
            Err(ArmFailure::Unavailable)
        );
    }

    #[test]
    fn introspection_compares_roles_as_a_set() {
        let mut exchange = exchange_response();
        exchange.roles.push("viewer".into());
        let mut claims = introspected_identity();
        claims.roles = vec!["viewer".into(), "operator".into()];
        assert!(identity_from_exchange(exchange, claims).is_ok());
    }

    #[test]
    fn authority_debug_redacts_credentials() {
        let config = AuthorityConfig {
            supabase_api_key: Some("publishable-key".into()),
            introspect_secret: Some("service-secret".into()),
            ..Default::default()
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("publishable-key"));
        assert!(!rendered.contains("service-secret"));
        assert!(rendered.contains("[redacted]"));
    }

    #[test]
    fn named_supabase_backends_win_over_the_default_url() {
        let config = AuthorityConfig {
            supabase_url: Some("https://auth.oresoftware.dev".into()),
            supabase_api_key: Some("hub-key".into()),
            supabase_backends: vec![
                SupabaseBackend {
                    name: "sonus-auris".into(),
                    url: "https://auth.sonusauris.app".into(),
                    api_key: Some("spoke-key".into()),
                },
                SupabaseBackend {
                    name: "zed-pkg".into(),
                    url: "https://auth.zpkg.net".into(),
                    api_key: None,
                },
            ],
            ..Default::default()
        };
        let (url, key) = config.supabase_backend("sonus-auris").unwrap();
        assert_eq!(url, "https://auth.sonusauris.app");
        assert_eq!(key, Some("spoke-key"));
        let (url, key) = config.supabase_backend("zed-pkg").unwrap();
        assert_eq!(url, "https://auth.zpkg.net");
        assert_eq!(key, None);
        let (url, key) = config.supabase_backend("unknown").unwrap();
        assert_eq!(url, "https://auth.oresoftware.dev");
        assert_eq!(key, Some("hub-key"));
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("spoke-key"));
        assert!(!rendered.contains("hub-key"));
    }

    #[test]
    fn projects_json_maps_custom_auth_hosts_and_conventional_env_names() {
        let raw = r#"[
            {"name":"oresoftware-hub","role":"hub","auth_host":"auth.oresoftware.dev","project_ref":"hubref000000000001"},
            {"name":"sonus-auris","role":"spoke","auth_host":"auth.sonusauris.app","application_key":"sonus-auris"},
            {"name":"zed-pkg","auth_host":"auth.zpkg.net"},
            {"name":"fiducia-cloud","project_ref":"fiduciacloudref0001"}
        ]"#;
        let backends = parse_with_sonus_key(raw);
        assert_eq!(backends.len(), 4);
        assert_eq!(backends[0].url, "https://auth.oresoftware.dev");
        assert_eq!(backends[1].url, "https://auth.sonusauris.app");
        assert_eq!(backends[1].api_key.as_deref(), Some("sonus-key"));
        assert_eq!(backends[2].url, "https://auth.zpkg.net");
        assert_eq!(backends[2].api_key, None);
        assert_eq!(backends[3].url, "https://fiduciacloudref0001.supabase.co");
        let rendered = format!("{:?}", backends[1]);
        assert!(!rendered.contains("sonus-key"));
    }

    #[test]
    fn remaining_product_spokes_use_auth_hosts() {
        let raw = r#"[
            {"name":"athlet-o","auth_host":"auth.athleto.store"},
            {"name":"canonical-plus","auth_host":"auth.canonica.plus"},
            {"name":"benefactor","auth_host":"auth.benefactor.cc"}
        ]"#;
        let backends = SupabaseBackend::from_projects_json(raw, |_| None).unwrap();
        assert_eq!(
            backends
                .iter()
                .map(|backend| backend.url.as_str())
                .collect::<Vec<_>>(),
            [
                "https://auth.athleto.store",
                "https://auth.canonica.plus",
                "https://auth.benefactor.cc"
            ]
        );
    }

    #[test]
    fn projects_json_fails_closed_on_garbage_or_incomplete_entries() {
        assert!(SupabaseBackend::from_projects_json("{not-json", |_| None).is_err());
        assert!(SupabaseBackend::from_projects_json(r#"[{"name":"orphan"}]"#, |_| None).is_err());
    }

    fn parse_with_sonus_key(raw: &str) -> Vec<SupabaseBackend> {
        let mut keys = std::collections::HashMap::from([(
            "AUTH_SUPABASE_SONUS_AURIS_PUBLISHABLE_KEY".to_string(),
            "sonus-key".to_string(),
        )]);
        SupabaseBackend::from_projects_json(raw, |name| keys.remove(name)).unwrap()
    }
}
