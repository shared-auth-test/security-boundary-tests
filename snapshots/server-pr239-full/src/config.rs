//! Environment-driven configuration.
//!
//! Everything sensitive (provider API keys, DB URL, signing key, Management PAT) is
//! injected via the environment — in the cluster from an `ExternalSecret`
//! pointing at the shared `ClusterSecretStore` (`deploy/k8s/externalsecret.yaml`).
//! Nothing here reads from disk except the PEM signing key, which may be given
//! inline or as a path.

use std::net::SocketAddr;

use serde::Deserialize;

use crate::error::ConfigError;
use crate::locks::{FiduciaHttpLease, LockPlan};

/// Hub versus product-spoke placement of a Supabase project.
///
/// Shared Auth Postgres is always the federated directory. A `hub` project is
/// the optional network-wide login provider; every other GitHub org keeps an
/// isolated `spoke` project behind `auth.<product-domain>`.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRole {
    Hub,
    #[default]
    Spoke,
}

/// One Supabase project this server accepts tokens from. Each GitHub org
/// (sonus-auris, zed-pkg, athlet-o, fiducia-cloud, canonical-plus, benefactor, …)
/// maps to one spoke with its own issuer, JWKS, and `auth.*` host. An optional
/// hub project is the network-wide login provider; it is never a second user
/// database.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupabaseProject {
    /// Stable slug used in logs, metrics, and the `supabase_project` mirror
    /// column, e.g. `"fiducia-cloud"`.
    pub name: String,
    /// Supabase project ref, e.g. `abcdefghijklmnopqrst`. Used to derive
    /// `issuer`/`jwks_url` when those are not given explicitly.
    pub project_ref: String,
    /// Hub (network-wide login) or product spoke. Defaults to spoke.
    #[serde(default)]
    pub role: ProviderRole,
    /// Browser Auth host for this project, e.g. `auth.sonusauris.app`. When set
    /// and `issuer` is omitted, tokens are pinned to `https://<host>/auth/v1`.
    #[serde(default)]
    pub auth_host: Option<String>,
    /// Shared Auth application key this spoke enrolls into, e.g. `sonus-auris`.
    #[serde(default)]
    pub application_key: Option<String>,
    /// Non-secret Supabase organization slug. Never a credential.
    #[serde(default)]
    pub org: Option<String>,
    /// Token issuer to pin (`iss`). Defaults to the custom `auth_host` issuer
    /// when that host is set, otherwise `https://<project_ref>.supabase.co/auth/v1`.
    #[serde(default)]
    pub issuer: Option<String>,
    /// JWKS endpoint. Defaults to `<issuer>/.well-known/jwks.json`.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Expected audience. Supabase stamps `authenticated` on end-user tokens.
    #[serde(default = "default_audience")]
    pub audience: String,
    /// Name of the environment variable holding the publishable/legacy anon key.
    /// The key itself must never appear in `AUTH_SUPABASE_PROJECTS`. When omitted,
    /// `AUTH_SUPABASE_<SLUG>_PUBLISHABLE_KEY` is read if present.
    #[serde(default)]
    pub publishable_key_env: Option<String>,
    /// Name of the environment variable holding a modern server-side secret key.
    #[serde(default)]
    pub secret_key_env: Option<String>,
    /// Name of the environment variable holding a legacy service-role key.
    #[serde(default)]
    pub service_role_key_env: Option<String>,
    /// Legacy HS256 only: name of the environment variable holding the JWT secret.
    /// Prefer asymmetric JWKS verification and omit this for modern projects.
    /// When omitted, `AUTH_SUPABASE_<SLUG>_JWT_SECRET` is read if present.
    #[serde(default)]
    pub jwt_secret_env: Option<String>,
    /// Resolved runtime credentials. Serde always skips these fields so secret
    /// values cannot be embedded in the provider metadata JSON by mistake.
    #[serde(skip)]
    pub api_keys: SupabaseApiKeys,
    #[serde(skip)]
    pub hs256_secret: Option<String>,
}

/// Runtime-only Supabase credentials resolved from environment-variable names in
/// `SupabaseProject`. This type deliberately does not implement `Debug` or
/// `Serialize`, which keeps accidental config logging from exposing key values.
#[derive(Clone, Default)]
pub struct SupabaseApiKeys {
    pub publishable_key: Option<String>,
    pub secret_key: Option<String>,
    pub service_role_key: Option<String>,
}

fn default_audience() -> String {
    "authenticated".to_string()
}

impl SupabaseProject {
    /// Conventional Fiducia/flags-2-env name for a per-org credential.
    /// `fiducia-cloud` + `PUBLISHABLE_KEY` → `AUTH_SUPABASE_FIDUCIA_CLOUD_PUBLISHABLE_KEY`.
    pub fn conventional_credential_env(name: &str, kind: &str) -> String {
        let slug = name.to_ascii_uppercase().replace('-', "_");
        format!("AUTH_SUPABASE_{slug}_{kind}")
    }

    /// The issuer to pin. Custom `auth.*` hosts win over the default
    /// `*.supabase.co` issuer so product custom domains verify correctly.
    pub fn issuer(&self) -> String {
        if let Some(issuer) = &self.issuer {
            return issuer.clone();
        }
        if let Some(host) = &self.auth_host {
            return format!("https://{host}/auth/v1");
        }
        format!("https://{}.supabase.co/auth/v1", self.project_ref)
    }

    /// The JWKS URL, derived from the issuer when not set explicitly.
    pub fn jwks_url(&self) -> String {
        self.jwks_url
            .clone()
            .unwrap_or_else(|| format!("{}/.well-known/jwks.json", self.issuer()))
    }
}

/// How this server signs the unified OreSoftware JWTs it mints.
#[derive(Clone)]
pub struct SigningConfig {
    /// PKCS#8 PEM of an EC P-256 private key (ES256). Held in memory only.
    pub ec_private_pem: String,
    /// `kid` advertised in our JWKS and stamped on tokens. Downstream services
    /// select the verification key by this id, so keep it stable across rotation
    /// windows (publish old+new together while rotating).
    pub key_id: String,
    /// `iss` on the tokens we mint.
    pub issuer: String,
    /// `aud` on the tokens we mint — the set of OreSoftware services meant to
    /// accept them.
    pub audience: String,
    /// Lifetime of a minted token, in seconds.
    pub ttl_secs: u64,
}

/// AWS RDS identity-mirror connection.
#[derive(Clone)]
pub struct DbConfig {
    /// `postgres://…` DSN. `search_path` should include `shared_auth`.
    pub url: String,
    pub max_connections: u32,
    /// Unpadded base64url encoding of the 256-bit HMAC key shared only with
    /// the trusted admin web edge. It is never accepted as a command-line flag.
    pub admin_email_search_hmac_key: Option<String>,
}

/// Optional Redis/Valkey cache in the private network. It is never the source
/// of truth; losing it only removes acceleration and distributed rate limits.
#[derive(Clone)]
pub struct RedisConfig {
    pub url: String,
    pub key_prefix: String,
}

/// How strictly a Supabase JWT must be paired with a shared-auth proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DualProofMode {
    Off,
    #[default]
    Warn,
    Strict,
}

impl DualProofMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" | "0" | "false" | "no" => Some(Self::Off),
            "warn" | "warning" => Some(Self::Warn),
            "strict" | "required" | "on" | "true" | "yes" => Some(Self::Strict),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct SessionConfig {
    pub refresh_ttl_secs: u64,
    pub allow_registration: bool,
    /// Pair a Supabase JWT with `X-Shared-Auth-Access` on `/auth/exchange`.
    pub dual_proof: DualProofMode,
    /// How a rate-limit check behaves when Redis is configured but a call errors
    /// mid-request. Default `true` preserves the historical behavior of the
    /// supplemental edge buckets. Login, TOTP verification, and OTP delivery
    /// retain their authoritative PostgreSQL budgets regardless. Set
    /// `AUTH_RATE_LIMIT_FAIL_OPEN=false` when every Redis-backed bucket must also
    /// fail closed during a cache outage. When Redis is not configured at all,
    /// only the durable database budgets remain active.
    pub rate_limit_fail_open: bool,
}

/// Privileged global-session revocation control plane.
///
/// This surface is intentionally absent unless an admin-realm operator opts in.
/// It never accepts a service secret in lieu of a user-bound, revocation-aware
/// AAL2 passkey session.
#[derive(Clone)]
pub struct GlobalRevocationConfig {
    pub enabled: bool,
    pub admin_realm: bool,
    pub max_auth_age_secs: u64,
    pub preview_ttl_secs: u64,
    pub require_dual_control: bool,
}

/// Nested Fiducia + Postgres advisory lock plan for exclusive mutations.
#[derive(Clone)]
pub struct NestedLockConfig {
    pub plan: LockPlan,
    pub fiducia_base_url: Option<String>,
    pub fiducia_bearer: Option<String>,
    pub fiducia_internal_auth: Option<String>,
}

impl std::fmt::Debug for NestedLockConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NestedLockConfig")
            .field("plan", &self.plan)
            .field("fiducia_base_url", &self.fiducia_base_url)
            .field("fiducia_bearer", &self.fiducia_bearer.as_ref().map(|_| "<redacted>"))
            .field(
                "fiducia_internal_auth",
                &self.fiducia_internal_auth.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Default for NestedLockConfig {
    fn default() -> Self {
        Self {
            plan: LockPlan::PG_ONLY,
            fiducia_base_url: None,
            fiducia_bearer: None,
            fiducia_internal_auth: None,
        }
    }
}

/// Optional RDS-backed passwordless email OTP delivered through SendGrid.
///
/// Empty values keep the server deployable and leave only the passwordless
/// email request endpoint unavailable. `link_base_url` is retained solely for
/// compatibility with already-issued legacy magic links.
#[derive(Clone)]
pub struct MagicLinkConfig {
    pub sendgrid_api_key: Option<String>,
    pub otp_pepper: Option<String>,
    pub from_email: Option<String>,
    pub from_name: String,
    pub link_base_url: Option<String>,
    pub ttl_secs: u64,
    pub allow_signup: bool,
}

impl MagicLinkConfig {
    pub fn is_enabled(&self) -> bool {
        self.sendgrid_api_key.is_some() && self.otp_pepper.is_some() && self.from_email.is_some()
    }
}

#[derive(Clone)]
pub struct TwilioVerifyConfig {
    pub account_sid: Option<String>,
    pub auth_token: Option<String>,
    pub service_sid: Option<String>,
}

impl TwilioVerifyConfig {
    pub fn is_enabled(&self) -> bool {
        self.account_sid.is_some() && self.auth_token.is_some() && self.service_sid.is_some()
    }
}

/// Fully-resolved configuration.
#[derive(Clone)]
pub struct AppConfig {
    pub bind_addr: SocketAddr,
    pub projects: Vec<SupabaseProject>,
    pub signing: SigningConfig,
    /// Optional: without a DB the server still verifies + mints, it just skips
    /// mirroring identities.
    pub db: Option<DbConfig>,
    pub redis: Option<RedisConfig>,
    pub sessions: SessionConfig,
    pub global_revocation: GlobalRevocationConfig,
    pub magic_links: MagicLinkConfig,
    pub twilio_verify: TwilioVerifyConfig,
    /// HMAC secret for `/internal/webhook/sync`. When absent the endpoint is
    /// disabled (404), rather than exposed without authentication.
    pub webhook_secret: Option<String>,
    /// Shared service credential required to call `/auth/introspect`. When set,
    /// callers must present `Authorization: Bearer <secret>` and unauthenticated
    /// callers are rejected. When absent, introspection is disabled. The
    /// dashboard audience additionally requires current Postgres-backed,
    /// tenant-scoped directory grants and emits a redacted strict profile.
    pub introspect_secret: Option<String>,
    /// Independent service credential for the trusted web server to exchange
    /// an active dashboard actor token for the one exact global-revocation
    /// scope. It is required whenever the control plane is enabled.
    pub admin_token_exchange_secret: Option<String>,
    /// Optional CORS allow-list for browser callers.
    pub cors_allow_origins: Vec<String>,
    /// Fiducia + Postgres nested lock plan. Global revocation refuses [`LockPlan::NEITHER`].
    pub nested_locks: NestedLockConfig,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_env_map(&crate::env_map::current_env_map())
    }

    pub fn from_env_map(env: &crate::env_map::EnvMap) -> Result<Self, ConfigError> {
        let bind_addr = env_or(env, "AUTH_BIND_ADDR", "0.0.0.0:8120")
            .parse()
            .map_err(|_| ConfigError::Invalid("AUTH_BIND_ADDR"))?;

        // Supabase is a secondary authority. An empty registry is valid for a
        // local-only deployment and lets future provider adapters be introduced
        // without making Supabase a hard startup dependency.
        let projects_json = env_or(env, "AUTH_SUPABASE_PROJECTS", "[]");
        let mut projects: Vec<SupabaseProject> = serde_json::from_str(&projects_json)
            .map_err(|_| ConfigError::Invalid("AUTH_SUPABASE_PROJECTS (expected JSON array)"))?;
        resolve_provider_secrets(env, &mut projects)?;
        validate_projects(&projects)?;

        let ec_private_pem = load_signing_pem(env)?;
        let signing = SigningConfig {
            ec_private_pem,
            key_id: env_or(env, "AUTH_SIGNING_KID", "shared-auth-v1"),
            issuer: env_or(env, "AUTH_ISSUER", "https://auth.oresoftware.dev"),
            audience: env_or(env, "AUTH_AUDIENCE", "oresoftware"),
            ttl_secs: env_or(env, "AUTH_ACCESS_TOKEN_TTL_SECS", "900")
                .parse()
                .map_err(|_| ConfigError::Invalid("AUTH_ACCESS_TOKEN_TTL_SECS"))?,
        };
        if !(60..=86_400).contains(&signing.ttl_secs) {
            return Err(ConfigError::Invalid(
                "AUTH_ACCESS_TOKEN_TTL_SECS must be between 60 and 86400",
            ));
        }

        let admin_email_search_hmac_key = optional_env(env, "AUTH_ADMIN_EMAIL_SEARCH_HMAC_KEY");
        if admin_email_search_hmac_key
            .as_deref()
            .is_some_and(|value| crate::revocation::decode_email_search_hmac_key(value).is_none())
        {
            return Err(ConfigError::Invalid(
                "AUTH_ADMIN_EMAIL_SEARCH_HMAC_KEY must be unpadded base64url for exactly 32 bytes",
            ));
        }
        let db = match lookup_env(env, "AUTH_DATABASE_URL")
            .ok()
            .filter(|s| !s.is_empty())
        {
            Some(url) => Some(DbConfig {
                url,
                max_connections: env_or(env, "AUTH_DB_MAX_CONNECTIONS", "5")
                    .parse()
                    .map_err(|_| ConfigError::Invalid("AUTH_DB_MAX_CONNECTIONS"))?,
                admin_email_search_hmac_key,
            }),
            None if parse_bool(env, "AUTH_ALLOW_DBLESS", false)? => None,
            None => return Err(ConfigError::Missing("AUTH_DATABASE_URL")),
        };

        let redis = lookup_env(env, "AUTH_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|url| RedisConfig {
                url,
                key_prefix: env_or(env, "AUTH_REDIS_KEY_PREFIX", "shared-auth:v1"),
            });

        let refresh_ttl_secs = env_or(env, "AUTH_REFRESH_TOKEN_TTL_SECS", "2592000")
            .parse()
            .map_err(|_| ConfigError::Invalid("AUTH_REFRESH_TOKEN_TTL_SECS"))?;
        if !(300..=31_536_000).contains(&refresh_ttl_secs) {
            return Err(ConfigError::Invalid(
                "AUTH_REFRESH_TOKEN_TTL_SECS must be between 300 and 31536000",
            ));
        }
        let dual_proof = DualProofMode::parse(&env_or(env, "AUTH_DUAL_PROOF", "warn"))
            .ok_or(ConfigError::Invalid("AUTH_DUAL_PROOF"))?;
        let sessions = SessionConfig {
            refresh_ttl_secs,
            allow_registration: parse_bool(env, "AUTH_ALLOW_REGISTRATION", false)?,
            rate_limit_fail_open: parse_bool(env, "AUTH_RATE_LIMIT_FAIL_OPEN", true)?,
            dual_proof,
        };

        let global_revocation_enabled = parse_bool(env, "AUTH_GLOBAL_REVOCATION_ENABLED", false)?;
        let admin_realm = optional_env(env, "AUTH_REALM").as_deref() == Some("admin");
        if global_revocation_enabled && !admin_realm {
            return Err(ConfigError::Invalid(
                "AUTH_GLOBAL_REVOCATION_ENABLED requires AUTH_REALM=admin",
            ));
        }
        if global_revocation_enabled && db.is_none() {
            return Err(ConfigError::Invalid(
                "AUTH_GLOBAL_REVOCATION_ENABLED requires AUTH_DATABASE_URL",
            ));
        }
        if global_revocation_enabled
            && db
                .as_ref()
                .and_then(|config| config.admin_email_search_hmac_key.as_ref())
                .is_none()
        {
            return Err(ConfigError::Invalid(
                "AUTH_GLOBAL_REVOCATION_ENABLED requires AUTH_ADMIN_EMAIL_SEARCH_HMAC_KEY",
            ));
        }
        let max_auth_age_secs = env_or(env, "AUTH_GLOBAL_REVOCATION_MAX_AUTH_AGE_SECS", "300")
            .parse()
            .map_err(|_| ConfigError::Invalid("AUTH_GLOBAL_REVOCATION_MAX_AUTH_AGE_SECS"))?;
        if !(60..=900).contains(&max_auth_age_secs) {
            return Err(ConfigError::Invalid(
                "AUTH_GLOBAL_REVOCATION_MAX_AUTH_AGE_SECS must be between 60 and 900",
            ));
        }
        let preview_ttl_secs = env_or(env, "AUTH_GLOBAL_REVOCATION_PREVIEW_TTL_SECS", "600")
            .parse()
            .map_err(|_| ConfigError::Invalid("AUTH_GLOBAL_REVOCATION_PREVIEW_TTL_SECS"))?;
        if !(60..=1_800).contains(&preview_ttl_secs) {
            return Err(ConfigError::Invalid(
                "AUTH_GLOBAL_REVOCATION_PREVIEW_TTL_SECS must be between 60 and 1800",
            ));
        }
        let require_dual_control = parse_bool(env, "AUTH_GLOBAL_REVOCATION_REQUIRE_DUAL_CONTROL", true)?;
        if global_revocation_enabled && !require_dual_control {
            return Err(ConfigError::Invalid(
                "global revocation requires distinct-operator dual control",
            ));
        }
        let global_revocation = GlobalRevocationConfig {
            enabled: global_revocation_enabled,
            admin_realm,
            max_auth_age_secs,
            preview_ttl_secs,
            require_dual_control,
        };

        let magic_link_ttl_secs = env_or(env, "AUTH_MAGIC_LINK_TTL_SECS", "900")
            .parse()
            .map_err(|_| ConfigError::Invalid("AUTH_MAGIC_LINK_TTL_SECS"))?;
        if !(300..=3_600).contains(&magic_link_ttl_secs) {
            return Err(ConfigError::Invalid(
                "AUTH_MAGIC_LINK_TTL_SECS must be between 300 and 3600",
            ));
        }
        let magic_link_base_url = optional_env(env, "AUTH_MAGIC_LINK_BASE_URL");
        if let Some(value) = magic_link_base_url.as_deref() {
            validate_magic_link_base_url(value)?;
        }
        let from_email = optional_env(env, "AUTH_EMAIL_FROM");
        if from_email
            .as_deref()
            .is_some_and(|value| !looks_like_email(value))
        {
            return Err(ConfigError::Invalid("AUTH_EMAIL_FROM"));
        }
        let otp_pepper = optional_env(env, "AUTH_OTP_PEPPER");
        if otp_pepper.as_ref().is_some_and(|value| value.len() < 32) {
            return Err(ConfigError::Invalid(
                "AUTH_OTP_PEPPER must contain at least 32 bytes",
            ));
        }
        let magic_links = MagicLinkConfig {
            sendgrid_api_key: optional_env(env, "AUTH_SENDGRID_API_KEY"),
            otp_pepper,
            from_email,
            from_name: env_or(env, "AUTH_EMAIL_FROM_NAME", "OreSoftware"),
            link_base_url: magic_link_base_url,
            ttl_secs: magic_link_ttl_secs,
            allow_signup: parse_bool(env, "AUTH_MAGIC_LINK_ALLOW_SIGNUP", false)?,
        };
        let twilio_verify = TwilioVerifyConfig {
            account_sid: optional_env(env, "AUTH_TWILIO_ACCOUNT_SID"),
            auth_token: optional_env(env, "AUTH_TWILIO_AUTH_TOKEN"),
            service_sid: optional_env(env, "AUTH_TWILIO_VERIFY_SERVICE_SID"),
        };
        validate_twilio_identifier(
            twilio_verify.account_sid.as_deref(),
            "AUTH_TWILIO_ACCOUNT_SID",
            "AC",
        )?;
        validate_twilio_identifier(
            twilio_verify.service_sid.as_deref(),
            "AUTH_TWILIO_VERIFY_SERVICE_SID",
            "VA",
        )?;

        let webhook_secret = lookup_env(env, "AUTH_WEBHOOK_SECRET")
            .ok()
            .filter(|value| !value.is_empty());
        if webhook_secret
            .as_ref()
            .is_some_and(|secret| secret.len() < 32)
        {
            return Err(ConfigError::Invalid(
                "AUTH_WEBHOOK_SECRET must contain at least 32 bytes",
            ));
        }

        let introspect_secret = lookup_env(env, "AUTH_INTROSPECT_SECRET")
            .ok()
            .filter(|value| !value.is_empty());
        if introspect_secret
            .as_ref()
            .is_some_and(|secret| secret.len() < 32)
        {
            return Err(ConfigError::Invalid(
                "AUTH_INTROSPECT_SECRET must contain at least 32 bytes",
            ));
        }
        let admin_token_exchange_secret = lookup_env(env, "AUTH_ADMIN_TOKEN_EXCHANGE_SECRET")
            .ok()
            .filter(|value| !value.is_empty());
        if admin_token_exchange_secret
            .as_ref()
            .is_some_and(|secret| crate::revocation::decode_email_search_hmac_key(secret).is_none())
        {
            return Err(ConfigError::Invalid(
                "AUTH_ADMIN_TOKEN_EXCHANGE_SECRET must be unpadded base64url for exactly 32 random bytes",
            ));
        }
        if global_revocation_enabled && admin_token_exchange_secret.is_none() {
            return Err(ConfigError::Invalid(
                "AUTH_GLOBAL_REVOCATION_ENABLED requires AUTH_ADMIN_TOKEN_EXCHANGE_SECRET",
            ));
        }
        validate_independent_admin_secrets([
            ("AUTH_INTROSPECT_SECRET", introspect_secret.as_deref()),
            (
                "AUTH_ADMIN_TOKEN_EXCHANGE_SECRET",
                admin_token_exchange_secret.as_deref(),
            ),
            (
                "AUTH_ADMIN_EMAIL_SEARCH_HMAC_KEY",
                db.as_ref()
                    .and_then(|config| config.admin_email_search_hmac_key.as_deref()),
            ),
        ])?;

        let cors_allow_origins = env_or(env, "AUTH_CORS_ALLOW_ORIGINS", "")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        let fiducia_base_url = optional_env(env, "AUTH_FIDUCIA_LOCK_BASE_URL");
        let fiducia_bearer = optional_env(env, "AUTH_FIDUCIA_LOCK_BEARER");
        let fiducia_internal_auth = optional_env(env, "AUTH_FIDUCIA_INTERNAL_AUTH");
        if fiducia_base_url.is_none()
            && (fiducia_bearer.is_some() || fiducia_internal_auth.is_some())
        {
            return Err(ConfigError::Invalid(
                "AUTH_FIDUCIA_LOCK_BEARER and AUTH_FIDUCIA_INTERNAL_AUTH require AUTH_FIDUCIA_LOCK_BASE_URL",
            ));
        }
        if let Some(base) = fiducia_base_url.as_deref() {
            FiduciaHttpLease::new(base, None).map_err(|_| {
                ConfigError::Invalid("AUTH_FIDUCIA_LOCK_BASE_URL is not a usable Fiducia origin")
            })?;
        }
        let nested_locks = NestedLockConfig {
            plan: LockPlan::for_production(fiducia_base_url.is_some()),
            fiducia_base_url,
            fiducia_bearer,
            fiducia_internal_auth,
        };
        if nested_locks.plan.is_neither() {
            return Err(ConfigError::Invalid(
                "nested lock plan must not be LockPlan::NEITHER",
            ));
        }

        Ok(Self {
            bind_addr,
            projects,
            signing,
            db,
            redis,
            sessions,
            global_revocation,
            magic_links,
            twilio_verify,
            webhook_secret,
            introspect_secret,
            admin_token_exchange_secret,
            cors_allow_origins,
            nested_locks,
        })
    }
}

fn lookup_env(env: &crate::env_map::EnvMap, key: &str) -> Result<String, std::env::VarError> {
    env.get(key).cloned().ok_or(std::env::VarError::NotPresent)
}

fn optional_env(env: &crate::env_map::EnvMap, key: &str) -> Option<String> {
    crate::env_map::env_value(env, key).map(str::to_owned)
}

fn validate_independent_admin_secrets<const N: usize>(
    secrets: [(&'static str, Option<&str>); N],
) -> Result<(), ConfigError> {
    for (index, (left_name, left)) in secrets.iter().enumerate() {
        let Some(left) = left else { continue };
        for (right_name, right) in &secrets[index + 1..] {
            if right.is_some_and(|right| right == *left) {
                tracing::error!(
                    left_secret = *left_name,
                    right_secret = *right_name,
                    "independent admin trust functions reuse one secret"
                );
                return Err(ConfigError::Invalid(
                    "introspection, admin token exchange, and email search secrets must be pairwise distinct",
                ));
            }
        }
    }
    Ok(())
}

fn validate_magic_link_base_url(value: &str) -> Result<(), ConfigError> {
    let parsed =
        reqwest::Url::parse(value).map_err(|_| ConfigError::Invalid("AUTH_MAGIC_LINK_BASE_URL"))?;
    let loopback_http = parsed.scheme() == "http"
        && parsed
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    if parsed.scheme() != "https" && parsed.scheme() != "sonusauris" && !loopback_http {
        return Err(ConfigError::Invalid(
            "AUTH_MAGIC_LINK_BASE_URL must use HTTPS, sonusauris, or loopback HTTP",
        ));
    }
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigError::Invalid(
            "AUTH_MAGIC_LINK_BASE_URL must not contain credentials, query, or fragment",
        ));
    }
    Ok(())
}

fn looks_like_email(value: &str) -> bool {
    let mut parts = value.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    !local.is_empty()
        && domain.contains('.')
        && parts.next().is_none()
        && value.len() <= 320
        && !value.chars().any(char::is_whitespace)
}

fn validate_twilio_identifier(
    value: Option<&str>,
    key: &'static str,
    prefix: &str,
) -> Result<(), ConfigError> {
    if value.is_some_and(|value| {
        value.len() != 34
            || !value.starts_with(prefix)
            || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }) {
        return Err(ConfigError::Invalid(key));
    }
    Ok(())
}

fn validate_projects(projects: &[SupabaseProject]) -> Result<(), ConfigError> {
    let mut names = std::collections::HashSet::new();
    let mut issuers = std::collections::HashSet::new();
    let mut refs = std::collections::HashSet::new();
    let mut hosts = std::collections::HashSet::new();
    let mut env_names = std::collections::HashSet::new();
    let mut secret_values = std::collections::HashSet::new();
    let mut hubs = 0usize;
    for project in projects {
        if project.name.is_empty()
            || project.name.len() > 64
            || !project
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(ConfigError::Invalid("invalid Supabase project name"));
        }
        if project.role == ProviderRole::Hub {
            hubs += 1;
        }
        if hubs > 1 {
            return Err(ConfigError::Invalid(
                "AUTH_SUPABASE_PROJECTS may declare at most one hub provider",
            ));
        }
        if !refs.insert(project.project_ref.clone()) {
            return Err(ConfigError::Invalid("duplicate Supabase project_ref"));
        }
        if !names.insert(project.name.clone()) || !issuers.insert(project.issuer()) {
            return Err(ConfigError::Invalid("duplicate Supabase project or issuer"));
        }
        if let Some(host) = project.auth_host.as_deref() {
            validate_auth_host(host)?;
            if !hosts.insert(host.to_ascii_lowercase()) {
                return Err(ConfigError::Invalid("duplicate Supabase auth_host"));
            }
        }
        if let Some(application_key) = project.application_key.as_deref() {
            validate_application_key(application_key)?;
        }
        if let Some(org) = project.org.as_deref() {
            validate_org_slug(org)?;
        }
        if project
            .hs256_secret
            .as_ref()
            .is_some_and(|secret| secret.len() < 32)
        {
            return Err(ConfigError::Invalid(
                "Supabase HS256 secrets must contain at least 32 bytes",
            ));
        }
        for env_name in [
            project.publishable_key_env.as_deref(),
            project.secret_key_env.as_deref(),
            project.service_role_key_env.as_deref(),
            project.jwt_secret_env.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !env_names.insert(env_name.to_owned()) {
                return Err(ConfigError::Invalid(
                    "Supabase credential env names must be unique per project",
                ));
            }
        }
        for secret in [
            project.api_keys.publishable_key.as_deref(),
            project.api_keys.secret_key.as_deref(),
            project.api_keys.service_role_key.as_deref(),
            project.hs256_secret.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !secret_values.insert(secret.to_owned()) {
                return Err(ConfigError::Invalid(
                    "Supabase credential values must not be reused across projects",
                ));
            }
        }
    }
    Ok(())
}

fn validate_auth_host(host: &str) -> Result<(), ConfigError> {
    let host = host.trim();
    if host.len() < 8
        || host.len() > 253
        || !host.starts_with("auth.")
        || host.contains('/')
        || host.contains(':')
        || host.contains('@')
        || host.contains(char::is_whitespace)
        || !host.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-')
        })
    {
        return Err(ConfigError::Invalid(
            "auth_host must be a lowercase auth.<product-domain> hostname",
        ));
    }
    Ok(())
}

fn validate_application_key(value: &str) -> Result<(), ConfigError> {
    let bytes = value.as_bytes();
    if bytes.len() < 2
        || bytes.len() > 64
        || !bytes[0].is_ascii_lowercase()
        || !bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(ConfigError::Invalid("invalid Supabase application_key"));
    }
    Ok(())
}

fn validate_org_slug(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ConfigError::Invalid("invalid Supabase org slug"));
    }
    Ok(())
}

fn resolve_provider_secrets(
    env: &crate::env_map::EnvMap,
    projects: &mut [SupabaseProject],
) -> Result<(), ConfigError> {
    for project in projects {
        project.api_keys = SupabaseApiKeys {
            publishable_key: read_project_secret(
                env,
                &project.publishable_key_env,
                &project.name,
                "PUBLISHABLE_KEY",
            )?,
            secret_key: read_project_secret(env, &project.secret_key_env, &project.name, "SECRET_KEY")?,
            service_role_key: read_project_secret(
                env,
                &project.service_role_key_env,
                &project.name,
                "SERVICE_ROLE_KEY",
            )?,
        };
        project.hs256_secret = read_project_secret(env, &project.jwt_secret_env, &project.name, "JWT_SECRET")?;
    }
    Ok(())
}

fn read_project_secret(
    env: &crate::env_map::EnvMap,
    explicit: &Option<String>,
    project_name: &str,
    kind: &str,
) -> Result<Option<String>, ConfigError> {
    if explicit.is_some() {
        return read_referenced_secret(env, explicit, true);
    }
    let conventional = SupabaseProject::conventional_credential_env(project_name, kind);
    read_referenced_secret(env, &Some(conventional), false)
}

fn read_referenced_secret(
    env: &crate::env_map::EnvMap,
    env_name: &Option<String>,
    required: bool,
) -> Result<Option<String>, ConfigError> {
    let Some(env_name) = env_name.as_deref() else {
        return Ok(None);
    };
    if env_name.is_empty()
        || env_name.len() > 128
        || !env_name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_uppercase() || byte == b'_' || (index > 0 && byte.is_ascii_digit())
        })
    {
        return Err(ConfigError::Invalid(
            "Supabase credential env names must use uppercase A-Z, digits, and underscores",
        ));
    }
    match crate::env_map::env_value(env, env_name).map(str::to_owned) {
        Some(value) => Ok(Some(value)),
        None if required => Err(ConfigError::Invalid(
            "referenced Supabase credential env var is missing or empty",
        )),
        None => Ok(None),
    }
}

fn parse_bool(
    env: &crate::env_map::EnvMap,
    key: &'static str,
    default: bool,
) -> Result<bool, ConfigError> {
    match optional_env(env, key).as_deref() {
        None => Ok(default),
        Some("1" | "true" | "TRUE" | "yes" | "YES") => Ok(true),
        Some("0" | "false" | "FALSE" | "no" | "NO") => Ok(false),
        Some(_) => Err(ConfigError::Invalid(key)),
    }
}

/// Load the EC signing PEM from `AUTH_SIGNING_KEY_PEM` (inline) or
/// `AUTH_SIGNING_KEY_FILE` (path).
fn load_signing_pem(env: &crate::env_map::EnvMap) -> Result<String, ConfigError> {
    if let Some(inline) = optional_env(env, "AUTH_SIGNING_KEY_PEM") {
        return Ok(inline);
    }
    if let Some(path) = optional_env(env, "AUTH_SIGNING_KEY_FILE") {
        return std::fs::read_to_string(&path)
            .map_err(|_| ConfigError::Invalid("AUTH_SIGNING_KEY_FILE unreadable"));
    }
    Err(ConfigError::Missing(
        "AUTH_SIGNING_KEY_PEM or AUTH_SIGNING_KEY_FILE",
    ))
}

fn env_or(env: &crate::env_map::EnvMap, key: &str, default: &str) -> String {
    optional_env(env, key).unwrap_or_else(|| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_and_jwks_derive_from_project_ref() {
        let p = SupabaseProject {
            name: "fiducia-cloud".into(),
            project_ref: "abcref".into(),
            role: ProviderRole::Spoke,
            auth_host: None,
            application_key: None,
            org: None,
            issuer: None,
            jwks_url: None,
            audience: "authenticated".into(),
            publishable_key_env: None,
            secret_key_env: None,
            service_role_key_env: None,
            jwt_secret_env: None,
            api_keys: SupabaseApiKeys::default(),
            hs256_secret: None,
        };
        assert_eq!(p.issuer(), "https://abcref.supabase.co/auth/v1");
        assert_eq!(
            p.jwks_url(),
            "https://abcref.supabase.co/auth/v1/.well-known/jwks.json"
        );
    }

    #[test]
    fn explicit_issuer_and_jwks_override_derivation() {
        let p = SupabaseProject {
            name: "x".into(),
            project_ref: "r".into(),
            role: ProviderRole::Spoke,
            auth_host: None,
            application_key: None,
            org: None,
            issuer: Some("https://custom.example/iss".into()),
            jwks_url: Some("https://custom.example/keys".into()),
            audience: "authenticated".into(),
            publishable_key_env: None,
            secret_key_env: None,
            service_role_key_env: None,
            jwt_secret_env: None,
            api_keys: SupabaseApiKeys::default(),
            hs256_secret: None,
        };
        assert_eq!(p.issuer(), "https://custom.example/iss");
        assert_eq!(p.jwks_url(), "https://custom.example/keys");
    }

    #[test]
    fn projects_json_parses_with_defaults() {
        let v: Vec<SupabaseProject> = serde_json::from_str(
            r#"[{"name":"3fa-app","project_ref":"ref1"},
                {"name":"sonus-auris","project_ref":"ref2","audience":"custom",
                 "publishable_key_env":"AUTH_SUPABASE_SONUS_PUBLISHABLE_KEY",
                 "jwt_secret_env":"AUTH_SUPABASE_SONUS_JWT_SECRET"}]"#,
        )
        .unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].audience, "authenticated"); // default
        assert!(v[0].hs256_secret.is_none());
        assert_eq!(v[1].audience, "custom");
        assert_eq!(
            v[1].publishable_key_env.as_deref(),
            Some("AUTH_SUPABASE_SONUS_PUBLISHABLE_KEY")
        );
        assert_eq!(
            v[1].jwt_secret_env.as_deref(),
            Some("AUTH_SUPABASE_SONUS_JWT_SECRET")
        );
        assert!(v[1].hs256_secret.is_none());
        assert_eq!(v[0].role, ProviderRole::Spoke);
        assert_eq!(v[1].role, ProviderRole::Spoke);
    }

    #[test]
    fn auth_host_becomes_the_custom_domain_issuer() {
        let p = SupabaseProject {
            name: "sonus-auris".into(),
            project_ref: "sonusref".into(),
            role: ProviderRole::Spoke,
            auth_host: Some("auth.sonusauris.app".into()),
            application_key: Some("sonus-auris".into()),
            org: Some("sonus-auris".into()),
            issuer: None,
            jwks_url: None,
            audience: "authenticated".into(),
            publishable_key_env: None,
            secret_key_env: None,
            service_role_key_env: None,
            jwt_secret_env: None,
            api_keys: SupabaseApiKeys::default(),
            hs256_secret: None,
        };
        assert_eq!(p.issuer(), "https://auth.sonusauris.app/auth/v1");
        assert_eq!(
            p.jwks_url(),
            "https://auth.sonusauris.app/auth/v1/.well-known/jwks.json"
        );
    }

    #[test]
    fn conventional_credential_env_is_slug_and_kind() {
        assert_eq!(
            SupabaseProject::conventional_credential_env("fiducia-cloud", "PUBLISHABLE_KEY"),
            "AUTH_SUPABASE_FIDUCIA_CLOUD_PUBLISHABLE_KEY"
        );
        assert_eq!(
            SupabaseProject::conventional_credential_env("zed-pkg", "SECRET_KEY"),
            "AUTH_SUPABASE_ZED_PKG_SECRET_KEY"
        );
    }

    #[test]
    fn hub_and_spoke_registry_parses() {
        let v: Vec<SupabaseProject> = serde_json::from_str(
            r#"[{"name":"oresoftware-hub","project_ref":"hubref01","role":"hub",
                 "auth_host":"auth.oresoftware.dev"},
                {"name":"sonus-auris","project_ref":"sonusref1","role":"spoke",
                 "auth_host":"auth.sonusauris.app","application_key":"sonus-auris"}]"#,
        )
        .unwrap();
        assert_eq!(v[0].role, ProviderRole::Hub);
        assert_eq!(v[1].auth_host.as_deref(), Some("auth.sonusauris.app"));
        validate_projects(&v).unwrap();
    }

    #[test]
    fn two_hubs_are_rejected() {
        let v: Vec<SupabaseProject> = serde_json::from_str(
            r#"[{"name":"hub-a","project_ref":"hubrefaa","role":"hub"},
                {"name":"hub-b","project_ref":"hubrefbb","role":"hub"}]"#,
        )
        .unwrap();
        assert!(validate_projects(&v).is_err());
    }

    #[test]
    fn inline_provider_secrets_are_rejected() {
        let result = serde_json::from_str::<SupabaseProject>(
            r#"{"name":"x","project_ref":"ref","hs256_secret":"must-not-be-inline"}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn admin_trust_function_secrets_must_be_pairwise_distinct() {
        let introspection = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let exchange = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let email_search = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        assert!(validate_independent_admin_secrets([
            ("introspection", Some(introspection)),
            ("exchange", Some(exchange)),
            ("email-search", Some(email_search)),
        ])
        .is_ok());
        assert!(validate_independent_admin_secrets([
            ("introspection", Some(introspection)),
            ("exchange", Some(introspection)),
            ("email-search", Some(email_search)),
        ])
        .is_err());
        assert!(validate_independent_admin_secrets([
            ("introspection", None),
            ("exchange", Some(exchange)),
            ("email-search", Some(exchange)),
        ])
        .is_err());
    }
}
