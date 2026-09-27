//! Provider-neutral asymmetric JWT verification and authority-only signing.
//!
//! This module accepts signed compact JWS tokens from Supabase, Neon Auth, or
//! another explicitly configured issuer. It deliberately does not turn claims
//! into product authorization: callers must apply their own tenant, role, and
//! resource policy after verification.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures_util::StreamExt;
use jsonwebtoken::{
    decode, decode_header, encode,
    jwk::{
        AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse,
    },
    Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde_json::{Map, Value};
use tokio::sync::{Mutex, RwLock};

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(600);
const MAX_CACHE_TTL: Duration = Duration::from_secs(600);
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_JWKS_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_SIGNED_TOKEN_TTL: Duration = Duration::from_secs(3600);
const MIN_UNKNOWN_KID_REFRESH: Duration = Duration::from_secs(30);
const MAX_JWKS_KEYS: usize = 64;

/// A bounded, non-sensitive reason for a failed verification operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtVerificationError {
    /// The token or its trust metadata was definitively rejected.
    Invalid(&'static str),
    /// The configured authority could not currently provide a decision.
    Unavailable(&'static str),
    /// The verifier or signer configuration is unsafe or incomplete.
    Configuration(&'static str),
}

impl fmt::Display for JwtVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, reason) = match self {
            Self::Invalid(reason) => ("invalid", reason),
            Self::Unavailable(reason) => ("unavailable", reason),
            Self::Configuration(reason) => ("configuration", reason),
        };
        write!(formatter, "provider JWT {kind}: {reason}")
    }
}

impl std::error::Error for JwtVerificationError {}

/// Exact trust policy for one token issuer.
#[derive(Clone, Debug)]
pub struct ProviderJwtConfig {
    /// Low-cardinality provider label used only for diagnostics.
    pub provider: String,
    /// Exact expected `iss` claim.
    pub issuer: String,
    /// One or more accepted audience values.
    pub audiences: Vec<String>,
    /// HTTPS JWKS discovery endpoint.
    pub jwks_url: String,
    /// Explicit algorithm allowlist. Only ES256 and RS256 are supported.
    pub allowed_algorithms: Vec<Algorithm>,
    /// Fresh-key cache lifetime. Values above ten minutes are rejected.
    pub cache_ttl: Duration,
    /// Network deadline for JWKS discovery.
    pub http_timeout: Duration,
    /// Clock skew applied to `exp`, `nbf`, and `iat` validation.
    pub clock_skew: Duration,
    /// Require an `iat` claim in addition to validating it when present.
    pub require_iat: bool,
    /// Require an `nbf` claim in addition to validating it when present.
    pub require_nbf: bool,
    /// Optional maximum age measured from `iat`.
    pub max_token_age: Option<Duration>,
    /// Maximum compact token size accepted before parsing.
    pub max_token_bytes: usize,
    /// Maximum JWKS response body size.
    pub max_jwks_bytes: usize,
    /// Test/self-hosting escape hatch. Production defaults to HTTPS only.
    pub allow_insecure_http: bool,
}

impl ProviderJwtConfig {
    /// Secure defaults for an issuer. The caller must still choose audiences,
    /// algorithms, and the exact JWKS URL explicitly.
    pub fn new(
        provider: impl Into<String>,
        issuer: impl Into<String>,
        audiences: Vec<String>,
        jwks_url: impl Into<String>,
        allowed_algorithms: Vec<Algorithm>,
    ) -> Self {
        Self {
            provider: provider.into(),
            issuer: issuer.into(),
            audiences,
            jwks_url: jwks_url.into(),
            allowed_algorithms,
            cache_ttl: DEFAULT_CACHE_TTL,
            http_timeout: DEFAULT_HTTP_TIMEOUT,
            clock_skew: Duration::from_secs(30),
            require_iat: true,
            require_nbf: false,
            max_token_age: None,
            max_token_bytes: DEFAULT_MAX_TOKEN_BYTES,
            max_jwks_bytes: DEFAULT_MAX_JWKS_BYTES,
            allow_insecure_http: false,
        }
    }

    /// Standard Supabase asymmetric signing-key endpoints.
    pub fn supabase(
        project_url: &str,
        audiences: Vec<String>,
        allowed_algorithms: Vec<Algorithm>,
    ) -> Result<Self, JwtVerificationError> {
        let base = project_url.trim_end_matches('/');
        if base.is_empty() {
            return Err(JwtVerificationError::Configuration("empty project URL"));
        }
        Ok(Self::new(
            "supabase",
            format!("{base}/auth/v1"),
            audiences,
            format!("{base}/auth/v1/.well-known/jwks.json"),
            allowed_algorithms,
        ))
    }

    fn validate(&self) -> Result<(), JwtVerificationError> {
        if self.provider.trim().is_empty() || self.issuer.trim().is_empty() {
            return Err(JwtVerificationError::Configuration(
                "empty provider or issuer",
            ));
        }
        if self.audiences.is_empty() || self.audiences.iter().any(|value| value.trim().is_empty()) {
            return Err(JwtVerificationError::Configuration("empty audience policy"));
        }
        if self.allowed_algorithms.is_empty()
            || self
                .allowed_algorithms
                .iter()
                .any(|algorithm| !matches!(algorithm, Algorithm::ES256 | Algorithm::RS256))
        {
            return Err(JwtVerificationError::Configuration(
                "unsupported algorithm policy",
            ));
        }
        if self.cache_ttl.is_zero() || self.cache_ttl > MAX_CACHE_TTL {
            return Err(JwtVerificationError::Configuration(
                "JWKS cache TTL must be 1..600 seconds",
            ));
        }
        if self.http_timeout.is_zero()
            || self.max_token_bytes == 0
            || self.max_jwks_bytes == 0
            || self.max_jwks_bytes > 4 * DEFAULT_MAX_JWKS_BYTES
        {
            return Err(JwtVerificationError::Configuration(
                "invalid verifier bounds",
            ));
        }
        let url = reqwest::Url::parse(&self.jwks_url)
            .map_err(|_| JwtVerificationError::Configuration("invalid JWKS URL"))?;
        if url.scheme() != "https" && !(self.allow_insecure_http && url.scheme() == "http") {
            return Err(JwtVerificationError::Configuration(
                "JWKS URL must use HTTPS",
            ));
        }
        if url.host_str().is_none() {
            return Err(JwtVerificationError::Configuration("JWKS URL has no host"));
        }
        Ok(())
    }
}

/// Cryptographically verified claims. `Debug` intentionally omits claims and
/// subject because they may contain personal or high-cardinality data.
pub struct VerifiedJwt {
    provider: String,
    issuer: String,
    algorithm: Algorithm,
    key_id: String,
    subject: String,
    claims: Map<String, Value>,
}

impl VerifiedJwt {
    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn claims(&self) -> &Map<String, Value> {
        &self.claims
    }
}

impl fmt::Debug for VerifiedJwt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedJwt")
            .field("provider", &self.provider)
            .field("issuer", &self.issuer)
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("subject", &"[redacted]")
            .field("claims", &"[redacted]")
            .finish()
    }
}

struct CachedJwks {
    fetched_at: Instant,
    set: Arc<JwkSet>,
}

/// Async JWKS verifier with a ten-minute maximum cache, refresh-on-unknown-kid,
/// single-flight refresh, bounded response bodies, and no stale-key grace.
pub struct ProviderJwtVerifier {
    config: ProviderJwtConfig,
    http: reqwest::Client,
    static_jwks: Option<Arc<JwkSet>>,
    cache: RwLock<Option<CachedJwks>>,
    refresh_lock: Mutex<()>,
}

impl ProviderJwtVerifier {
    pub fn new(config: ProviderJwtConfig) -> Result<Self, JwtVerificationError> {
        config.validate()?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.http_timeout)
            .build()
            .map_err(|_| JwtVerificationError::Configuration("HTTP client setup failed"))?;
        Ok(Self {
            config,
            http,
            static_jwks: None,
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
        })
    }

    pub fn with_static_jwks(
        config: ProviderJwtConfig,
        jwks: JwkSet,
    ) -> Result<Self, JwtVerificationError> {
        let mut verifier = Self::new(config)?;
        verifier.static_jwks = Some(Arc::new(jwks));
        Ok(verifier)
    }

    pub async fn verify(&self, token: &str) -> Result<VerifiedJwt, JwtVerificationError> {
        let header = checked_header(token, &self.config)?;
        let kid = header
            .kid
            .as_deref()
            .ok_or(JwtVerificationError::Invalid("missing key id"))?;
        let set = self.jwks_for(kid).await?;
        verify_with_jwks(token, &set, &self.config)
    }

    /// Purge locally cached public keys after an urgent provider revocation.
    pub async fn purge_cache(&self) {
        *self.cache.write().await = None;
    }

    async fn jwks_for(&self, kid: &str) -> Result<Arc<JwkSet>, JwtVerificationError> {
        if let Some(set) = &self.static_jwks {
            return match find_unique_key(set, kid)? {
                Some(_) => Ok(Arc::clone(set)),
                None => Err(JwtVerificationError::Invalid("unknown key id")),
            };
        }

        {
            let cache = self.cache.read().await;
            if let Some(cache) = cache
                .as_ref()
                .filter(|entry| entry.fetched_at.elapsed() < self.config.cache_ttl)
            {
                if find_unique_key(&cache.set, kid)?.is_some() {
                    return Ok(Arc::clone(&cache.set));
                }
                if cache.fetched_at.elapsed() < MIN_UNKNOWN_KID_REFRESH {
                    return Err(JwtVerificationError::Invalid("unknown key id"));
                }
            }
        }

        let fresh = self.refresh(kid).await?;
        match find_unique_key(&fresh, kid)? {
            Some(_) => Ok(fresh),
            None => Err(JwtVerificationError::Invalid("unknown key id")),
        }
    }

    async fn refresh(&self, kid: &str) -> Result<Arc<JwkSet>, JwtVerificationError> {
        let _guard = self.refresh_lock.lock().await;
        {
            let cache = self.cache.read().await;
            if let Some(cache) = cache
                .as_ref()
                .filter(|entry| entry.fetched_at.elapsed() < self.config.cache_ttl)
            {
                if find_unique_key(&cache.set, kid)?.is_some() {
                    return Ok(Arc::clone(&cache.set));
                }
                if cache.fetched_at.elapsed() < MIN_UNKNOWN_KID_REFRESH {
                    return Err(JwtVerificationError::Invalid("unknown key id"));
                }
            }
        }
        let response = self
            .http
            .get(&self.config.jwks_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| JwtVerificationError::Unavailable("JWKS fetch failed"))?;
        if !response.status().is_success() {
            return Err(JwtVerificationError::Unavailable(
                "JWKS endpoint rejected request",
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.config.max_jwks_bytes as u64)
        {
            return Err(JwtVerificationError::Unavailable("JWKS response too large"));
        }

        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| JwtVerificationError::Unavailable("JWKS body failed"))?;
            if body.len().saturating_add(chunk.len()) > self.config.max_jwks_bytes {
                return Err(JwtVerificationError::Unavailable("JWKS response too large"));
            }
            body.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&body)
            .map_err(|_| JwtVerificationError::Unavailable("JWKS response malformed"))?;
        let keys = value
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(JwtVerificationError::Unavailable("JWKS response malformed"))?;
        if keys.is_empty() || keys.len() > MAX_JWKS_KEYS {
            return Err(JwtVerificationError::Unavailable("JWKS contains no keys"));
        }
        const PRIVATE_PARAMETERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "oth"];
        if keys.iter().any(|key| {
            key.as_object().is_none_or(|object| {
                PRIVATE_PARAMETERS
                    .iter()
                    .any(|parameter| object.contains_key(*parameter))
            })
        }) {
            return Err(JwtVerificationError::Unavailable(
                "JWKS exposes private key material",
            ));
        }
        let set: JwkSet = serde_json::from_value(value)
            .map_err(|_| JwtVerificationError::Unavailable("JWKS response malformed"))?;
        let set = Arc::new(set);
        *self.cache.write().await = Some(CachedJwks {
            fetched_at: Instant::now(),
            set: Arc::clone(&set),
        });
        Ok(set)
    }
}

/// Verify against a caller-pinned JWKS without network access.
pub fn verify_with_jwks(
    token: &str,
    jwks: &JwkSet,
    config: &ProviderJwtConfig,
) -> Result<VerifiedJwt, JwtVerificationError> {
    config.validate()?;
    let header = checked_header(token, config)?;
    let kid = header
        .kid
        .as_deref()
        .ok_or(JwtVerificationError::Invalid("missing key id"))?;
    let key = find_unique_key(jwks, kid)?.ok_or(JwtVerificationError::Invalid("unknown key id"))?;
    validate_key(key, header.alg)?;
    let decoding_key = DecodingKey::from_jwk(key)
        .map_err(|_| JwtVerificationError::Invalid("unusable verification key"))?;

    let mut validation = Validation::new(header.alg);
    validation.algorithms = config.allowed_algorithms.clone();
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&config.audiences);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    if config.require_nbf {
        validation.required_spec_claims.insert("nbf".to_owned());
    }
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = config.clock_skew.as_secs();

    let claims = decode::<Map<String, Value>>(token, &decoding_key, &validation)
        .map_err(|_| JwtVerificationError::Invalid("signature or claims rejected"))?
        .claims;
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 1024)
        .ok_or(JwtVerificationError::Invalid("invalid subject"))?
        .to_owned();
    validate_iat(&claims, config)?;

    Ok(VerifiedJwt {
        provider: config.provider.clone(),
        issuer: config.issuer.clone(),
        algorithm: header.alg,
        key_id: kid.to_owned(),
        subject,
        claims,
    })
}

fn checked_header(token: &str, config: &ProviderJwtConfig) -> Result<Header, JwtVerificationError> {
    if token.is_empty() || token.len() > config.max_token_bytes || token.split('.').count() != 3 {
        return Err(JwtVerificationError::Invalid("malformed compact token"));
    }
    let header =
        decode_header(token).map_err(|_| JwtVerificationError::Invalid("invalid header"))?;
    if !config.allowed_algorithms.contains(&header.alg) {
        return Err(JwtVerificationError::Invalid("algorithm not allowed"));
    }
    if header.typ.as_deref().is_some_and(|value| value != "JWT") {
        return Err(JwtVerificationError::Invalid("unexpected token type"));
    }
    if header.kid.as_deref().is_none_or(str::is_empty) {
        return Err(JwtVerificationError::Invalid("missing key id"));
    }
    Ok(header)
}

fn validate_key(key: &Jwk, algorithm: Algorithm) -> Result<(), JwtVerificationError> {
    if key
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|usage| usage != &PublicKeyUse::Signature)
    {
        return Err(JwtVerificationError::Invalid(
            "key not allowed for signatures",
        ));
    }
    if key
        .common
        .key_operations
        .as_ref()
        .is_some_and(|ops| !ops.contains(&KeyOperations::Verify))
    {
        return Err(JwtVerificationError::Invalid(
            "key not allowed for verification",
        ));
    }
    let expected = match algorithm {
        Algorithm::ES256 => KeyAlgorithm::ES256,
        Algorithm::RS256 => KeyAlgorithm::RS256,
        _ => return Err(JwtVerificationError::Invalid("algorithm not supported")),
    };
    if key
        .common
        .key_algorithm
        .is_some_and(|actual| actual != expected)
    {
        return Err(JwtVerificationError::Invalid("key algorithm mismatch"));
    }
    let type_matches = match (&key.algorithm, algorithm) {
        (AlgorithmParameters::EllipticCurve(parameters), Algorithm::ES256) => {
            parameters.curve == EllipticCurve::P256
                && !parameters.x.is_empty()
                && !parameters.y.is_empty()
        }
        (AlgorithmParameters::RSA(parameters), Algorithm::RS256) => {
            URL_SAFE_NO_PAD
                .decode(&parameters.n)
                .is_ok_and(|modulus| modulus.len() >= 256)
                && URL_SAFE_NO_PAD
                    .decode(&parameters.e)
                    .is_ok_and(|exponent| !exponent.is_empty() && exponent.len() <= 4)
        }
        _ => false,
    };
    type_matches
        .then_some(())
        .ok_or(JwtVerificationError::Invalid("key type mismatch"))
}

fn find_unique_key<'a>(
    jwks: &'a JwkSet,
    kid: &str,
) -> Result<Option<&'a Jwk>, JwtVerificationError> {
    let mut matching = jwks
        .keys
        .iter()
        .filter(|key| key.common.key_id.as_deref() == Some(kid));
    let first = matching.next();
    if matching.next().is_some() {
        return Err(JwtVerificationError::Unavailable("duplicate key id"));
    }
    Ok(first)
}

fn validate_iat(
    claims: &Map<String, Value>,
    config: &ProviderJwtConfig,
) -> Result<(), JwtVerificationError> {
    let iat = claims.get("iat").and_then(numeric_date);
    if config.require_iat && iat.is_none() {
        return Err(JwtVerificationError::Invalid("missing issued-at claim"));
    }
    if let Some(iat) = iat {
        let now = unix_seconds()?;
        let skew = config.clock_skew.as_secs();
        if iat > now.saturating_add(skew) {
            return Err(JwtVerificationError::Invalid("issued-at is in the future"));
        }
        if let Some(max_age) = config.max_token_age {
            if now.saturating_sub(iat) > max_age.as_secs().saturating_add(skew) {
                return Err(JwtVerificationError::Invalid("token is older than policy"));
            }
        }
    } else if config.max_token_age.is_some() {
        return Err(JwtVerificationError::Invalid(
            "issued-at required by max-age policy",
        ));
    }
    Ok(())
}

fn numeric_date(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
}

fn unix_seconds() -> Result<u64, JwtVerificationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| JwtVerificationError::Unavailable("system clock unavailable"))
}

/// Server-only signing policy. Private key bytes are accepted only by the
/// constructor, stored in `EncodingKey`, and never rendered through `Debug`.
#[derive(Clone, Debug)]
pub struct SigningConfig {
    pub issuer: String,
    pub audience: String,
    pub key_id: String,
    pub algorithm: Algorithm,
    pub token_ttl: Duration,
}

/// Central authority signer. Product services should verify tokens, not mint
/// interchangeable identities, unless they are explicitly the configured issuer.
pub struct ServerJwtSigner {
    config: SigningConfig,
    key: EncodingKey,
}

impl fmt::Debug for ServerJwtSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerJwtSigner")
            .field("config", &self.config)
            .field("private_key", &"[redacted]")
            .finish()
    }
}

impl ServerJwtSigner {
    /// Load an EC PKCS#8 or RSA PEM key supplied by the runtime secret manager.
    pub fn from_pem(
        config: SigningConfig,
        private_key_pem: &[u8],
    ) -> Result<Self, JwtVerificationError> {
        validate_signing_config(&config)?;
        let key = match config.algorithm {
            Algorithm::ES256 => EncodingKey::from_ec_pem(private_key_pem),
            Algorithm::RS256 => EncodingKey::from_rsa_pem(private_key_pem),
            _ => {
                return Err(JwtVerificationError::Configuration(
                    "unsupported signing algorithm",
                ))
            }
        }
        .map_err(|_| JwtVerificationError::Configuration("private signing key rejected"))?;
        Ok(Self { config, key })
    }

    /// Mint a short-lived token. Reserved registered claims cannot be replaced
    /// by custom data.
    pub fn mint(
        &self,
        subject: &str,
        custom_claims: Map<String, Value>,
    ) -> Result<SignedJwt, JwtVerificationError> {
        if subject.is_empty() || subject.len() > 1024 {
            return Err(JwtVerificationError::Configuration(
                "invalid signing subject",
            ));
        }
        const RESERVED: [&str; 6] = ["iss", "aud", "sub", "iat", "nbf", "exp"];
        if RESERVED
            .iter()
            .any(|name| custom_claims.contains_key(*name))
        {
            return Err(JwtVerificationError::Configuration(
                "custom claim replaces registered claim",
            ));
        }
        let now = unix_seconds()?;
        let mut claims = custom_claims;
        claims.insert("iss".into(), self.config.issuer.clone().into());
        claims.insert("aud".into(), self.config.audience.clone().into());
        claims.insert("sub".into(), subject.into());
        claims.insert("iat".into(), now.into());
        claims.insert("nbf".into(), now.into());
        claims.insert(
            "exp".into(),
            now.saturating_add(self.config.token_ttl.as_secs()).into(),
        );

        let mut header = Header::new(self.config.algorithm);
        header.kid = Some(self.config.key_id.clone());
        header.typ = Some("JWT".into());
        encode(&header, &claims, &self.key)
            .map(SignedJwt)
            .map_err(|_| JwtVerificationError::Unavailable("token signing failed"))
    }
}

fn validate_signing_config(config: &SigningConfig) -> Result<(), JwtVerificationError> {
    if config.issuer.trim().is_empty()
        || config.audience.trim().is_empty()
        || config.key_id.trim().is_empty()
        || config.token_ttl.is_zero()
        || config.token_ttl > MAX_SIGNED_TOKEN_TTL
        || !matches!(config.algorithm, Algorithm::ES256 | Algorithm::RS256)
    {
        return Err(JwtVerificationError::Configuration(
            "invalid signing policy",
        ));
    }
    Ok(())
}

/// A secret-bearing compact token whose normal formatting is always redacted.
pub struct SignedJwt(String);

impl SignedJwt {
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SignedJwt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignedJwt([redacted])")
    }
}

impl fmt::Display for SignedJwt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use futures_util::future::join_all;
    use p256::{
        pkcs8::{EncodePrivateKey, LineEnding},
        SecretKey,
    };
    use rsa::{rand_core::OsRng, traits::PublicKeyParts, RsaPrivateKey};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn config(algorithm: Algorithm) -> ProviderJwtConfig {
        let mut config = ProviderJwtConfig::new(
            "fixture",
            "https://issuer.test",
            vec!["api".into()],
            "https://issuer.test/.well-known/jwks.json",
            vec![algorithm],
        );
        config.clock_skew = Duration::ZERO;
        config
    }

    fn signing_config(algorithm: Algorithm, kid: &str) -> SigningConfig {
        SigningConfig {
            issuer: "https://issuer.test".into(),
            audience: "api".into(),
            key_id: kid.into(),
            algorithm,
            token_ttl: Duration::from_secs(300),
        }
    }

    fn ec_jwks(secret: &SecretKey, kid: &str) -> JwkSet {
        let mut key = serde_json::to_value(secret.public_key().to_jwk()).unwrap();
        let object = key.as_object_mut().unwrap();
        object.insert("kid".into(), kid.into());
        object.insert("alg".into(), "ES256".into());
        object.insert("use".into(), "sig".into());
        object.insert("key_ops".into(), serde_json::json!(["verify"]));
        serde_json::from_value(serde_json::json!({ "keys": [key] })).unwrap()
    }

    async fn start_jwks_server(responses: Vec<String>, requests: Arc<AtomicUsize>) -> String {
        let responses = Arc::new(responses);
        let app = Router::new().route(
            "/",
            get(move || {
                let responses = Arc::clone(&responses);
                let requests = Arc::clone(&requests);
                async move {
                    let index = requests.fetch_add(1, Ordering::SeqCst);
                    responses[index.min(responses.len() - 1)].clone()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{address}/")
    }

    fn sign_claims(secret_pem: &[u8], kid: &str, claims: Map<String, Value>) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.into());
        header.typ = Some("JWT".into());
        encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(secret_pem).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn es256_sign_and_verify_round_trip() {
        let secret = SecretKey::random(&mut OsRng);
        let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        let jwks = ec_jwks(&secret, "ec-1");
        let signer =
            ServerJwtSigner::from_pem(signing_config(Algorithm::ES256, "ec-1"), pem.as_bytes())
                .unwrap();
        let token = signer
            .mint(
                "user-1",
                Map::from_iter([("role".into(), "authenticated".into())]),
            )
            .unwrap();
        let verified =
            verify_with_jwks(token.expose_secret(), &jwks, &config(Algorithm::ES256)).unwrap();
        assert_eq!(verified.subject(), "user-1");
        assert_eq!(verified.claims()["role"], "authenticated");
        assert_eq!(format!("{token}"), "[redacted]");
    }

    #[test]
    fn rs256_sign_and_verify_round_trip() {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
        let public = private.to_public_key();
        let jwks: JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
                "kid": "rsa-1", "alg": "RS256", "use": "sig", "key_ops": ["verify"]
            }]
        }))
        .unwrap();
        let signer =
            ServerJwtSigner::from_pem(signing_config(Algorithm::RS256, "rsa-1"), pem.as_bytes())
                .unwrap();
        let token = signer.mint("user-2", Map::new()).unwrap();
        let verified =
            verify_with_jwks(token.expose_secret(), &jwks, &config(Algorithm::RS256)).unwrap();
        assert_eq!(verified.subject(), "user-2");
        assert_eq!(verified.algorithm(), Algorithm::RS256);
    }

    #[test]
    fn rejects_wrong_audience_algorithm_unknown_key_and_registered_override() {
        let secret = SecretKey::random(&mut OsRng);
        let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        let jwks = ec_jwks(&secret, "ec-1");
        let signer =
            ServerJwtSigner::from_pem(signing_config(Algorithm::ES256, "ec-1"), pem.as_bytes())
                .unwrap();
        let token = signer.mint("user-1", Map::new()).unwrap();

        let mut wrong_audience = config(Algorithm::ES256);
        wrong_audience.audiences = vec!["other".into()];
        assert!(matches!(
            verify_with_jwks(token.expose_secret(), &jwks, &wrong_audience),
            Err(JwtVerificationError::Invalid(_))
        ));

        let wrong_algorithm = config(Algorithm::RS256);
        assert_eq!(
            verify_with_jwks(token.expose_secret(), &jwks, &wrong_algorithm).unwrap_err(),
            JwtVerificationError::Invalid("algorithm not allowed")
        );

        let empty = JwkSet { keys: vec![] };
        assert_eq!(
            verify_with_jwks(token.expose_secret(), &empty, &config(Algorithm::ES256)).unwrap_err(),
            JwtVerificationError::Invalid("unknown key id")
        );

        assert_eq!(
            signer
                .mint("user-1", Map::from_iter([("iss".into(), "evil".into())]))
                .unwrap_err(),
            JwtVerificationError::Configuration("custom claim replaces registered claim")
        );
    }

    #[tokio::test]
    async fn concurrent_cold_cache_uses_one_single_flight_fetch() {
        let secret = SecretKey::random(&mut OsRng);
        let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        let jwks = ec_jwks(&secret, "ec-concurrent");
        let signer = ServerJwtSigner::from_pem(
            signing_config(Algorithm::ES256, "ec-concurrent"),
            pem.as_bytes(),
        )
        .unwrap();
        let token = Arc::new(signer.mint("user-concurrent", Map::new()).unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let uri = start_jwks_server(
            vec![serde_json::to_string(&jwks).unwrap()],
            Arc::clone(&requests),
        )
        .await;
        let mut policy = config(Algorithm::ES256);
        policy.jwks_url = uri;
        policy.allow_insecure_http = true;
        let verifier = Arc::new(ProviderJwtVerifier::new(policy).unwrap());

        let attempts = (0..24).map(|_| {
            let verifier = Arc::clone(&verifier);
            let token = Arc::clone(&token);
            async move { verifier.verify(token.expose_secret()).await }
        });
        let results = join_all(attempts).await;
        assert!(results.iter().all(|result| {
            result
                .as_ref()
                .is_ok_and(|verified| verified.subject() == "user-concurrent")
        }));
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unknown_kid_is_throttled_until_purge_loads_rotated_key() {
        let old_secret = SecretKey::random(&mut OsRng);
        let rotated_secret = SecretKey::random(&mut OsRng);
        let rotated_pem = rotated_secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        let signer = ServerJwtSigner::from_pem(
            signing_config(Algorithm::ES256, "rotated"),
            rotated_pem.as_bytes(),
        )
        .unwrap();
        let token = signer.mint("user-rotated", Map::new()).unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let uri = start_jwks_server(
            vec![
                serde_json::to_string(&ec_jwks(&old_secret, "old")).unwrap(),
                serde_json::to_string(&ec_jwks(&rotated_secret, "rotated")).unwrap(),
            ],
            Arc::clone(&requests),
        )
        .await;
        let mut policy = config(Algorithm::ES256);
        policy.jwks_url = uri;
        policy.allow_insecure_http = true;
        let verifier = ProviderJwtVerifier::new(policy).unwrap();

        for _ in 0..2 {
            assert_eq!(
                verifier.verify(token.expose_secret()).await.unwrap_err(),
                JwtVerificationError::Invalid("unknown key id")
            );
        }
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        verifier.purge_cache().await;
        let verified = verifier.verify(token.expose_secret()).await.unwrap();
        assert_eq!(verified.subject(), "user-rotated");
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn adversarial_jwks_preserves_failure_classification_and_size_bound() {
        let secret = SecretKey::random(&mut OsRng);
        let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        let signer =
            ServerJwtSigner::from_pem(signing_config(Algorithm::ES256, "ec-1"), pem.as_bytes())
                .unwrap();
        let token = signer.mint("user-1", Map::new()).unwrap();

        let mut duplicate = ec_jwks(&secret, "ec-1");
        duplicate.keys.push(duplicate.keys[0].clone());
        assert_eq!(
            verify_with_jwks(token.expose_secret(), &duplicate, &config(Algorithm::ES256))
                .unwrap_err(),
            JwtVerificationError::Unavailable("duplicate key id")
        );

        let mut wrong_curve = serde_json::to_value(ec_jwks(&secret, "ec-1")).unwrap();
        wrong_curve["keys"][0]["crv"] = "P-384".into();
        let wrong_curve: JwkSet = serde_json::from_value(wrong_curve).unwrap();
        assert_eq!(
            verify_with_jwks(
                token.expose_secret(),
                &wrong_curve,
                &config(Algorithm::ES256)
            )
            .unwrap_err(),
            JwtVerificationError::Invalid("key type mismatch")
        );

        let private_jwks = serde_json::json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "x": "AQ", "y": "AQ",
                "d": "secret", "kid": "ec-1", "alg": "ES256"
            }]
        })
        .to_string();
        let requests = Arc::new(AtomicUsize::new(0));
        let uri = start_jwks_server(vec![private_jwks], Arc::clone(&requests)).await;
        let mut private_policy = config(Algorithm::ES256);
        private_policy.jwks_url = uri;
        private_policy.allow_insecure_http = true;
        let private_verifier = ProviderJwtVerifier::new(private_policy).unwrap();
        assert_eq!(
            private_verifier
                .verify(token.expose_secret())
                .await
                .unwrap_err(),
            JwtVerificationError::Unavailable("JWKS exposes private key material")
        );

        let oversized = serde_json::json!({ "keys": [{ "padding": "x".repeat(256) }] }).to_string();
        let uri = start_jwks_server(vec![oversized], Arc::new(AtomicUsize::new(0))).await;
        let mut oversized_policy = config(Algorithm::ES256);
        oversized_policy.jwks_url = uri;
        oversized_policy.allow_insecure_http = true;
        oversized_policy.max_jwks_bytes = 32;
        let oversized_verifier = ProviderJwtVerifier::new(oversized_policy).unwrap();
        assert_eq!(
            oversized_verifier
                .verify(token.expose_secret())
                .await
                .unwrap_err(),
            JwtVerificationError::Unavailable("JWKS response too large")
        );
    }

    #[test]
    fn temporal_policy_rejects_expired_future_and_over_age_tokens() {
        let secret = SecretKey::random(&mut OsRng);
        let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
        let jwks = ec_jwks(&secret, "ec-time");
        let now = unix_seconds().unwrap();
        let cases = [
            ("expired", now - 600, now - 300, None),
            ("future", now + 60, now + 360, None),
            (
                "over-age",
                now - 400,
                now + 500,
                Some(Duration::from_secs(300)),
            ),
        ];
        for (subject, issued_at, expires_at, max_age) in cases {
            let claims = Map::from_iter([
                ("iss".into(), "https://issuer.test".into()),
                ("aud".into(), "api".into()),
                ("sub".into(), subject.into()),
                ("iat".into(), issued_at.into()),
                ("nbf".into(), issued_at.into()),
                ("exp".into(), expires_at.into()),
            ]);
            let token = sign_claims(pem.as_bytes(), "ec-time", claims);
            let mut policy = config(Algorithm::ES256);
            policy.max_token_age = max_age;
            assert!(matches!(
                verify_with_jwks(&token, &jwks, &policy),
                Err(JwtVerificationError::Invalid(_))
            ));
        }
    }

    #[tokio::test]
    async fn malformed_token_corpus_is_rejected_without_network_access() {
        let requests = Arc::new(AtomicUsize::new(0));
        let uri = start_jwks_server(
            vec![serde_json::json!({ "keys": [] }).to_string()],
            Arc::clone(&requests),
        )
        .await;
        let mut policy = config(Algorithm::ES256);
        policy.jwks_url = uri;
        policy.allow_insecure_http = true;
        let verifier = ProviderJwtVerifier::new(policy).unwrap();
        let malformed = [
            "",
            ".",
            "a.b",
            "a.b.c.d",
            "!!!.e30.signature",
            "e30.e30.signature",
            "eyJhbGciOiJub25lIiwia2lkIjoieCJ9.e30.signature",
            "eyJhbGciOiJFUzI1NiIsImtpZCI6IngiLCJ0eXAiOiJKV0UifQ.e30.signature",
        ];
        for token in malformed {
            assert!(matches!(
                verifier.verify(token).await,
                Err(JwtVerificationError::Invalid(_))
            ));
        }
        assert_eq!(requests.load(Ordering::SeqCst), 0);
    }
}
