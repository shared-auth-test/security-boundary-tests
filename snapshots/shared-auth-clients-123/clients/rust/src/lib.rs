//! Thin typed client for the shared-auth server (see ../../ENDPOINTS.md).
//!
//! Verbs only — guard logic (the dual-auth race, limited HTML) lives in
//! shared-auth-lib. This crate is for services that need to call the API with
//! bounded transport defaults and, where configured, an authenticated
//! introspection credential.

use std::{sync::Arc, time::Duration};

use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    redirect::Policy,
    Method, RequestBuilder, Response,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

mod session;
pub use session::{PasswordlessAccepted, SessionResponse};

const DEFAULT_MAX_REQUEST_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const DEFAULT_INTROSPECTION_AUDIENCE: &str = "oresoftware";
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_REQUIRED_SCOPES: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Uniform 401 from the server.
    #[error("unauthorized")]
    Unauthorized,
    /// Protected introspection was called without the independent service
    /// credential. No HTTP request was attempted.
    #[error("introspection service credential is required")]
    MissingServiceCredential,
    #[error("invalid shared-auth base URL")]
    InvalidBaseUrl,
    #[error("invalid {0}")]
    InvalidInput(&'static str),
    #[error("request body exceeds {limit} bytes")]
    RequestTooLarge { limit: usize },
    #[error("response body exceeds {limit} bytes")]
    ResponseTooLarge { limit: usize },
    #[error("request JSON encoding failed")]
    Encode {
        #[source]
        source: serde_json::Error,
    },
    #[error("response JSON decoding failed")]
    Decode {
        #[source]
        source: serde_json::Error,
    },
    #[error("transport failed")]
    Transport(#[from] reqwest::Error),
    #[error("unexpected status {0}")]
    Status(u16),
    #[error(
        "refusing cleartext http:// to public host {0:?}: use https://, an in-cluster \
         address, or loopback (or opt out with SharedAuthClient::allow_insecure_transport)"
    )]
    InsecureTransport(String),
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: u64,
    pub shared_user_id: String,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub provider_tenant: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StepUpResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: u64,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Introspection {
    pub active: bool,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub aud: Option<String>,
    #[serde(default)]
    pub iat: Option<u64>,
    #[serde(default)]
    pub nbf: Option<u64>,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(default)]
    pub jti: Option<String>,
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub auth_time: Option<u64>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub provider_tenant: Option<String>,
    #[serde(default)]
    pub provider_subject: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub aal: Option<u8>,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(default)]
    pub parent_jti: Option<String>,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

impl Introspection {
    /// Missing legacy assurance claims never satisfy an explicit policy.
    pub fn has_acr(&self, required: &str) -> bool {
        self.active && self.acr.as_deref() == Some(required)
    }

    pub fn used_method(&self, method: &str) -> bool {
        self.active && self.amr.iter().any(|candidate| candidate == method)
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.active && self.roles.iter().any(|candidate| candidate == role)
    }

    pub fn has_scope(&self, required: &str) -> bool {
        self.active
            && self.scope.as_deref().is_some_and(|scope| {
                scope
                    .split_ascii_whitespace()
                    .any(|value| value == required)
            })
    }

    pub fn has_delegation_lineage(&self) -> bool {
        self.active
            && self.jti.as_deref().is_some_and(|value| !value.is_empty())
            && self
                .parent_jti
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            && self.jti != self.parent_jti
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Capabilities {
    pub mfa_enabled: bool,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub threefa_import_scheme: Option<String>,
    #[serde(default)]
    pub biometric_model: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Factor {
    pub factor_id: String,
    pub kind: String,
    #[serde(default)]
    pub label: Option<String>,
    pub enabled: bool,
    #[serde(default)]
    pub confirmed_at: Option<String>,
    #[serde(default)]
    pub last_used_at: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TotpEnrollment {
    pub factor_id: String,
    pub secret_base32: String,
    pub otpauth_uri: String,
    pub threefa_import_uri: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    EmailOtp,
    SmsOtp,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ChallengeStart {
    pub challenge_id: String,
    pub expires_at: String,
    pub delivery: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CeremonyStart {
    pub challenge_id: String,
    pub options: serde_json::Value,
    pub expires_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TotpEnrollRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TotpConfirmRequest<'a> {
    pub factor_id: &'a str,
    pub code: &'a str,
}

#[derive(Clone, Debug, Serialize)]
pub struct PasskeyRegistrationFinish<'a> {
    pub challenge_id: &'a str,
    pub credential: &'a serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PasskeyAuthenticationFinish<'a> {
    pub challenge_id: &'a str,
    pub credential: &'a serde_json::Value,
}

#[derive(Clone, Serialize)]
struct IntrospectionRequestEnvelope<'a> {
    contract: &'static str,
    payload: IntrospectionRequestPayload<'a>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IntrospectionRequestPayload<'a> {
    token: &'a str,
    audience: &'a str,
    required_scopes: &'a [&'a str],
}

/// Bounded, redirect-free transport shared by the default constructors.
fn default_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .redirect(Policy::none())
        .user_agent("shared-auth-client-rust/0.1")
        .build()
        .expect("static shared-auth HTTP client configuration is valid")
}

#[derive(Clone)]
enum BaseUrl {
    Valid(Url),
    Invalid,
    /// Parsed, but cleartext `http://` to a public host. Held rather than
    /// rejected at construction so a bad config value surfaces as an error from
    /// the first request instead of a panic at startup.
    Insecure(String),
}

#[derive(Clone)]
pub struct SharedAuthClient {
    base: BaseUrl,
    http: reqwest::Client,
    service_credential: Option<Arc<str>>,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl SharedAuthClient {
    /// `base` is the mounted prefix, e.g. `https://gateway/shared-auth`.
    ///
    /// The default transport refuses redirects and bounds connect/request time so
    /// an auth dependency cannot occupy a task indefinitely.
    ///
    /// # Panics
    /// Construction never fails. A base URL is usually a config value, so an
    /// unusable one is reported from the first request — as
    /// [`ClientError::InsecureTransport`] for cleartext to a public host, or
    /// [`ClientError::InvalidBaseUrl`] for an unparseable one — rather than
    /// crashing the process at startup. Use [`Self::try_new`] to check eagerly,
    /// or [`Self::allow_insecure_transport`] for a trusted debugging proxy.
    pub fn new(base: impl Into<String>) -> Self {
        Self::with_http(base, default_http_client())
    }

    /// Eagerly-checked [`Self::new`], for callers that would rather learn about
    /// a bad base URL at startup than on the first request.
    pub fn try_new(base: impl Into<String>) -> Result<Self, ClientError> {
        Self::try_with_http(base, default_http_client())
    }

    /// Construction never fails; see [`Self::new`].
    pub fn with_http(base: impl Into<String>, http: reqwest::Client) -> Self {
        let base = base.into();
        let mut client = Self::allow_insecure_transport(base.clone(), http);
        // Cleartext-to-public takes precedence over "unparseable". A base like
        // `http://localhost@evil.test` is both, and naming the real host is the
        // more actionable diagnosis — `normalize_base` would only report that
        // the URL carries credentials.
        if !transport_is_acceptable(&base) {
            client.base =
                BaseUrl::Insecure(cleartext_http_host(&base).unwrap_or_default().to_owned());
        }
        client
    }

    /// Eagerly-checked [`Self::with_http`].
    pub fn try_with_http(
        base: impl Into<String>,
        http: reqwest::Client,
    ) -> Result<Self, ClientError> {
        let client = Self::with_http(base, http);
        match &client.base {
            BaseUrl::Invalid => Err(ClientError::InvalidBaseUrl),
            BaseUrl::Insecure(host) => Err(ClientError::InsecureTransport(host.clone())),
            BaseUrl::Valid(_) => Ok(client),
        }
    }

    /// Build without the cleartext check. Only for a trusted debugging proxy —
    /// every credential this client sends would travel unencrypted.
    pub fn allow_insecure_transport(base: impl Into<String>, http: reqwest::Client) -> Self {
        let base = base.into();
        Self {
            base: match normalize_base(&base) {
                Ok(base) => BaseUrl::Valid(base),
                Err(()) => BaseUrl::Invalid,
            },
            http,
            service_credential: None,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// Attach the service-to-service bearer required by protected introspection.
    /// The credential is never used for end-user exchange, verification, or MFA
    /// endpoints, where the caller's own access token remains authoritative.
    pub fn with_service_credential(self, credential: impl Into<String>) -> Self {
        Self {
            service_credential: Some(Arc::<str>::from(credential.into())),
            ..self
        }
    }

    pub fn without_service_credential(self) -> Self {
        Self {
            service_credential: None,
            ..self
        }
    }

    pub fn with_max_request_bytes(self, limit: usize) -> Self {
        Self {
            max_request_bytes: limit,
            ..self
        }
    }

    pub fn with_max_response_bytes(self, limit: usize) -> Self {
        Self {
            max_response_bytes: limit,
            ..self
        }
    }

    /// Supabase access token → shared-auth token.
    pub async fn exchange(&self, supabase_token: &str) -> Result<ExchangeResponse, ClientError> {
        let request = self.request(Method::POST, &["auth", "exchange"])?;
        let request = with_bearer(request, supabase_token, "Supabase token")?;
        self.send_json(request).await
    }

    /// RFC-7662-shaped protected introspection using the server's default
    /// shared-auth audience.
    pub async fn introspect(&self, token: &str) -> Result<Introspection, ClientError> {
        self.introspect_with_requirements(token, DEFAULT_INTROSPECTION_AUDIENCE, &[])
            .await
    }

    /// Protected introspection pinned to an exact delegated product audience.
    ///
    /// Resource servers should use this method for user-delegated product
    /// tokens. The independent service credential is attached only to the
    /// introspection request; it is never returned or forwarded to the product.
    pub async fn introspect_for_audience(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<Introspection, ClientError> {
        self.introspect_with_requirements(token, audience, &[])
            .await
    }

    /// Protected introspection with exact audience and scope requirements.
    ///
    /// The independent service credential is checked before the inspected token
    /// or request constraints are parsed, matching the server's fail-closed
    /// authentication order.
    pub async fn introspect_with_requirements(
        &self,
        token: &str,
        audience: &str,
        required_scopes: &[&str],
    ) -> Result<Introspection, ClientError> {
        let credential = self
            .service_credential
            .as_deref()
            .ok_or(ClientError::MissingServiceCredential)?;
        let credential = required_credential(credential, "service credential")?;
        let token = required_credential(token, "token")?;
        let audience = required_identifier(audience, "audience")?;
        validate_required_scopes(required_scopes)?;
        let request = self.request(Method::POST, &["auth", "introspect"])?;
        let request = self.with_json(
            request,
            &IntrospectionRequestEnvelope {
                contract: "IntrospectionRequest",
                payload: IntrospectionRequestPayload {
                    token,
                    audience,
                    required_scopes,
                },
            },
        )?;
        let request = with_bearer(request, credential, "service credential")?;
        self.send_json(request).await
    }

    /// Lightweight bearer check (the gateway `auth_request` endpoint).
    pub async fn verify(&self, token: &str) -> Result<bool, ClientError> {
        let request = self.request(Method::GET, &["auth", "verify"])?;
        let request = with_bearer(request, token, "token")?;
        let response = request.send().await?;
        match response.status().as_u16() {
            200 => Ok(true),
            401 => Ok(false),
            code => Err(ClientError::Status(code)),
        }
    }

    /// The server's public JWKS (for local verification via shared-auth-lib).
    pub async fn jwks(&self) -> Result<serde_json::Value, ClientError> {
        let request = self.request(Method::GET, &[".well-known", "jwks.json"])?;
        self.send_json(request).await
    }

    pub async fn capabilities(&self) -> Result<Capabilities, ClientError> {
        let request = self.request(Method::GET, &["auth", "capabilities"])?;
        self.send_json(request).await
    }

    pub async fn factors(&self, access_token: &str) -> Result<Vec<Factor>, ClientError> {
        self.authed_json(Method::GET, &["auth", "factors"], access_token, None::<&()>)
            .await
    }

    pub async fn enroll_totp(
        &self,
        access_token: &str,
        label: Option<&str>,
    ) -> Result<TotpEnrollment, ClientError> {
        self.authed_json(
            Method::POST,
            &["auth", "factors", "totp", "enroll"],
            access_token,
            Some(&TotpEnrollRequest { label }),
        )
        .await
    }

    pub async fn confirm_totp(
        &self,
        access_token: &str,
        factor_id: &str,
        code: &str,
    ) -> Result<StepUpResponse, ClientError> {
        let factor_id = required_field(factor_id, "factor ID")?;
        let code = required_field(code, "TOTP code")?;
        self.authed_json(
            Method::POST,
            &["auth", "factors", "totp", "confirm"],
            access_token,
            Some(&TotpConfirmRequest { factor_id, code }),
        )
        .await
    }

    pub async fn delete_factor(
        &self,
        access_token: &str,
        factor_id: &str,
    ) -> Result<(), ClientError> {
        let factor_id = required_field(factor_id, "factor ID")?;
        let request = self.request(Method::DELETE, &["auth", "factors", factor_id])?;
        let request = with_bearer(request, access_token, "access token")?;
        decode_empty(request.send().await?)
    }

    pub async fn create_challenge(
        &self,
        access_token: &str,
        kind: ChallengeKind,
    ) -> Result<ChallengeStart, ClientError> {
        self.authed_json(
            Method::POST,
            &["auth", "challenges"],
            access_token,
            Some(&serde_json::json!({ "kind": kind })),
        )
        .await
    }

    pub async fn verify_challenge(
        &self,
        access_token: &str,
        challenge_id: &str,
        code: &str,
    ) -> Result<StepUpResponse, ClientError> {
        let challenge_id = required_field(challenge_id, "challenge ID")?;
        let code = required_field(code, "challenge code")?;
        self.authed_json(
            Method::POST,
            &["auth", "challenges", challenge_id, "verify"],
            access_token,
            Some(&serde_json::json!({ "code": code })),
        )
        .await
    }

    pub async fn start_passkey_registration(
        &self,
        access_token: &str,
        label: Option<&str>,
    ) -> Result<CeremonyStart, ClientError> {
        self.authed_json(
            Method::POST,
            &["auth", "passkeys", "registration", "options"],
            access_token,
            Some(&serde_json::json!({ "label": label })),
        )
        .await
    }

    pub async fn finish_passkey_registration(
        &self,
        access_token: &str,
        challenge_id: &str,
        credential: &serde_json::Value,
        label: Option<&str>,
    ) -> Result<Factor, ClientError> {
        let challenge_id = required_field(challenge_id, "challenge ID")?;
        self.authed_json(
            Method::POST,
            &["auth", "passkeys", "registration", "verify"],
            access_token,
            Some(&PasskeyRegistrationFinish {
                challenge_id,
                credential,
                label,
            }),
        )
        .await
    }

    pub async fn start_passkey_authentication(
        &self,
        access_token: &str,
    ) -> Result<CeremonyStart, ClientError> {
        self.authed_json(
            Method::POST,
            &["auth", "passkeys", "authentication", "options"],
            access_token,
            Some(&serde_json::json!({})),
        )
        .await
    }

    pub async fn finish_passkey_authentication(
        &self,
        access_token: &str,
        challenge_id: &str,
        credential: &serde_json::Value,
    ) -> Result<StepUpResponse, ClientError> {
        let challenge_id = required_field(challenge_id, "challenge ID")?;
        self.authed_json(
            Method::POST,
            &["auth", "passkeys", "authentication", "verify"],
            access_token,
            Some(&PasskeyAuthenticationFinish {
                challenge_id,
                credential,
            }),
        )
        .await
    }

    pub async fn oauth_discovery(&self) -> Result<serde_json::Value, ClientError> {
        let request = self.request(Method::GET, &[".well-known", "openid-configuration"])?;
        self.send_json(request).await
    }

    pub async fn authorize_decision(
        &self,
        access_token: &str,
        resource: &str,
        action: &str,
    ) -> Result<serde_json::Value, ClientError> {
        let resource = required_identifier(resource, "resource")?;
        let action = required_identifier(action, "action")?;
        self.authed_json(
            Method::POST,
            &["authz", "decide"],
            access_token,
            Some(&serde_json::json!({ "resource": resource, "action": action })),
        )
        .await
    }

    pub async fn saml_metadata(&self) -> Result<String, ClientError> {
        let request = self.request(Method::GET, &["saml", "metadata"])?;
        let response = request.send().await?;
        match response.status().as_u16() {
            200..=299 => {}
            401 => return Err(ClientError::Unauthorized),
            code => return Err(ClientError::Status(code)),
        }
        let bytes = response.bytes().await?;
        String::from_utf8(bytes.to_vec()).map_err(|_| ClientError::InvalidInput("SAML metadata"))
    }

    pub async fn saml_sso(&self, idp_entity_id: &str) -> Result<reqwest::Response, ClientError> {
        let idp_entity_id = required_identifier(idp_entity_id, "idp_entity_id")?;
        let mut url = self.endpoint(&["saml", "sso"])?;
        url.query_pairs_mut()
            .append_pair("idp_entity_id", idp_entity_id);
        Ok(self.http.get(url).send().await?)
    }

    pub async fn saml_acs(
        &self,
        saml_response: &str,
        relay_state: Option<&str>,
    ) -> Result<serde_json::Value, ClientError> {
        let mut form = vec![("SAMLResponse", saml_response.to_owned())];
        if let Some(relay) = relay_state {
            form.push(("RelayState", relay.to_owned()));
        }
        let request = self
            .http
            .request(Method::POST, self.endpoint(&["saml", "acs"])?)
            .form(&form);
        self.send_json(request).await
    }

    pub async fn scim_service_provider_config(&self) -> Result<serde_json::Value, ClientError> {
        let request = self.request(Method::GET, &["scim", "v2", "ServiceProviderConfig"])?;
        self.send_json(request).await
    }

    pub async fn scim_list_users(
        &self,
        access_token: &str,
    ) -> Result<serde_json::Value, ClientError> {
        self.authed_json(
            Method::GET,
            &["scim", "v2", "Users"],
            access_token,
            None::<&()>,
        )
        .await
    }

    pub async fn scim_create_user(
        &self,
        access_token: &str,
        user: &serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        self.authed_json(
            Method::POST,
            &["scim", "v2", "Users"],
            access_token,
            Some(user),
        )
        .await
    }

    pub async fn scim_get_user(
        &self,
        access_token: &str,
        id: &str,
    ) -> Result<serde_json::Value, ClientError> {
        let id = required_field(id, "id")?;
        self.authed_json(
            Method::GET,
            &["scim", "v2", "Users", id],
            access_token,
            None::<&()>,
        )
        .await
    }

    pub async fn scim_replace_user(
        &self,
        access_token: &str,
        id: &str,
        user: &serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        let id = required_field(id, "id")?;
        self.authed_json(
            Method::PUT,
            &["scim", "v2", "Users", id],
            access_token,
            Some(user),
        )
        .await
    }

    pub async fn scim_patch_user(
        &self,
        access_token: &str,
        id: &str,
        patch: &serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        let id = required_field(id, "id")?;
        self.authed_json(
            Method::PATCH,
            &["scim", "v2", "Users", id],
            access_token,
            Some(patch),
        )
        .await
    }

    pub async fn scim_delete_user(&self, access_token: &str, id: &str) -> Result<(), ClientError> {
        let id = required_field(id, "id")?;
        let request = self.request(Method::DELETE, &["scim", "v2", "Users", id])?;
        let request = with_bearer(request, access_token, "access token")?;
        decode_empty(request.send().await?)
    }

    pub async fn scim_list_groups(
        &self,
        access_token: &str,
    ) -> Result<serde_json::Value, ClientError> {
        self.authed_json(
            Method::GET,
            &["scim", "v2", "Groups"],
            access_token,
            None::<&()>,
        )
        .await
    }

    pub async fn scim_create_group(
        &self,
        access_token: &str,
        group: &serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        self.authed_json(
            Method::POST,
            &["scim", "v2", "Groups"],
            access_token,
            Some(group),
        )
        .await
    }

    pub async fn scim_get_group(
        &self,
        access_token: &str,
        id: &str,
    ) -> Result<serde_json::Value, ClientError> {
        let id = required_field(id, "id")?;
        self.authed_json(
            Method::GET,
            &["scim", "v2", "Groups", id],
            access_token,
            None::<&()>,
        )
        .await
    }

    pub async fn scim_replace_group(
        &self,
        access_token: &str,
        id: &str,
        group: &serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        let id = required_field(id, "id")?;
        self.authed_json(
            Method::PUT,
            &["scim", "v2", "Groups", id],
            access_token,
            Some(group),
        )
        .await
    }

    pub async fn scim_patch_group(
        &self,
        access_token: &str,
        id: &str,
        patch: &serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        let id = required_field(id, "id")?;
        self.authed_json(
            Method::PATCH,
            &["scim", "v2", "Groups", id],
            access_token,
            Some(patch),
        )
        .await
    }

    pub async fn scim_delete_group(&self, access_token: &str, id: &str) -> Result<(), ClientError> {
        let id = required_field(id, "id")?;
        let request = self.request(Method::DELETE, &["scim", "v2", "Groups", id])?;
        let request = with_bearer(request, access_token, "access token")?;
        decode_empty(request.send().await?)
    }

    async fn authed_json<T, B>(
        &self,
        method: Method,
        segments: &[&str],
        access_token: &str,
        body: Option<&B>,
    ) -> Result<T, ClientError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let request = self.request(method, segments)?;
        let request = with_bearer(request, access_token, "access token")?;
        let request = match body {
            Some(body) => self.with_json(request, body)?,
            None => request,
        };
        self.send_json(request).await
    }

    fn request(&self, method: Method, segments: &[&str]) -> Result<RequestBuilder, ClientError> {
        Ok(self
            .http
            .request(method, self.endpoint(segments)?)
            .header(ACCEPT, "application/json"))
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, ClientError> {
        let mut url = match &self.base {
            BaseUrl::Valid(url) => url.clone(),
            BaseUrl::Invalid => return Err(ClientError::InvalidBaseUrl),
            // Refuse before the socket opens: every credential this client
            // carries would otherwise cross a public hop in the clear.
            BaseUrl::Insecure(host) => return Err(ClientError::InsecureTransport(host.clone())),
        };
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| ClientError::InvalidBaseUrl)?;
            path.pop_if_empty();
            for segment in segments {
                validate_path_segment(segment)?;
                path.push(segment);
            }
        }
        Ok(url)
    }

    fn with_json<B: Serialize + ?Sized>(
        &self,
        request: RequestBuilder,
        body: &B,
    ) -> Result<RequestBuilder, ClientError> {
        let encoded = serde_json::to_vec(body).map_err(|source| ClientError::Encode { source })?;
        if encoded.len() > self.max_request_bytes {
            return Err(ClientError::RequestTooLarge {
                limit: self.max_request_bytes,
            });
        }
        Ok(request
            .header(CONTENT_TYPE, "application/json")
            .body(encoded))
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
    ) -> Result<T, ClientError> {
        decode_json(request.send().await?, self.max_response_bytes).await
    }
}

fn normalize_base(base: &str) -> Result<Url, ()> {
    let mut url = Url::parse(base.trim()).map_err(|_| ())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.cannot_be_a_base()
    {
        return Err(());
    }
    let normalized_path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if normalized_path.is_empty() {
        "/"
    } else {
        &normalized_path
    });
    Ok(url)
}

/// The host of `base` when its scheme is cleartext `http://`, else `None`.
/// Mirrors the check in `3fa-clients`, the reference implementation.
fn cleartext_http_host(base: &str) -> Option<&str> {
    base.get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))?;
    let authority = base[7..].split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    Some(match host_port.strip_prefix('[') {
        // IPv6 literal: everything up to the closing bracket.
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => host_port.split(':').next().unwrap_or_default(),
    })
}

/// Loopback, private/link-local IPs, and in-cluster names, where TLS may
/// terminate at a sidecar and cleartext never leaves the trust boundary.
fn cleartext_internal_host_allowed(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if host.is_empty() || host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    if host == "::1" || host.starts_with("fc") || host.starts_with("fd") || host.starts_with("fe8")
    {
        return true;
    }
    match host
        .split('.')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()
        .as_deref()
    {
        Ok(
            [127, _, _, _]
            | [10, _, _, _]
            | [172, 16..=31, _, _]
            | [192, 168, _, _]
            | [169, 254, _, _],
        ) => true,
        Ok([_, _, _, _]) => false,
        _ => {
            // Single-label ("dd-shared-auth") and cluster DNS names never resolve publicly.
            !host.contains('.')
                || host.ends_with(".svc.cluster.local")
                || host.ends_with(".internal")
        }
    }
}

/// Whether `base` may carry credentials as configured.
fn transport_is_acceptable(base: &str) -> bool {
    cleartext_http_host(base).is_none_or(cleartext_internal_host_allowed)
}

fn with_bearer(
    request: RequestBuilder,
    credential: &str,
    field: &'static str,
) -> Result<RequestBuilder, ClientError> {
    Ok(request.bearer_auth(required_credential(credential, field)?))
}

fn required_credential<'a>(value: &'a str, field: &'static str) -> Result<&'a str, ClientError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
        || value.len() > MAX_CREDENTIAL_BYTES
    {
        return Err(ClientError::InvalidInput(field));
    }
    Ok(value)
}

fn required_field<'a>(value: &'a str, field: &'static str) -> Result<&'a str, ClientError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.len() > MAX_CREDENTIAL_BYTES
        || matches!(value, "." | "..")
    {
        return Err(ClientError::InvalidInput(field));
    }
    Ok(value)
}

fn required_identifier<'a>(value: &'a str, field: &'static str) -> Result<&'a str, ClientError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
    {
        return Err(ClientError::InvalidInput(field));
    }
    Ok(value)
}

fn validate_required_scopes(scopes: &[&str]) -> Result<(), ClientError> {
    if scopes.len() > MAX_REQUIRED_SCOPES {
        return Err(ClientError::InvalidInput("required scopes"));
    }
    scopes.iter().enumerate().try_for_each(|(index, scope)| {
        required_identifier(scope, "required scope")?;
        if scopes[..index].contains(scope) {
            Err(ClientError::InvalidInput("required scopes"))
        } else {
            Ok(())
        }
    })
}

fn validate_path_segment(segment: &str) -> Result<(), ClientError> {
    if segment.is_empty() || segment.chars().any(char::is_control) || matches!(segment, "." | "..")
    {
        return Err(ClientError::InvalidInput("path segment"));
    }
    Ok(())
}

async fn decode_json<T: DeserializeOwned>(
    mut response: Response,
    max_response_bytes: usize,
) -> Result<T, ClientError> {
    match response.status().as_u16() {
        200..=299 => {}
        401 => return Err(ClientError::Unauthorized),
        code => return Err(ClientError::Status(code)),
    }

    let max_response_bytes_u64 = u64::try_from(max_response_bytes).unwrap_or(u64::MAX);
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes_u64)
    {
        return Err(ClientError::ResponseTooLarge {
            limit: max_response_bytes,
        });
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let next_len =
            body.len()
                .checked_add(chunk.len())
                .ok_or(ClientError::ResponseTooLarge {
                    limit: max_response_bytes,
                })?;
        if next_len > max_response_bytes {
            return Err(ClientError::ResponseTooLarge {
                limit: max_response_bytes,
            });
        }
        body.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&body).map_err(|source| ClientError::Decode { source })
}

fn decode_empty(response: Response) -> Result<(), ClientError> {
    match response.status().as_u16() {
        200..=299 => Ok(()),
        401 => Err(ClientError::Unauthorized),
        code => Err(ClientError::Status(code)),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use super::*;

    #[test]
    fn base_url_is_normalized_and_dynamic_segments_are_encoded() {
        let client = SharedAuthClient::new(" https://gw.example/shared-auth/// ");
        let endpoint = client
            .endpoint(&["auth", "factors", "factor/one%two"])
            .unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://gw.example/shared-auth/auth/factors/factor%2Fone%25two"
        );
    }

    #[test]
    fn invalid_and_remote_plaintext_base_urls_fail_before_transport() {
        for base in [
            "relative/path",
            "ftp://gw.example/shared-auth",
            "https://user:secret@gw.example/shared-auth",
            "https://gw.example/shared-auth?tenant=one",
        ] {
            assert!(
                matches!(
                    SharedAuthClient::try_new(base),
                    Err(ClientError::InvalidBaseUrl)
                ),
                "{base}"
            );
        }

        assert!(matches!(
            SharedAuthClient::try_new("http://gw.example/shared-auth"),
            Err(ClientError::InsecureTransport(_))
        ));
    }

    #[test]
    fn assurance_checks_fail_closed() {
        let inactive = Introspection {
            active: false,
            sub: None,
            iss: None,
            aud: None,
            iat: None,
            nbf: None,
            exp: None,
            jti: None,
            sid: None,
            auth_time: None,
            project: None,
            provider: None,
            provider_tenant: None,
            provider_subject: None,
            email: None,
            email_verified: None,
            roles: vec!["admin".into()],
            aal: None,
            amr: vec!["passkey".into()],
            acr: Some("urn:oresoftware:loa:2".into()),
            scope: Some("cliptown:memebank:write".into()),
            azp: Some("memebank-api".into()),
            parent_jti: Some("parent".into()),
            rest: Default::default(),
        };
        assert!(!inactive.has_acr("urn:oresoftware:loa:2"));
        assert!(!inactive.used_method("passkey"));
        assert!(!inactive.has_role("admin"));
        assert!(!inactive.has_scope("cliptown:memebank:write"));
        assert!(!inactive.has_delegation_lineage());
    }

    #[tokio::test]
    async fn malformed_credentials_fail_before_transport() {
        let client = SharedAuthClient::new("http://127.0.0.1:1");
        let error = client.exchange(" token ").await.unwrap_err();
        assert!(matches!(error, ClientError::InvalidInput("Supabase token")));

        let error = client
            .clone()
            .with_service_credential("secret\nheader")
            .introspect("token")
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ClientError::InvalidInput("service credential")
        ));

        let error = client
            .with_service_credential("service-secret")
            .introspect_for_audience("token", " audience ")
            .await
            .unwrap_err();
        assert!(matches!(error, ClientError::InvalidInput("audience")));
    }

    #[tokio::test]
    async fn with_service_credential_does_not_mutate_the_original() {
        let original = SharedAuthClient::new("http://127.0.0.1:1");
        let _configured = original.clone().with_service_credential("service-secret");
        let error = original.introspect("token").await.unwrap_err();
        assert!(matches!(error, ClientError::MissingServiceCredential));
    }

    #[tokio::test]
    async fn request_bodies_are_bounded_before_transport() {
        let client = SharedAuthClient::new("http://127.0.0.1:1").with_max_request_bytes(32);
        let credential = serde_json::json!({ "padding": "x".repeat(128) });
        let error = client
            .finish_passkey_authentication("token", "challenge", &credential)
            .await
            .unwrap_err();
        assert!(matches!(error, ClientError::RequestTooLarge { limit: 32 }));
    }

    #[tokio::test]
    async fn response_bodies_are_bounded_before_decode() {
        let body =
            br#"{"padding":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#;
        let base = spawn_single_response(body);
        let client = SharedAuthClient::new(base).with_max_response_bytes(16);
        let error = client.jwks().await.unwrap_err();
        assert!(matches!(error, ClientError::ResponseTooLarge { limit: 16 }));
    }

    #[tokio::test]
    async fn transport_display_is_redacted() {
        let client = SharedAuthClient::new("http://127.0.0.1:1");
        let error = client.exchange("token").await.unwrap_err();
        assert!(matches!(error, ClientError::Transport(_)));
        assert_eq!(error.to_string(), "transport failed");
    }

    fn spawn_single_response(body: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        format!("http://{address}")
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;

    #[test]
    fn refuses_cleartext_to_public_hosts() {
        for base in [
            "http://auth.example.com",
            "HTTP://Auth.Example.COM/shared-auth",
            "http://user@evil.test",
            "http://8.8.8.8:8120",
        ] {
            assert!(
                matches!(
                    SharedAuthClient::try_new(base),
                    Err(ClientError::InsecureTransport(_))
                ),
                "should refuse {base}"
            );
        }
    }

    #[test]
    fn allows_cleartext_only_inside_the_trust_boundary() {
        for base in [
            "http://localhost:8120",
            "http://127.0.0.1:8120",
            "http://[::1]:8120",
            "http://10.1.2.3:8120",
            "http://172.16.0.9",
            "http://192.168.1.5",
            "http://dd-shared-auth",
            "http://dd-shared-auth.shared-auth.svc.cluster.local:8120",
        ] {
            assert!(
                SharedAuthClient::try_new(base).is_ok(),
                "should allow {base}"
            );
        }
    }

    #[test]
    fn https_is_always_accepted() {
        assert!(SharedAuthClient::try_new("https://auth.example.com").is_ok());
        assert!(SharedAuthClient::try_new("https://gateway/shared-auth").is_ok());
    }

    #[test]
    fn credentials_in_the_authority_do_not_disguise_the_host() {
        let Err(ClientError::InsecureTransport(host)) =
            SharedAuthClient::try_new("http://localhost@evil.test/x")
        else {
            panic!("expected the real host to be rejected");
        };
        assert_eq!(host, "evil.test");
    }
}
