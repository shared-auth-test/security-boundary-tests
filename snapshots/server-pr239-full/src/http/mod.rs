//! The axum surface.
//!
//! JSON API + a small script-free Maud HTML UI. No websockets.
//! - `GET  /`                           status landing (HTML)
//! - `GET  /ui`                         token-exchange helper (HTML)
//! - `POST /ui/exchange`                exchange result (HTML)
//! - `GET  /auth/browser/sign-in`       first-party email-OTP sign-in UI
//! - `POST /auth/browser/sign-in`       send email OTP
//! - `GET  /auth/browser/consume`       consume a legacy magic link
//! - `POST /auth/browser/otp`           consume email OTP and set browser session
//! - `GET  /auth/browser/session`       resolve the first-party session cookie
//! - `GET  /authorize`                  product-client sign-in with PKCE
//! - `POST /authorize`                  issue a PKCE-bound one-time code
//! - `POST /auth/handoff/redeem`        backend-only code redemption
//! - `POST /hooks/supabase/send-email`  signed Supabase hook → SendGrid OTP
//! - `POST /auth/test/supabase/session` isolated test-only Supabase session
//! - `GET  /healthz`                    liveness
//! - `GET  /readyz`                     readiness (DB ping if configured)
//! - `GET  /.well-known/jwks.json`      our public JWKS (downstream verifiers)
//! - `POST /auth/exchange`              provider access token → OreSoftware JWT
//! - `POST /auth/delegate`              OreSoftware JWT → narrow product JWT
//! - `GET  /auth/ssh/keys`              list registered SSH public keys
//! - `POST /auth/ssh/keys`              register one (interactive LOA2 only)
//! - `DELETE /auth/ssh/keys/{id}`       remove one and revoke its live tokens
//! - `POST /auth/ssh/challenge`         open a key handshake
//! - `POST /auth/ssh/verify`            SSHSIG signature → sandboxed token
//! - `POST /auth/introspect`            validate an OreSoftware JWT → claims
//! - `GET  /auth/verify`                bearer check (gateway auth_request)
//! - `GET  /metrics`                    Prometheus

pub(crate) mod admin_revocation;
mod browser;
mod delegate;
mod docs;
mod exchange;
mod handoff;
mod health;
pub(crate) mod introspect;
mod jwks;
mod local;
mod metrics;
mod mfa;
mod passwordless;
mod recovery;
pub(crate) mod session_tokens;
mod sshkeys;
mod supabase_hooks;
#[cfg(feature = "test-auth-bypass")]
mod test_auth;
mod ui;
pub mod webhook;

pub(crate) use local::enforce_limit;
#[cfg(feature = "test-auth-bypass")]
pub(crate) use test_auth::validate_startup as validate_test_auth_startup;

#[cfg(not(feature = "test-auth-bypass"))]
pub(crate) fn validate_test_auth_startup(
    _config: &crate::config::AppConfig,
) -> Result<(), crate::error::AuthError> {
    if std::env::var("AUTH_TEST_AUTH_ENABLED")
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
    {
        tracing::error!(
            "AUTH_TEST_AUTH_ENABLED was set on a binary compiled without test-auth-bypass"
        );
        return Err(crate::error::AuthError::Unavailable);
    }
    Ok(())
}

use std::time::Duration;

use axum::{
    http::{header, HeaderName, HeaderValue, Method},
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;

use crate::state::AppState;

// TimeoutLayer::new is deprecated in tower-http 0.6 in favour of
// with_status_code; new() still produces the same 408-on-timeout behaviour we
// want, so allow it rather than pin to the newer signature.
#[allow(deprecated)]
pub fn router(state: AppState) -> Router {
    let cors = build_cors(&state);

    let routes = Router::new()
        // HTML UI
        .route("/", get(ui::landing))
        .route("/ui", get(ui::sign_in))
        .route("/ui/exchange", post(ui::ui_exchange))
        .route("/docs/api", get(docs::api_docs))
        .route("/api/docs", get(docs::api_docs))
        .route("/api/docs.json", get(docs::openapi))
        // First-party browser ceremony. Product gateways expose this under a
        // path such as `/shared-auth/`, keeping all __Host- cookies scoped to
        // the product origin instead of sharing them across domains.
        .route(
            "/auth/browser/sign-in",
            get(browser::sign_in).post(browser::request_code),
        )
        .route("/auth/browser/consume", get(browser::consume_link))
        .route("/auth/browser/otp", post(browser::consume_otp))
        .route("/auth/browser/session", get(browser::session))
        // Registered product-client ceremony. Only an opaque, single-use,
        // state- and PKCE-bound code travels through the browser; token bundles
        // are encrypted at rest and redeemed by the product backend.
        .route(
            "/authorize",
            get(handoff::authorize).post(handoff::authorize_password),
        )
        // Signed provider hooks and isolated automation support.
        .route(
            "/hooks/supabase/send-email",
            post(supabase_hooks::send_email),
        )
        // JSON API
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .route("/.well-known/jwks.json", get(jwks::jwks))
        .route("/auth/exchange", post(exchange::exchange))
        .route("/auth/delegate", post(delegate::delegate))
        .route("/auth/handoff/redeem", post(handoff::redeem))
        .route("/auth/register", post(local::register))
        .route("/auth/login", post(local::login))
        .route("/auth/passwordless/request", post(passwordless::request))
        .route("/auth/passwordless/consume", post(passwordless::consume))
        .route("/auth/mfa/sms/request", post(mfa::request_sms))
        .route("/auth/mfa/sms/verify", post(mfa::verify_sms))
        .route("/auth/capabilities", get(crate::factors::capabilities))
        .route("/auth/factors", get(crate::factors::list))
        .route("/auth/factors/{factorId}", delete(crate::factors::delete))
        .route(
            "/auth/factors/totp/enroll",
            post(crate::factors::enroll_totp),
        )
        .route(
            "/auth/factors/totp/confirm",
            post(crate::factors::confirm_totp),
        )
        .route("/auth/challenges", post(crate::factors::create_challenge))
        .route(
            "/auth/challenges/{challengeId}/verify",
            post(crate::factors::verify_challenge),
        )
        .route(
            "/auth/passkeys/registration/options",
            post(crate::factors::start_passkey_registration),
        )
        .route(
            "/auth/passkeys/registration/verify",
            post(crate::factors::finish_passkey_registration),
        )
        .route(
            "/auth/passkeys/authentication/options",
            post(crate::factors::start_passkey_authentication),
        )
        .route(
            "/auth/passkeys/authentication/verify",
            post(crate::factors::finish_passkey_authentication),
        )
        // Non-interactive clients: SSH public keys on the sandboxed plane.
        // Registration and removal are control-plane operations behind an
        // interactive LOA2 session; challenge/verify are the key's own
        // handshake and carry no bearer token.
        // Kept on one line: `fix/restore-aal2-gating-and-build` adds a test that
        // cross-checks the OpenAPI document against this file by searching for
        // the literal `.route("<path>"`, so a path wrapped onto its own line
        // reads as a route the server does not serve.
        .route("/auth/ssh/keys", get(sshkeys::list).post(sshkeys::register))
        .route("/auth/ssh/keys/{publicKeyId}", delete(sshkeys::revoke))
        .route("/auth/ssh/challenge", post(sshkeys::challenge))
        .route("/auth/ssh/verify", post(sshkeys::verify))
        .route("/auth/risk/evaluate", post(crate::risk::evaluate))
        .route("/auth/qr/challenge", post(crate::qr::start_challenge))
        .route("/auth/qr/consume", post(crate::qr::consume))
        .route("/auth/qr/login/start", post(crate::qr::login_start))
        .route("/auth/qr/login/approve", post(crate::qr::login_approve))
        .route("/auth/qr/login/poll", post(crate::qr::login_poll))
        .route("/auth/idv/sessions", post(crate::idv::start_session))
        .route(
            "/auth/idv/sessions/{sessionId}",
            post(crate::idv::session_status),
        )
        .route(
            "/auth/idv/sessions/{sessionId}/complete",
            post(crate::idv::complete_session),
        )
        .route("/auth/recovery/capabilities", get(recovery::capabilities))
        .route(
            "/auth/recovery/enrollment",
            post(recovery::begin_enrollment).delete(recovery::revoke_enrollment),
        )
        .route(
            "/auth/recovery/enrollment/{ceremonyId}/complete",
            post(recovery::complete_enrollment),
        )
        .route("/auth/recovery/ceremonies", post(recovery::begin_recovery))
        .route(
            "/auth/recovery/ceremonies/{ceremonyId}/status",
            post(recovery::recovery_status),
        )
        .route(
            "/auth/recovery/ceremonies/{ceremonyId}/complete",
            post(recovery::complete_recovery),
        )
        .route(
            "/auth/recovery/ceremonies/{ceremonyId}/redeem",
            post(recovery::redeem_recovery),
        )
        .route(
            "/internal/recovery/ceremonies/{ceremonyId}/review",
            post(recovery::review_recovery),
        )
        .route("/auth/refresh", post(local::refresh))
        .route("/auth/logout", post(local::logout))
        .route("/auth/introspect", post(introspect::introspect))
        .route("/auth/verify", get(introspect::verify))
        .route("/internal/webhook/sync", post(webhook::sync_webhook))
        // SCIM 2.0 inbound provisioning. Tenant-scoped, server-to-server; the
        // per-tenant bearer is verified before any body is deserialized.
        .route("/scim/v2/ServiceProviderConfig", get(crate::scim::service_provider_config))
        .route("/scim/v2/ResourceTypes", get(crate::scim::resource_types))
        .route("/scim/v2/Schemas", get(crate::scim::schemas_endpoint))
        .route("/scim/v2/Users", get(crate::scim::list_users).post(crate::scim::create_user))
        .route("/scim/v2/Users/{scimUserId}", get(crate::scim::get_user).put(crate::scim::replace_user).patch(crate::scim::patch_user).delete(crate::scim::delete_user))
        .route("/scim/v2/Groups", get(crate::scim::list_groups).post(crate::scim::create_group))
        .route("/scim/v2/Groups/{scimGroupId}", get(crate::scim::get_group).put(crate::scim::replace_group).patch(crate::scim::patch_group).delete(crate::scim::delete_group))
        // SAML 2.0 service provider. Every response must match an outstanding
        // request record; IdP-initiated login is refused as a class.
        .route("/auth/saml/{registration}/metadata", get(crate::saml::api::metadata))
        .route("/auth/saml/{registration}/login", get(crate::saml::api::login))
        .route("/auth/saml/{registration}/acs", post(crate::saml::api::acs))
        .route("/metrics", get(metrics::metrics));
    #[cfg(feature = "test-auth-bypass")]
    let routes = routes
        .route("/auth/test/supabase/session", post(test_auth::session))
        .route("/auth/test/supabase/sms-hook", post(test_auth::capture_sms));
    // Do not register the privileged surface at all unless every startup gate
    // is already satisfied. Handler-level checks remain as defense in depth.
    let routes = if state.config.global_revocation.enabled
        && state.config.global_revocation.admin_realm
        && state.db.is_some()
    {
        routes
            .route(
                "/auth/admin/revocation-token-exchange",
                post(admin_revocation::exchange_revocation_token),
            )
            .route(
                "/admin/v1/session-revocations/search",
                post(admin_revocation::search),
            )
            .route(
                "/admin/v1/session-revocations/selections",
                post(admin_revocation::select),
            )
            .route(
                "/admin/v1/session-revocations/previews",
                post(admin_revocation::preview),
            )
            .route(
                "/admin/v1/session-revocations/previews/{previewId}",
                get(admin_revocation::get_preview),
            )
            .route(
                "/admin/v1/session-revocations/previews/{previewId}/commit-authorizations",
                post(admin_revocation::authorize_commit),
            )
            .route(
                "/admin/v1/session-revocations/operations",
                post(admin_revocation::commit),
            )
            .route(
                "/admin/v1/session-revocations/operations/{operationId}",
                get(admin_revocation::status),
            )
    } else {
        routes
    };

    routes
        // One tracing span per request (W3C traceparent → OTLP), then limits.
        .layer(crate::telemetry::http_trace_layer())
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        .layer(RequestBodyLimitLayer::new(64 * 1024))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            ),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
        // Token-bearing responses must not enter shared or browser caches.
        // if_not_present preserves the explicit public JWKS cache policy.
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        // The script-free UI needs no powerful browser capabilities.
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static(
                "accelerometer=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
            ),
        ))
        // Isolate authentication UI from cross-origin opener relationships.
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .layer(cors)
        .with_state(state)
}

fn build_cors(state: &AppState) -> CorsLayer {
    if state.config.cors_allow_origins.is_empty() {
        return CorsLayer::new();
    }
    let origins = state
        .config
        .cors_allow_origins
        .iter()
        .filter_map(|origin| origin.parse().ok())
        .collect::<Vec<_>>();
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("idempotency-key"),
            HeaderName::from_static("x-shared-auth-access"),
        ])
}

/// Extract a bearer token from the `Authorization` header.
pub(crate) fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
}
