#![recursion_limit = "256"]

//! Centralized OreSoftware auth server.
//!
//! Verifies Supabase access tokens issued by the configured realm project,
//! mirrors the verified identity into the realm's `shared_auth` Postgres schema
//! on AWS RDS, and mints OreSoftware JWTs for downstream services.
//!
//! The same binary is deployed independently as the privileged admin realm and
//! customer realm. Runtime startup validates that issuer, database endpoint and
//! references, secret paths, signing-key reference, cookie namespace, and
//! Supabase project all belong to the selected realm.
//!
//! It runs *alongside* Supabase's built-in auth — Supabase stays an upstream
//! credential authority; this server is the verifier + session/token authority,
//! never a mirror of Supabase's password store. The account-level Supabase
//! credential is used only by the offline `discover` subcommand, never on the
//! request path.
//!
//! ## Module map
//! - [`config`] — environment-driven configuration
//! - [`realm`] — fail-closed admin/customer runtime boundary
//! - [`supabase`] — per-project JWKS verification, issuer routing, Management API
//! - [`db`] — the realm RDS identity store (`shared_auth.principals`)
//! - [`token`] — minting unified and delegated OreSoftware JWTs + JWKS
//! - [`oidc`] — OpenID Connect discovery, ID-token and userinfo contract
//! - [`pubkey`] — SSH public-key auth for non-interactive clients, on a
//!   sandboxed token plane that cannot reach the control plane
//! - [`openpgp`] — provenance-only detached-signature verification
//! - [`handoff`] — PKCE-bound browser authorization-code broker
//! - [`workload`] — first-class non-human service-account identity invariants
//! - [`workload_token`] — unsigned first-class workload JWT claim profile
//! - [`http`] — the axum surface
//! - [`locks`] — Fiducia lease wrapping a Postgres xact advisory lock
//! - [`state`] — shared application state
//! - [`ores_logging`] — canonical ores.otel.log adapter and security-event policy
//! - [`error`], [`telemetry`], [`env_map`]

pub mod admin_contracts;
pub mod authz;
pub mod cache;
pub mod config;
pub mod coordination;
pub mod db;
pub mod directory_grants;
pub mod email;
pub mod env_map;
pub mod error;
pub mod factors;
pub mod flags;
pub mod handoff;
pub mod http;
pub mod idv;
pub mod locks;
pub mod metrics;
pub mod oauth_as;
pub mod oauth_provider;
pub mod oidc;
pub mod openpgp;
pub mod openpgp_http;
pub mod ores_logging;
pub mod password;
mod provider_guard;
pub mod pubkey;
pub mod qr;
pub mod realm;
pub mod recovery;
pub mod revocation;
pub mod risk;
pub mod saml;
pub mod scim;
pub mod session;
pub mod shutdown;
pub mod state;
pub mod supabase;
pub mod telemetry;
pub mod token;
pub mod twilio;
pub mod upstream_federation;
pub mod upstream_oauth_authorize;
pub mod upstream_oauth_transaction;
pub mod views;
pub mod workload;
pub mod workload_token;

use anyhow::Context;
use next_loggers::Value;
use ores_logging::{SecurityEvent, SecurityOutcome};

/// OTel service.name / metrics namespace for this process.
pub const SERVICE_NAME: &str = "dd-shared-auth";

/// Process entrypoint: apply CLI flags, initialise telemetry, dispatch subcommand.
///
/// - `serve` (default) — run the HTTP auth server.
/// - `discover` — enumerate the account's Supabase orgs/projects via the
///   Management API and print a ready-to-paste `AUTH_SUPABASE_PROJECTS` value.
/// - `materialize-admin-email-search-index` — explicit, realm-validated
///   bootstrap/key-rotation of the keyed admin lookup index.
pub async fn run() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let env = flags::apply_cli_flags();
    let _otel = telemetry::init(SERVICE_NAME, &env);
    let _logger = ores_logging::init();

    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "serve".to_string());
    let _ = SecurityEvent::new("process.mode_selected", SecurityOutcome::Success)
        .reason_code("MODE_SELECTED")
        .field("process.mode", Value::String(mode.clone()))
        .emit();

    let result = match mode.as_str() {
        "serve" => serve(&env).await,
        "discover" => supabase::management::discover().await,
        "materialize-admin-email-search-index" => materialize_admin_email_search_index(&env).await,
        other => anyhow::bail!(
            "unknown subcommand {other:?} (expected: serve | discover | \
             materialize-admin-email-search-index)"
        ),
    };

    match &result {
        Ok(()) => {
            let _ = SecurityEvent::new("process.completed", SecurityOutcome::Success)
                .reason_code("PROCESS_COMPLETED")
                .field("process.mode", Value::String(mode))
                .emit();
        }
        Err(error) => ores_logging::fatal_unhandled(error),
    }
    ores_logging::flush();
    result
}

async fn materialize_admin_email_search_index(env: &crate::env_map::EnvMap) -> anyhow::Result<()> {
    let config = config::AppConfig::from_env_map(env).context("loading configuration")?;
    let _realm = realm::RealmConfig::from_env_map(&config, env)
        .context("validating authentication realm boundary")?;
    let db_config = config
        .db
        .as_ref()
        .context("AUTH_DATABASE_URL is required to materialize the admin email search index")?;
    let db = db::DbStore::connect(db_config)
        .await
        .context("connecting to realm RDS")?;
    let updated = db
        .materialize_admin_email_search_index()
        .await
        .context("materializing keyed admin email search index")?;
    db.assert_admin_email_search_index_ready()
        .await
        .context("validating keyed admin email search index")?;
    tracing::info!(rows_updated = updated, "admin email search index materialized");
    Ok(())
}

async fn serve(env: &crate::env_map::EnvMap) -> anyhow::Result<()> {
    provider_guard::validate_environment_map(env)
        .context("validating provider credential bundles")?;
    let config = config::AppConfig::from_env_map(env).context("loading configuration")?;
    http::validate_test_auth_startup(&config)
        .context("validating deterministic test auth boundary")?;
    let realm = realm::RealmConfig::from_env_map(&config, env)
        .context("validating authentication realm boundary")?;
    let bind_addr = config.bind_addr;
    let state = state::AppState::build(config)
        .await
        .context("building application state")?;

    let router = http::router(state.clone())
        .merge(openpgp_http::router(state.clone()))
        .merge(oauth_provider::router(state.clone()))
        .merge(oidc::router(state.clone()));
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("binding {bind_addr}"))?;
    let listener = listener
        .into_std()
        .context("converting HTTP listener for lifecycle control")?;

    tracing::info!(
        %bind_addr,
        realm = %realm.realm,
        deployment = %realm.deployment,
        realm_dbless = realm.development_dbless,
        realm_loopback = realm.development_loopback,
        projects = state.supabase.len(),
        db = state.db.is_some(),
        browser_handoff = state.handoff.is_some(),
        openpgp_provenance = state.openpgp.is_some(),
        "shared-auth-server listening"
    );
    let _ = SecurityEvent::new("server.listening", SecurityOutcome::Success)
        .reason_code("SERVER_LISTENING")
        .field("network.bind_addr", Value::String(bind_addr.to_string()))
        .field("realm.name", Value::String(realm.realm.to_string()))
        .field("deployment.name", Value::String(realm.deployment.to_string()))
        .field("realm.development_dbless", Value::Bool(realm.development_dbless))
        .field("realm.development_loopback", Value::Bool(realm.development_loopback))
        .field("supabase.project_count", Value::from(state.supabase.len() as u64))
        .field("database.configured", Value::Bool(state.db.is_some()))
        .emit();

    let outcome = shutdown::serve(
        listener,
        router,
        state,
        shutdown::ShutdownConfig::from_env_map(env),
    )
    .await?;
    if outcome == shutdown::ShutdownOutcome::Forced {
        tracing::warn!("shared-auth-server required forced shutdown");
    }
    tracing::info!("shutdown signal received");
    let _ = SecurityEvent::new("process.shutdown_signal", SecurityOutcome::Success)
        .reason_code("SHUTDOWN_SIGNAL_RECEIVED")
        .emit();
    Ok(())
}
