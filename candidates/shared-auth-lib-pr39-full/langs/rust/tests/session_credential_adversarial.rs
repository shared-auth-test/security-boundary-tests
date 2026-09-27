use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde_json::json;
use shared_auth_lib::{
    AccessPolicy, AuthGuardConfig, AuthOutcome, Authority, AuthorityConfig, GuardConfig,
    SessionAwareAuthGuard, ORE_SESSION_COOKIE, SUPABASE_TOKEN_COOKIE, SUPABASE_TOKEN_HEADER,
};

#[derive(Clone)]
struct AuthorityState {
    requests: Arc<AtomicUsize>,
    expected_token: Option<&'static str>,
}

async fn authority(State(state): State<AuthorityState>, request: Request) -> Response {
    state.requests.fetch_add(1, Ordering::SeqCst);
    let path = request.uri().path().to_string();
    if let Some(token) = state.expected_token {
        let expected = format!("Bearer {token}");
        assert_eq!(
            request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some(expected.as_str())
        );
    }

    match path.as_str() {
        "/shared/auth/exchange" => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        "/supabase/auth/v1/user" => (
            StatusCode::OK,
            Json(json!({
                "id": "11111111-1111-4111-8111-111111111111",
                "email": "customer@example.invalid",
                "email_confirmed_at": "2026-08-02T12:00:00Z"
            })),
        )
            .into_response(),
        _ => panic!("unexpected authority path {path}"),
    }
}

async fn start_authority(expected_token: Option<&'static str>) -> (String, Arc<AtomicUsize>) {
    let requests = Arc::new(AtomicUsize::new(0));
    let router = Router::new()
        .fallback(authority)
        .with_state(AuthorityState {
            requests: Arc::clone(&requests),
            expected_token,
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind authority fixture");
    let address = listener.local_addr().expect("read authority address");
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("serve authority fixture");
    });
    (format!("http://{address}"), requests)
}

fn config(base: &str) -> AuthGuardConfig {
    AuthGuardConfig {
        guard: GuardConfig {
            authority: AuthorityConfig {
                shared_auth_base: format!("{base}/shared"),
                issuer: "https://auth.example.invalid".to_string(),
                audience: "fiducia".to_string(),
                supabase_url: Some(format!("{base}/supabase")),
                supabase_api_key: Some("publishable-key".to_string()),
                introspect_secret: Some("introspect-secret".to_string()),
                arm_timeout: Duration::from_millis(300),
                ..Default::default()
            },
            supabase_project: Some("fiducia-customer".to_string()),
            race_deadline: Duration::from_secs(1),
            ..Default::default()
        },
        policy: AccessPolicy {
            allowed_emails: vec!["customer@example.invalid".to_string()],
            allowed_roles: vec!["customer".to_string()],
        },
    }
}

fn guard(base: &str) -> SessionAwareAuthGuard {
    SessionAwareAuthGuard::from_config(&config(base)).expect("valid session-aware guard")
}

fn cookie_header(name: &str, value: &str) -> String {
    format!("{name}={value}")
}

fn provider_header_name() -> HeaderName {
    HeaderName::from_bytes(SUPABASE_TOKEN_HEADER.as_bytes()).expect("valid provider header name")
}

#[tokio::test]
async fn duplicate_authorization_headers_are_rejected_without_network() {
    let (base, requests) = start_authority(None).await;
    let guard = guard(&base);
    let mut headers = HeaderMap::new();
    headers.append(header::AUTHORIZATION, "Bearer first".parse().unwrap());
    headers.append(header::AUTHORIZATION, "Bearer second".parse().unwrap());

    let decision = guard.authorize_with_upgrade(&headers).await;
    assert_eq!(decision.outcome, AuthOutcome::Unauthenticated);
    assert!(decision.session_upgrade.is_none());
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn malformed_authorization_never_downgrades_to_ambient_cookie() {
    let (base, requests) = start_authority(None).await;
    let guard = guard(&base);
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, "Basic not-a-bearer".parse().unwrap());
    headers.insert(
        header::COOKIE,
        cookie_header(ORE_SESSION_COOKIE, "ambient-shared-token")
            .parse()
            .unwrap(),
    );

    let decision = guard.authorize_with_upgrade(&headers).await;
    assert_eq!(decision.outcome, AuthOutcome::Unauthenticated);
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn duplicate_shared_cookies_are_rejected_without_network() {
    let (base, requests) = start_authority(None).await;
    let guard = guard(&base);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}=first; other=value; {}=second",
            ORE_SESSION_COOKIE, ORE_SESSION_COOKIE
        )
        .parse()
        .unwrap(),
    );

    let decision = guard.authorize_with_upgrade(&headers).await;
    assert_eq!(decision.outcome, AuthOutcome::Unauthenticated);
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn duplicate_provider_headers_never_fall_back_to_provider_cookie() {
    let (base, requests) = start_authority(None).await;
    let guard = guard(&base);
    let mut headers = HeaderMap::new();
    let name = provider_header_name();
    headers.append(name.clone(), "first-provider-token".parse().unwrap());
    headers.append(name, "second-provider-token".parse().unwrap());
    headers.insert(
        header::COOKIE,
        cookie_header(SUPABASE_TOKEN_COOKIE, "ambient-provider-token")
            .parse()
            .unwrap(),
    );

    let decision = guard.authorize_with_upgrade(&headers).await;
    assert_eq!(decision.outcome, AuthOutcome::Unauthenticated);
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn oversized_explicit_bearer_is_rejected_without_network_or_cookie_fallback() {
    let (base, requests) = start_authority(None).await;
    let guard = guard(&base);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", "x".repeat(17 * 1024)).parse().unwrap(),
    );
    headers.insert(
        header::COOKIE,
        cookie_header(ORE_SESSION_COOKIE, "ambient-shared-token")
            .parse()
            .unwrap(),
    );

    let decision = guard.authorize_with_upgrade(&headers).await;
    assert_eq!(decision.outcome, AuthOutcome::Unauthenticated);
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn explicit_provider_bearer_precedes_ambient_shared_cookie() {
    const TOKEN: &str = "explicit-provider-token";
    let (base, requests) = start_authority(Some(TOKEN)).await;
    let guard = guard(&base);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {TOKEN}").parse().unwrap(),
    );
    headers.insert(
        header::COOKIE,
        cookie_header(ORE_SESSION_COOKIE, "ambient-shared-token")
            .parse()
            .unwrap(),
    );

    let decision = guard.authorize_with_upgrade(&headers).await;
    assert!(matches!(
        decision.outcome,
        AuthOutcome::Authenticated {
            authority: Authority::Supabase,
            ..
        }
    ));
    assert!(decision.session_upgrade.is_none());
    assert!((1..=2).contains(&requests.load(Ordering::SeqCst)));
}

#[tokio::test]
async fn explicit_provider_header_precedes_ambient_provider_cookie() {
    const TOKEN: &str = "explicit-provider-header";
    let (base, requests) = start_authority(Some(TOKEN)).await;
    let guard = guard(&base);
    let mut headers = HeaderMap::new();
    headers.insert(provider_header_name(), TOKEN.parse().unwrap());
    headers.insert(
        header::COOKIE,
        cookie_header(SUPABASE_TOKEN_COOKIE, "ambient-provider-cookie")
            .parse()
            .unwrap(),
    );

    let decision = guard.authorize_with_upgrade(&headers).await;
    assert!(matches!(
        decision.outcome,
        AuthOutcome::Authenticated {
            authority: Authority::Supabase,
            ..
        }
    ));
    assert!(decision.session_upgrade.is_none());
    assert!((1..=2).contains(&requests.load(Ordering::SeqCst)));
}
