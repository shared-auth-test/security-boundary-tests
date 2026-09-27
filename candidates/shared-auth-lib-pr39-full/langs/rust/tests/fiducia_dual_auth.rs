use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use base64::Engine;
use serde_json::json;
use shared_auth_lib::{
    AccessPolicy, AuthGuard, AuthGuardConfig, AuthOutcome, Authority, AuthorityConfig, Guard,
    GuardConfig, SUPABASE_TOKEN_HEADER,
};

#[derive(Clone, Copy)]
enum Scenario {
    SharedAuthWins,
    SharedAuthUnavailable,
}

#[derive(Clone)]
struct MockState {
    scenario: Scenario,
    paths: Arc<Mutex<Vec<String>>>,
}

async fn handler(State(state): State<MockState>, request: Request) -> Response {
    let path = request.uri().path().to_string();
    let headers = request.headers().clone();
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 64 * 1024).await.unwrap();
    state.paths.lock().unwrap().push(path.clone());

    match path.as_str() {
        "/shared/auth/exchange" => {
            assert_eq!(
                headers.get("authorization").unwrap().to_str().unwrap(),
                format!("Bearer {}", provider_token())
            );
            match state.scenario {
                Scenario::SharedAuthWins => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    (
                        StatusCode::OK,
                        Json(json!({
                            "access_token": "new-shared-auth-jwt",
                            "shared_user_id": "shared-customer-1",
                            "provider": "supabase",
                            "provider_tenant": "fiducia-customer",
                            "provider_subject": "sup-user-1",
                            "roles": ["customer"]
                        })),
                    )
                        .into_response()
                }
                Scenario::SharedAuthUnavailable => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            }
        }
        "/shared/auth/introspect" => {
            assert_eq!(
                headers.get("authorization").unwrap().to_str().unwrap(),
                "Bearer test-introspect-secret"
            );
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["contract"], "IntrospectionRequest");
            assert_eq!(
                body["payload"]["token"].as_str(),
                Some("new-shared-auth-jwt")
            );
            assert_eq!(body["payload"]["audience"], "oresoftware");
            assert_eq!(body["payload"]["requiredScopes"], json!([]));
            tokio::time::sleep(Duration::from_millis(5)).await;
            (
                StatusCode::OK,
                Json(json!({
                    "active": true,
                    "sub": "shared-customer-1",
                    "provider": "supabase",
                    "provider_tenant": "fiducia-customer",
                    "provider_subject": "sup-user-1",
                    "project": "fiducia-customer",
                    "supabase_user_id": "sup-user-1",
                    "sid": "00000000-0000-0000-0000-000000000001",
                    "email": "customer@example.invalid",
                    "email_verified": true,
                    "roles": ["customer"]
                })),
            )
                .into_response()
        }
        "/supabase/auth/v1/user" => {
            assert_eq!(
                headers.get("apikey").unwrap().to_str().unwrap(),
                "fiducia-customer-publishable-key"
            );
            match state.scenario {
                Scenario::SharedAuthWins => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Scenario::SharedAuthUnavailable => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
            (
                StatusCode::OK,
                Json(json!({
                    "id": "sup-user-1",
                    "email": "customer@example.invalid",
                    "email_confirmed_at": "2026-08-02T12:00:00Z"
                })),
            )
                .into_response()
        }
        _ => {
            panic!("unexpected request: {} {}", parts.method, path);
        }
    }
}

async fn server(scenario: Scenario) -> (String, Arc<Mutex<Vec<String>>>) {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        scenario,
        paths: paths.clone(),
    };
    let app = Router::new().fallback(handler).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), paths)
}

fn provider_token() -> String {
    let encode = |value: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
    };
    format!(
        "{}.{}.fixture-signature",
        encode(json!({"alg": "HS256", "typ": "JWT"})),
        encode(json!({"iss": "https://fiducia-customer.supabase.co/auth/v1"}))
    )
}

fn headers_with_only_provider_token() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(SUPABASE_TOKEN_HEADER, provider_token().parse().unwrap());
    headers
}

fn guard_config(base: &str) -> GuardConfig {
    GuardConfig {
        authority: AuthorityConfig {
            shared_auth_base: format!("{base}/shared"),
            issuer: "https://auth.oresoftware.dev".into(),
            audience: "oresoftware".into(),
            supabase_url: Some(format!("{base}/supabase")),
            supabase_api_key: Some("fiducia-customer-publishable-key".into()),
            introspect_secret: Some("test-introspect-secret".into()),
            arm_timeout: Duration::from_millis(500),
            ..Default::default()
        },
        supabase_project: Some("fiducia-customer".into()),
        race_deadline: Duration::from_secs(1),
        ..Default::default()
    }
}

#[tokio::test]
async fn fiducia_provider_token_races_to_a_new_shared_auth_jwt_when_none_was_present() {
    let (base, paths) = server(Scenario::SharedAuthWins).await;
    let auth = AuthGuard::from_config(&AuthGuardConfig {
        guard: guard_config(&base),
        policy: AccessPolicy {
            allowed_emails: vec![],
            allowed_roles: vec!["customer".into()],
        },
    })
    .unwrap();

    let outcome = auth.authorize(&headers_with_only_provider_token()).await;
    match outcome {
        AuthOutcome::Authenticated {
            authority,
            identity,
            ..
        } => {
            assert_eq!(authority, Authority::SharedAuth);
            assert_eq!(identity.provider_tenant, "fiducia-customer");
            assert_eq!(identity.roles, vec!["customer"]);
            assert_eq!(
                identity.session_id.as_deref(),
                Some("00000000-0000-0000-0000-000000000001")
            );
        }
        other => panic!("expected Shared Auth to win, got {other:?}"),
    }

    let paths = paths.lock().unwrap();
    assert!(paths.iter().any(|path| path == "/shared/auth/exchange"));
    assert!(paths.iter().any(|path| path == "/shared/auth/introspect"));
    assert!(paths.iter().any(|path| path == "/supabase/auth/v1/user"));
}

#[tokio::test]
async fn fiducia_direct_supabase_arm_survives_a_shared_auth_outage_for_authentication() {
    let (base, _) = server(Scenario::SharedAuthUnavailable).await;
    let guard = Guard::new(guard_config(&base));

    let outcome = guard.check(&headers_with_only_provider_token()).await;
    match outcome {
        AuthOutcome::Authenticated {
            authority,
            identity,
            ..
        } => {
            assert_eq!(authority, Authority::Supabase);
            assert_eq!(identity.provider_tenant, "fiducia-customer");
            assert_eq!(identity.supabase_user_id.as_deref(), Some("sup-user-1"));
        }
        other => panic!("expected direct Supabase fallback, got {other:?}"),
    }
}

#[tokio::test]
async fn fiducia_local_role_policy_does_not_fall_back_to_unmirrored_provider_roles() {
    let (base, _) = server(Scenario::SharedAuthUnavailable).await;
    let auth = AuthGuard::from_config(&AuthGuardConfig {
        guard: guard_config(&base),
        policy: AccessPolicy {
            allowed_emails: vec![],
            allowed_roles: vec!["customer".into()],
        },
    })
    .unwrap();

    let outcome = auth.authorize(&headers_with_only_provider_token()).await;
    assert!(matches!(outcome, AuthOutcome::Degraded { .. }));
}
