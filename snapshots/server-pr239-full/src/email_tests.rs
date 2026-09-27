use std::sync::{Arc, Mutex};

use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Router;
use serde_json::Value;

use super::*;

#[derive(Clone, Debug)]
struct CapturedRequest {
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Clone)]
struct MockState {
    status: StatusCode,
    response_body: &'static str,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

async fn mock_handler(State(state): State<MockState>, request: Request) -> (StatusCode, String) {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 64 * 1024).await.unwrap().to_vec();
    state.requests.lock().unwrap().push(CapturedRequest {
        path: parts.uri.path().to_string(),
        headers: parts.headers,
        body,
    });
    (state.status, state.response_body.to_string())
}

async fn mock_server(
    status: StatusCode,
    response_body: &'static str,
) -> (String, Arc<Mutex<Vec<CapturedRequest>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        status,
        response_body,
        requests: requests.clone(),
    };
    let app = Router::new().fallback(mock_handler).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), requests)
}

fn config() -> MagicLinkConfig {
    MagicLinkConfig {
        sendgrid_api_key: Some("secret".into()),
        otp_pepper: Some("test-pepper-at-least-thirty-two-bytes".into()),
        from_email: Some("auth@example.com".into()),
        from_name: "Sonus Auris".into(),
        link_base_url: None,
        ttl_secs: 900,
        allow_signup: true,
    }
}

#[test]
fn html_escaping_protects_the_brand_name() {
    assert_eq!(
        escape_html("Sonus <Auris> & \"friends\""),
        "Sonus &lt;Auris&gt; &amp; &quot;friends&quot;"
    );
}

#[tokio::test]
async fn sendgrid_request_is_bearer_authenticated_branded_and_otp_only() {
    let (base, requests) = mock_server(StatusCode::ACCEPTED, "").await;
    send_email_otp_to(
        &reqwest::Client::new(),
        &config(),
        &format!("{base}/v3/mail/send"),
        "person@example.com",
        "123456",
    )
    .await
    .unwrap();

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.path, "/v3/mail/send");
    assert_eq!(
        request
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        "Bearer secret"
    );

    let payload: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(
        payload["personalizations"][0]["to"][0]["email"].as_str(),
        Some("person@example.com")
    );
    assert_eq!(payload["from"]["email"].as_str(), Some("auth@example.com"));
    assert_eq!(payload["from"]["name"].as_str(), Some("Sonus Auris"));
    assert_eq!(
        payload["subject"].as_str(),
        Some("Your Sonus Auris sign-in code")
    );

    let serialized = String::from_utf8(request.body.clone()).unwrap();
    assert!(!serialized.contains("Bearer secret"));
    for forbidden in [
        "http://",
        "https://",
        "<a ",
        "href=",
        "redirect_to",
        "token_hash",
        "action_link",
        "magic_link",
    ] {
        assert!(
            !serialized.to_ascii_lowercase().contains(forbidden),
            "OTP email unexpectedly contained {forbidden}"
        );
    }
    for index in [0, 1] {
        let content = payload["content"][index]["value"].as_str().unwrap();
        assert!(content.contains("123456"));
        assert!(content.contains("Sonus Auris"));
    }
}

#[tokio::test]
async fn invalid_or_blank_delivery_fields_fail_before_network() {
    let mut missing_api_key = config();
    missing_api_key.sendgrid_api_key = None;
    let mut missing_sender = config();
    missing_sender.from_email = None;
    let mut blank_api_key = config();
    blank_api_key.sendgrid_api_key = Some("   ".into());
    let mut blank_sender = config();
    blank_sender.from_email = Some("\n".into());
    let mut blank_brand = config();
    blank_brand.from_name = "\t".into();

    for (field, incomplete) in [
        ("missing api key", missing_api_key),
        ("missing sender", missing_sender),
        ("blank api key", blank_api_key),
        ("blank sender", blank_sender),
        ("blank brand", blank_brand),
    ] {
        let (base, requests) = mock_server(StatusCode::ACCEPTED, "").await;
        let result = send_email_otp_to(
            &reqwest::Client::new(),
            &incomplete,
            &format!("{base}/v3/mail/send"),
            "person@example.com",
            "123456",
        )
        .await;
        assert!(
            matches!(result, Err(AuthError::Unavailable)),
            "{field} must disable delivery"
        );
        assert_eq!(
            requests.lock().unwrap().len(),
            0,
            "{field} must fail before contacting SendGrid"
        );
    }

    let (base, requests) = mock_server(StatusCode::ACCEPTED, "").await;
    let result = send_email_otp_to(
        &reqwest::Client::new(),
        &config(),
        &format!("{base}/v3/mail/send"),
        "person@example.com",
        "12x456",
    )
    .await;
    assert!(matches!(result, Err(AuthError::BadRequest(_))));
    assert_eq!(requests.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn sendgrid_non_accepted_response_fails_closed() {
    let (base, _) = mock_server(StatusCode::TOO_MANY_REQUESTS, "rate limited").await;
    let result = send_email_otp_to(
        &reqwest::Client::new(),
        &config(),
        &format!("{base}/v3/mail/send"),
        "person@example.com",
        "123456",
    )
    .await;
    assert!(matches!(result, Err(AuthError::Upstream)));
}

#[tokio::test]
async fn sendgrid_payload_escapes_untrusted_brand_and_never_embeds_api_key() {
    let mut branded = config();
    branded.from_name = "Sonus <Auris>".into();
    let (base, requests) = mock_server(StatusCode::ACCEPTED, "").await;
    send_email_otp_to(
        &reqwest::Client::new(),
        &branded,
        &format!("{base}/v3/mail/send"),
        "person@example.com",
        "123456",
    )
    .await
    .unwrap();

    let requests = requests.lock().unwrap();
    let request = &requests[0];
    let serialized = String::from_utf8(request.body.clone()).unwrap();
    assert!(!serialized.contains("Bearer secret"));

    let payload: Value = serde_json::from_slice(&request.body).unwrap();
    let html = payload["content"][1]["value"].as_str().unwrap();
    assert!(html.contains("Sonus &lt;Auris&gt;"));
    assert!(!html.contains("Sonus <Auris>"));
    assert!(!html.contains("href="));
}
