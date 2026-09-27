//! The limited page.
//!
//! When a guard finds the caller unauthenticated and the request accepts HTML,
//! we return a small page that explains and offers login — never any protected
//! content, and never anything that lets a caller probe which users exist.
//! Non-HTML callers get a flat JSON error instead.

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use shared_auth_interfaces::LimitedPage;

const CSS: &str = r#"
  :root { color-scheme: light dark; }
  body { font: 15px/1.6 system-ui, -apple-system, Segoe UI, sans-serif;
         max-width: 32rem; margin: 6rem auto; padding: 0 1.25rem; }
  h1 { font-size: 1.25rem; margin-bottom: .25rem; }
  p { opacity: .8; }
  a.btn { display: inline-block; margin-top: 1.25rem; padding: .55rem 1.1rem;
          border: 1px solid currentColor; border-radius: 6px; text-decoration: none; }
  .muted { opacity: .55; font-size: .85rem; margin-top: 2rem; }
"#;

/// Does this caller want HTML? (`Accept:` contains `text/html`.)
pub fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false)
}

/// Render the limited page.
pub fn render(page: &LimitedPage) -> Markup {
    let login = login_href(page);
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="robots" content="noindex";
                title { "Sign in required" }
                style { (PreEscaped(CSS)) }
            }
            body {
                h1 { @if page.status_code == 503 { "Sign-in temporarily unavailable" } @else { "Sign in required" } }
                p { (page.reason) }
                a class="btn" href=(login) { "Sign in" }
                p class="muted" { "You are seeing a limited page because this content requires an account." }
            }
        }
    }
}

fn login_href(page: &LimitedPage) -> String {
    match &page.return_to {
        Some(to) if !to.is_empty() => {
            let sep = if page.login_url.contains('?') {
                '&'
            } else {
                '?'
            };
            format!("{}{}return={}", page.login_url, sep, urlencode(to))
        }
        _ => page.login_url.clone(),
    }
}

/// Minimal percent-encoding for a return path (no extra dependency).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The response for a **sandboxed** (machine) caller that reached a human-only
/// guard: always JSON, never the HTML sign-in page.
///
/// A CI runner or agent proved possession of a registered key — it is genuinely
/// authenticated, but it cannot "sign in", so rendering the limited HTML (even
/// when it sends `Accept: text/html`) would be nonsense. It is authenticated but
/// not authorized for an interactive resource, so the status is 403, distinct
/// from the 401 an unauthenticated caller gets.
pub fn forbidden_sandboxed(cred: Option<&str>) -> Response {
    let body = serde_json::json!({
        "error": "forbidden_sandboxed",
        "reason": "This resource requires an interactive session; a sandboxed credential cannot access it.",
        "cred": cred,
    });
    (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
}

/// Build the whole response: limited HTML for browsers, JSON otherwise.
pub fn response(headers: &HeaderMap, page: &LimitedPage) -> Response {
    let status = StatusCode::from_u16(page.status_code).unwrap_or(StatusCode::UNAUTHORIZED);
    if wants_html(headers) {
        (status, axum::response::Html(render(page).into_string())).into_response()
    } else {
        let body = serde_json::json!({
            "error": if status == StatusCode::SERVICE_UNAVAILABLE { "degraded" } else { "unauthorized" },
            "login_url": page.login_url,
        });
        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> LimitedPage {
        LimitedPage {
            status_code: 401,
            login_url: "/auth/sign-in".into(),
            return_to: Some("/dash board?x=1".into()),
            reason: "This page requires an account.".into(),
        }
    }

    #[test]
    fn renders_limited_html_with_login_and_return() {
        let out = render(&page()).into_string();
        assert!(out.contains("Sign in required"));
        assert!(out.contains("noindex"));
        // return path is percent-encoded onto the login URL
        assert!(out.contains("/auth/sign-in?return=/dash%20board%3Fx%3D1"));
        // never leaks protected content
        assert!(!out.contains("dashboard-data"));
    }

    #[test]
    fn degraded_page_says_unavailable_not_signed_out() {
        let p = LimitedPage {
            status_code: 503,
            ..page()
        };
        let out = render(&p).into_string();
        assert!(out.contains("temporarily unavailable"));
    }

    #[test]
    fn wants_html_detects_browsers() {
        let mut h = HeaderMap::new();
        assert!(!wants_html(&h));
        h.insert(header::ACCEPT, "application/json".parse().unwrap());
        assert!(!wants_html(&h));
        h.insert(
            header::ACCEPT,
            "text/html,application/xhtml+xml".parse().unwrap(),
        );
        assert!(wants_html(&h));
    }

    #[test]
    fn login_href_without_return_is_bare() {
        let p = LimitedPage {
            return_to: None,
            ..page()
        };
        assert_eq!(login_href(&p), "/auth/sign-in");
    }
}
