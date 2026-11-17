use reqwest::Method;
use serde::{Deserialize, Serialize};

use super::{decode_empty, required_credential, ClientError, SharedAuthClient};

const MIN_REGISTRATION_PASSWORD_BYTES: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1024;
const MAX_EMAIL_BYTES: usize = 320;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SessionResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: u64,
    pub refresh_token: String,
    pub refresh_expires_at: u64,
    pub shared_user_id: String,
    pub provider: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct PasswordlessAccepted {
    pub accepted: bool,
}

#[derive(Serialize)]
struct RegisterRequest<'a> {
    email: &'a str,
    password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Serialize)]
struct PasswordlessRequest<'a> {
    email: &'a str,
}

#[derive(Serialize)]
struct PasswordlessConsumeRequest<'a> {
    email: &'a str,
    otp: &'a str,
}

#[derive(Serialize)]
struct RefreshRequest<'a> {
    refresh_token: &'a str,
}

impl SharedAuthClient {
    pub async fn register(
        &self,
        email: &str,
        password: &str,
        display_name: Option<&str>,
    ) -> Result<SessionResponse, ClientError> {
        let email = validated_email(email)?;
        validate_registration_password(password)?;
        let display_name = validated_display_name(display_name)?;
        let request = self.request(Method::POST, &["auth", "register"])?;
        let request = self.with_json(
            request,
            &RegisterRequest {
                email,
                password,
                display_name,
            },
        )?;
        return self.send_json(request).await;
    }

    pub async fn login(&self, email: &str, password: &str) -> Result<SessionResponse, ClientError> {
        let email = validated_email(email)?;
        validate_login_password(password)?;
        let request = self.request(Method::POST, &["auth", "login"])?;
        let request = self.with_json(request, &LoginRequest { email, password })?;
        return self.send_json(request).await;
    }

    /// Starts the enumeration-resistant six-digit email OTP flow.
    ///
    /// For a syntactically valid email the server intentionally returns the same
    /// accepted response whether or not an account exists.
    pub async fn request_passwordless(
        &self,
        email: &str,
    ) -> Result<PasswordlessAccepted, ClientError> {
        let email = validated_email(email)?;
        let request = self.request(Method::POST, &["auth", "passwordless", "request"])?;
        let request = self.with_json(request, &PasswordlessRequest { email })?;
        return self.send_json(request).await;
    }

    /// Consumes a single-use six-digit email OTP.
    ///
    /// Legacy bearer-link tokens are intentionally not represented by this API.
    pub async fn consume_passwordless(
        &self,
        email: &str,
        otp: &str,
    ) -> Result<SessionResponse, ClientError> {
        let email = validated_email(email)?;
        validate_email_otp(otp)?;
        let request = self.request(Method::POST, &["auth", "passwordless", "consume"])?;
        let request = self.with_json(request, &PasswordlessConsumeRequest { email, otp })?;
        return self.send_json(request).await;
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<SessionResponse, ClientError> {
        let refresh_token = required_credential(refresh_token, "refresh token")?;
        let request = self.request(Method::POST, &["auth", "refresh"])?;
        let request = self.with_json(request, &RefreshRequest { refresh_token })?;
        return self.send_json(request).await;
    }

    pub async fn logout(&self, refresh_token: &str) -> Result<(), ClientError> {
        let refresh_token = required_credential(refresh_token, "refresh token")?;
        let request = self.request(Method::POST, &["auth", "logout"])?;
        let request = self.with_json(request, &RefreshRequest { refresh_token })?;
        decode_empty(request.send().await?)
    }
}

fn validated_email(value: &str) -> Result<&str, ClientError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_EMAIL_BYTES
        || value.chars().any(char::is_control)
        || !value.contains('@')
    {
        return Err(ClientError::InvalidInput("email"));
    }
    Ok(value)
}

fn validate_registration_password(value: &str) -> Result<(), ClientError> {
    if value.len() < MIN_REGISTRATION_PASSWORD_BYTES || value.len() > MAX_PASSWORD_BYTES {
        return Err(ClientError::InvalidInput("password"));
    }
    Ok(())
}

fn validate_login_password(value: &str) -> Result<(), ClientError> {
    if value.is_empty() || value.len() > MAX_PASSWORD_BYTES {
        return Err(ClientError::InvalidInput("password"));
    }
    Ok(())
}

fn validated_display_name(value: Option<&str>) -> Result<Option<&str>, ClientError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > 160 || trimmed.chars().any(char::is_control) {
        return Err(ClientError::InvalidInput("display name"));
    }
    Ok(Some(trimmed))
}

fn validate_email_otp(value: &str) -> Result<(), ClientError> {
    if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ClientError::InvalidInput("email otp"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use super::*;

    #[tokio::test]
    async fn passwordless_consume_uses_only_email_and_otp() {
        let (base, receiver) = spawn_json_response(
            r#"{"access_token":"access","token_type":"Bearer","expires_at":42,"refresh_token":"refresh","refresh_expires_at":84,"shared_user_id":"user-1","provider":"magic_link","roles":[],"amr":["email"]}"#,
        );
        let client = SharedAuthClient::new(base);

        let session = client
            .consume_passwordless("user@example.com", "123456")
            .await
            .unwrap();
        let request = receiver.recv().unwrap();

        assert_eq!(session.provider, "magic_link");
        assert!(request.starts_with("POST /auth/passwordless/consume HTTP/1.1"));
        assert!(request.contains(r#"{"email":"user@example.com","otp":"123456"}"#));
        assert!(!request.contains("token"));
    }

    #[tokio::test]
    async fn invalid_otp_fails_before_transport() {
        let client = SharedAuthClient::new("http://127.0.0.1:1");

        for otp in ["12345", "1234567", "12a456", " 12345"] {
            let error = client
                .consume_passwordless("user@example.com", otp)
                .await
                .unwrap_err();
            assert!(matches!(error, ClientError::InvalidInput("email otp")));
        }
    }

    #[tokio::test]
    async fn passwordless_request_preserves_enumeration_resistant_response() {
        let (base, receiver) = spawn_json_response(r#"{"accepted":true}"#);
        let client = SharedAuthClient::new(base);

        let response = client
            .request_passwordless("user@example.com")
            .await
            .unwrap();
        let request = receiver.recv().unwrap();

        assert!(response.accepted);
        assert!(request.starts_with("POST /auth/passwordless/request HTTP/1.1"));
        assert!(request.contains(r#"{"email":"user@example.com"}"#));
    }

    #[tokio::test]
    async fn malformed_session_inputs_fail_before_transport() {
        let client = SharedAuthClient::new("http://127.0.0.1:1");

        assert!(matches!(
            client
                .request_passwordless(" user@example.com")
                .await
                .unwrap_err(),
            ClientError::InvalidInput("email")
        ));
        assert!(matches!(
            client
                .register("user@example.com", "too-short", None)
                .await
                .unwrap_err(),
            ClientError::InvalidInput("password")
        ));
        assert!(matches!(
            client.refresh(" refresh-token").await.unwrap_err(),
            ClientError::InvalidInput("refresh token")
        ));
    }

    fn spawn_json_response(body: &'static str) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let count = stream.read(&mut buffer).unwrap();
            request.extend_from_slice(&buffer[..count]);
            sender
                .send(String::from_utf8_lossy(&request).into_owned())
                .unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            )
            .unwrap();
        });
        (format!("http://{address}"), receiver)
    }
}
