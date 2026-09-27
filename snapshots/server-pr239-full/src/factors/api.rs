/// Public availability discovery consumed before the dashboard has an
/// organization context. This is intentionally not the organization-scoped
/// Ores `CredentialCapabilityProjection`; consumers map it only after
/// directory authorization and must not treat it as role authority.
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDocument {
    schema: &'static str,
    generated_at: DateTime<Utc>,
    mfa_enabled: bool,
    methods: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threefa_import_scheme: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    biometric_model: Option<&'static str>,
    capabilities: Vec<Capability>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct Capability {
    id: &'static str,
    label: &'static str,
    state: &'static str,
    authority: &'static str,
    custody: &'static str,
    notes: &'static str,
}

#[derive(Serialize)]
pub struct Factor {
    factor_id: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_used_at: Option<String>,
    created_at: String,
}

#[derive(Deserialize)]
pub struct TotpEnrollRequest {
    #[serde(default)]
    label: Option<String>,
}

#[derive(Serialize)]
pub struct TotpEnrollment {
    factor_id: String,
    secret_base32: String,
    otpauth_uri: String,
    threefa_import_uri: String,
}

#[derive(Deserialize)]
pub struct TotpConfirmRequest {
    factor_id: String,
    code: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    EmailOtp,
    SmsOtp,
}

#[derive(Deserialize)]
pub struct ChallengeRequest {
    kind: ChallengeKind,
}

#[derive(Serialize)]
pub struct ChallengeStart {
    challenge_id: String,
    expires_at: String,
    delivery: String,
}

#[derive(Deserialize)]
pub struct ChallengeVerifyRequest {
    code: String,
}

#[derive(Serialize)]
pub struct CeremonyStart {
    challenge_id: String,
    options: Value,
    expires_at: String,
}

#[derive(Deserialize)]
pub struct PasskeyStartRequest {
    #[serde(default)]
    label: Option<String>,
}

#[derive(Deserialize)]
pub struct PasskeyFinishRequest {
    challenge_id: String,
    credential: Value,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Serialize)]
pub struct StepUpResponse {
    access_token: String,
    token_type: &'static str,
    expires_at: u64,
    amr: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acr: Option<String>,
}

pub async fn capabilities(State(state): State<AppState>) -> Json<CapabilityDocument> {
    let factors = state.factors.as_ref();
    let methods = configured_methods(
        email_otp_is_enabled(&state),
        sms_otp_is_enabled(&state),
        factors.is_some_and(FactorService::supports_totp),
        factors.is_some_and(FactorService::supports_passkeys),
    );
    let global_revocation_implemented = state.config.global_revocation.enabled
        && state.config.global_revocation.admin_realm
        && state.db.is_some();
    Json(capability_document(
        global_revocation_implemented,
        methods,
    ))
}

fn configured_methods(email_otp: bool, sms_otp: bool, totp: bool, passkey: bool) -> Vec<String> {
    [
        email_otp.then_some("email_otp"),
        sms_otp.then_some("sms_otp"),
        totp.then_some("totp"),
        passkey.then_some("passkey"),
    ]
    .into_iter()
    .flatten()
    .map(str::to_owned)
    .collect()
}

fn capability_document(
    global_revocation_implemented: bool,
    methods: Vec<String>,
) -> CapabilityDocument {
    let revocation_state = if global_revocation_implemented {
        "implemented"
    } else {
        "contract_only"
    };
    let revocation_notes = if global_revocation_implemented {
        "Authoritative keyed-alias lookup, dual-control preview/commit, central epoch fence, durable target state, and redacted audit are enabled."
    } else {
        "Unavailable until the authoritative database, keyed alias index, delegated-token exchange, and dual-control revocation plane pass startup gates."
    };
    CapabilityDocument {
        schema: "shared-auth/capabilities/v1",
        generated_at: Utc::now(),
        mfa_enabled: !methods.is_empty(),
        threefa_import_scheme: methods
            .iter()
            .any(|method| method == "totp")
            .then_some("otpauth"),
        biometric_model: methods
            .iter()
            .any(|method| method == "passkey")
            .then_some("platform_authenticator_webauthn"),
        methods,
        capabilities: vec![
            Capability {
                id: "jwt",
                label: "JWT / JWKS / introspection",
                state: "implemented",
                authority: "authentication",
                custody: "server_keys",
                notes: "ES256 identity tokens, JWKS verification, central revocation fences, and protected online introspection.",
            },
            Capability {
                id: "totp",
                label: "TOTP / OTP",
                state: "implemented",
                authority: "authentication_factor",
                custody: "encrypted_seed",
                notes: "Factor enrollment and challenges are implemented; seed material is encrypted and never rendered.",
            },
            Capability {
                id: "webauthn",
                label: "Passkeys / platform biometrics",
                state: "implemented",
                authority: "authentication_factor",
                custody: "platform_authenticator",
                notes: "Face or fingerprint matching remains inside the platform authenticator; only WebAuthn public credentials and assertions cross the boundary.",
            },
            Capability {
                id: "ssh",
                label: "SSH public-key challenge",
                state: "candidate",
                authority: "authentication_factor",
                custody: "public_key_only",
                notes: "Candidate only; private keys are never accepted or stored and no production authentication route is advertised.",
            },
            Capability {
                id: "kerberos",
                label: "Kerberos / SPNEGO",
                state: "contract_only",
                authority: "authentication",
                custody: "ticket_not_retained",
                notes: "Contract only; unavailable until implementation and replay protections are independently verified.",
            },
            Capability {
                id: "openpgp",
                label: "OpenPGP / GPG signatures",
                state: "contract_only",
                authority: "provenance_only",
                custody: "public_key_only",
                notes: "Public-key signature provenance only; it never grants roles, sessions, or resource authorization.",
            },
            Capability {
                id: "global-session-revocation-by-email",
                label: "Global session revocation by email",
                state: revocation_state,
                authority: "session_administration",
                custody: "email_transient_authoritative_service_only",
                notes: revocation_notes,
            },
            Capability {
                id: "external-face-recovery",
                label: "External face recovery",
                state: "disabled",
                authority: "none",
                custody: "none",
                notes: "Disabled. Raw images, face templates, and biometric-derived recovery material are neither accepted nor retained.",
            },
            Capability {
                id: "external-fingerprint-recovery",
                label: "External fingerprint recovery",
                state: "disabled",
                authority: "none",
                custody: "none",
                notes: "Disabled. Raw scans, fingerprint templates, and biometric-derived recovery material are neither accepted nor retained.",
            },
            Capability {
                id: "qr-device-bind",
                label: "QR login and device bind",
                state: "implemented",
                authority: "authentication_factor",
                custody: "challenge_nonce",
                notes: "Cross-device QR login and signed-in device bind. The payload is a challenge id and nonce; TOTP otpauth_uri remains the authenticator-app QR.",
            },
            Capability {
                id: "risk-signals",
                label: "IP, fingerprint, and embedding warnings",
                state: "implemented",
                authority: "risk_warning",
                custody: "hmac_only",
                notes: "Warning plane. Raw IP and client hints are hashed. Behavioral embeddings are compared to public bad-actor centroids; they are not faces.",
            },
            Capability {
                id: "id-verification",
                label: "Third-party government-ID verification",
                state: "implemented",
                authority: "identity_proofing",
                custody: "provider_inquiry_only",
                notes: "Vendor capture only. Shared-auth stores inquiry id, document type, and verdicts — never ID photos or face templates.",
            },
            Capability {
                id: "age-verification",
                label: "Age-over-N verification",
                state: "implemented",
                authority: "identity_proofing",
                custody: "provider_inquiry_only",
                notes: "Age-over-18/21 is fail-closed unless the vendor asserts it or returns an estimated age. Raw ID images are not retained.",
            },
        ],
    }
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Factor>>, AuthError> {
    let claims = claims(&state, &headers).await?;
    require_interactive_factor_token(&claims)?;
    let service = state.factors.as_ref().ok_or(AuthError::Unavailable)?;
    Ok(Json(service.list_factors(claim_user_id(&claims)?).await?))
}

pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_factor_id): Path<String>,
) -> Result<StatusCode, AuthError> {
    let claims = claims(&state, &headers).await?;
    require_interactive_factor_token(&claims)?;
    let factor_id = parse_uuid(&raw_factor_id, "invalid factor id")?;
    let service = state.factors.as_ref().ok_or(AuthError::Unavailable)?;
    let user_id = claim_user_id(&claims)?;
    service
        .authorize_factor_deletion(&state, &claims, factor_id)
        .await?;
    service.delete_factor(user_id, factor_id).await?;
    // Removing an authenticator is a security-sensitive change: drop the user's
    // existing sessions so access tokens minted under the old factor set stop
    // being honoured immediately rather than at their natural expiry.
    revoke_user_sessions(&state, user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn enroll_totp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TotpEnrollRequest>,
) -> Result<(StatusCode, Json<TotpEnrollment>), AuthError> {
    let claims = claims(&state, &headers).await?;
    require_interactive_factor_token(&claims)?;
    let service = state.factors.as_ref().ok_or(AuthError::Unavailable)?;
    service.authorize_factor_enrollment(&state, &claims).await?;
    let user_id = claim_user_id(&claims)?;
    let account = claims.email.as_deref().unwrap_or(&claims.sub);
    let enrollment = service
        .enroll_totp(user_id, account, request.label.as_deref())
        .await?;
    Ok((StatusCode::CREATED, Json(enrollment)))
}

pub async fn confirm_totp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TotpConfirmRequest>,
) -> Result<Json<StepUpResponse>, AuthError> {
    let claims = claims(&state, &headers).await?;
    require_interactive_factor_token(&claims)?;
    let factor_id = parse_uuid(&request.factor_id, "invalid factor id")?;
    let service = state.factors.as_ref().ok_or(AuthError::Unavailable)?;
    // Redis is a supplemental edge bucket. The factor row also consumes a
    // PostgreSQL-backed attempt before verification, so a cache outage can
    // never remove the durable cross-session/cross-replica lockout.
    crate::http::enforce_limit(&state, "totp_confirm", &claims.sub, 8, 900).await?;
    service
        .confirm_totp(&state, &claims, factor_id, &request.code)
        .await?;
    Ok(Json(step_up(&state, &claims, "totp")?))
}

pub async fn create_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ChallengeRequest>,
) -> Result<(StatusCode, Json<ChallengeStart>), AuthError> {
    let claims = claims(&state, &headers).await?;
    // Sandboxed and delegated tokens can never enter an AAL2 ceremony. This
    // also prevents non-interactive credentials from abusing OTP delivery.
    require_interactive_factor_token(&claims)?;
    match request.kind {
        ChallengeKind::EmailOtp if !email_otp_is_enabled(&state) => {
            return Err(AuthError::Unavailable);
        }
        ChallengeKind::SmsOtp if !sms_otp_is_enabled(&state) => {
            return Err(AuthError::Unavailable);
        }
        _ => {}
    }
    let service = state.factors.as_ref().ok_or(AuthError::Unavailable)?;
    let pepper = state
        .config
        .magic_links
        .otp_pepper
        .as_deref()
        .ok_or(AuthError::Unavailable)?;
    let (response, _, code) = service
        .create_otp_challenge(&claims, request.kind, pepper.as_bytes())
        .await?;
    let challenge_id = Uuid::parse_str(&response.challenge_id).map_err(|_| AuthError::Internal)?;
    let (bound_kind, destination) = service
        .bound_challenge_destination(&claims, challenge_id, pepper.as_bytes())
        .await?;
    let expected_kind = match request.kind {
        ChallengeKind::EmailOtp => "email_otp",
        ChallengeKind::SmsOtp => "sms_otp",
    };
    if bound_kind != expected_kind {
        return Err(AuthError::Internal);
    }
    let delivery = match request.kind {
        ChallengeKind::EmailOtp => send_email_otp(&state, &destination, &code).await,
        ChallengeKind::SmsOtp => {
            crate::twilio::start_sms_verification(
                &state.http,
                &state.config.twilio_verify,
                &destination,
            )
            .await
        }
    };
    if let Err(error) = delivery {
        // The code was never delivered. Consume the durable challenge so it
        // does not occupy the active-challenge budget or become usable after a
        // provider retry whose outcome the server did not observe.
        let user_id = claim_user_id(&claims)?;
        let session_id = claim_session_id(&claims)?;
        if let Err(cancel_error) = service
            .cancel_challenge(user_id, session_id, challenge_id)
            .await
        {
            tracing::warn!(error = %cancel_error, %challenge_id, "failed to cancel undelivered OTP challenge");
        }
        return Err(error);
    }
    Ok((StatusCode::ACCEPTED, Json(response)))
}

pub async fn verify_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(raw_challenge_id): Path<String>,
    Json(request): Json<ChallengeVerifyRequest>,
) -> Result<Json<StepUpResponse>, AuthError> {
    let claims = claims(&state, &headers).await?;
    require_interactive_factor_token(&claims)?;
    let challenge_id = parse_uuid(&raw_challenge_id, "invalid challenge id")?;
    let service = state.factors.as_ref().ok_or(AuthError::Unavailable)?;
    let pepper = state
        .config
        .magic_links
        .otp_pepper
        .as_deref()
        .ok_or(AuthError::Unavailable)?;

    // Resolve and verify the binding before a paid provider call. The durable
    // verifier repeats the same check after the call, so a destination change
    // in either interval burns or rejects the challenge.
    let (kind, destination) = service
        .bound_challenge_destination(&claims, challenge_id, pepper.as_bytes())
        .await?;
    if kind == "sms_otp" {
        let valid = crate::twilio::check_sms_verification(
            &state.http,
            &state.config.twilio_verify,
            &destination,
            &request.code,
        )
        .await?;
        if !valid {
            service
                .record_failed_otp_attempt(&claims, challenge_id, "sms_otp")
                .await?;
            return Err(AuthError::Unauthorized);
        }
    }
    let method = service
        .verify_otp_challenge(
            &claims,
            challenge_id,
            &request.code,
            pepper.as_bytes(),
            kind == "sms_otp",
        )
        .await?;
    Ok(Json(step_up(&state, &claims, method)?))
}

pub async fn start_passkey_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PasskeyStartRequest>,
) -> Result<Json<CeremonyStart>, AuthError> {
    let claims = claims(&state, &headers).await?;
    require_interactive_factor_token(&claims)?;
    let _ = crate::http::admin_revocation::enforce_privileged_passkey_enrollment(&state, &claims)
        .await?;
    let service = state.factors.as_ref().ok_or(AuthError::Unavailable)?;
    service.authorize_factor_enrollment(&state, &claims).await?;
    Ok(Json(
        service
            .start_passkey_registration(&claims, request.label.as_deref())
            .await?,
    ))
}

pub async fn finish_passkey_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PasskeyFinishRequest>,
) -> Result<Json<Factor>, AuthError> {
    let claims = claims(&state, &headers).await?;
    require_interactive_factor_token(&claims)?;
    let privileged_enrollment_authorized =
        crate::http::admin_revocation::enforce_privileged_passkey_enrollment(&state, &claims)
            .await?;
    let challenge_id = parse_uuid(&request.challenge_id, "invalid challenge id")?;
    let service = state.factors.as_ref().ok_or(AuthError::Unavailable)?;
    // Re-check at completion; the start decision is not a durable grant.
    service.authorize_factor_enrollment(&state, &claims).await?;
    Ok(Json(
        service
            .finish_passkey_registration(
                &claims,
                challenge_id,
                request.credential,
                request.label.as_deref(),
                privileged_enrollment_authorized,
            )
            .await?,
    ))
}

pub async fn start_passkey_authentication(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CeremonyStart>, AuthError> {
    let claims = claims(&state, &headers).await?;
    require_interactive_factor_token(&claims)?;
    let service = state.factors.as_ref().ok_or(AuthError::Unavailable)?;
    Ok(Json(service.start_passkey_authentication(&claims).await?))
}

pub async fn finish_passkey_authentication(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PasskeyFinishRequest>,
) -> Result<Json<StepUpResponse>, AuthError> {
    let claims = claims(&state, &headers).await?;
    require_interactive_factor_token(&claims)?;
    let challenge_id = parse_uuid(&request.challenge_id, "invalid challenge id")?;
    let service = state.factors.as_ref().ok_or(AuthError::Unavailable)?;
    service
        .finish_passkey_authentication(&claims, challenge_id, request.credential)
        .await?;
    Ok(Json(step_up(&state, &claims, "passkey")?))
}
