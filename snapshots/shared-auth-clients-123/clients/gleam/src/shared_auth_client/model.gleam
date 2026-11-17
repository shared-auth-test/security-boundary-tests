import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/list
import gleam/option.{type Option, None, Some}

pub type ExchangeResponse {
  ExchangeResponse(
    access_token: String,
    token_type: String,
    expires_at: Int,
    shared_user_id: String,
    project: Option(String),
    provider: Option(String),
    provider_tenant: Option(String),
  )
}

pub type SessionResponse {
  SessionResponse(
    access_token: String,
    token_type: String,
    expires_at: Int,
    refresh_token: String,
    refresh_expires_at: Int,
    shared_user_id: String,
    provider: String,
    roles: List(String),
    amr: List(String),
    acr: Option(String),
  )
}

pub type PasswordlessAccepted {
  PasswordlessAccepted(accepted: Bool)
}

pub type StepUpResponse {
  StepUpResponse(
    access_token: String,
    token_type: String,
    expires_at: Int,
    amr: List(String),
    acr: Option(String),
  )
}

pub type Introspection {
  Introspection(
    active: Bool,
    sub: Option(String),
    sid: Option(String),
    project: Option(String),
    provider: Option(String),
    provider_tenant: Option(String),
    provider_subject: Option(String),
    email: Option(String),
    email_verified: Option(Bool),
    roles: List(String),
    amr: List(String),
    acr: Option(String),
    exp: Option(Int),
  )
}

pub type Jwks {
  Jwks(keys: List(Dynamic))
}

pub type Capabilities {
  Capabilities(
    mfa_enabled: Bool,
    methods: List(String),
    threefa_import_scheme: Option(String),
    biometric_model: Option(String),
  )
}

pub type Factor {
  Factor(
    factor_id: String,
    kind: String,
    label: Option(String),
    enabled: Bool,
    confirmed_at: Option(String),
    last_used_at: Option(String),
    created_at: String,
  )
}

pub type TotpEnrollment {
  TotpEnrollment(
    factor_id: String,
    secret_base32: String,
    otpauth_uri: String,
    threefa_import_uri: String,
  )
}

pub type ChallengeKind {
  EmailOtp
  SmsOtp
}

pub type ChallengeStart {
  ChallengeStart(challenge_id: String, expires_at: String, delivery: String)
}

pub type CeremonyStart {
  CeremonyStart(challenge_id: String, options: Dynamic, expires_at: String)
}

pub fn challenge_kind_to_string(kind: ChallengeKind) -> String {
  case kind {
    EmailOtp -> "email_otp"
    SmsOtp -> "sms_otp"
  }
}

/// Missing or inactive assurance claims never satisfy an explicit policy.
pub fn has_assurance(value: Introspection, required_acr: String) -> Bool {
  value.active && value.acr == Some(required_acr)
}

pub fn used_method(value: Introspection, method: String) -> Bool {
  value.active && list.contains(value.amr, method)
}

pub fn has_role(value: Introspection, role: String) -> Bool {
  value.active && list.contains(value.roles, role)
}

pub fn exchange_response_decoder() -> decode.Decoder(ExchangeResponse) {
  use access_token <- decode.field("access_token", decode.string)
  use token_type <- decode.field("token_type", decode.string)
  use expires_at <- decode.field("expires_at", decode.int)
  use shared_user_id <- decode.field("shared_user_id", decode.string)
  use project <- decode.optional_field(
    "project",
    None,
    decode.optional(decode.string),
  )
  use provider <- decode.optional_field(
    "provider",
    None,
    decode.optional(decode.string),
  )
  use provider_tenant <- decode.optional_field(
    "provider_tenant",
    None,
    decode.optional(decode.string),
  )
  decode.success(ExchangeResponse(
    access_token: access_token,
    token_type: token_type,
    expires_at: expires_at,
    shared_user_id: shared_user_id,
    project: project,
    provider: provider,
    provider_tenant: provider_tenant,
  ))
}

pub fn session_response_decoder() -> decode.Decoder(SessionResponse) {
  use access_token <- decode.field("access_token", decode.string)
  use token_type <- decode.field("token_type", decode.string)
  use expires_at <- decode.field("expires_at", decode.int)
  use refresh_token <- decode.field("refresh_token", decode.string)
  use refresh_expires_at <- decode.field("refresh_expires_at", decode.int)
  use shared_user_id <- decode.field("shared_user_id", decode.string)
  use provider <- decode.field("provider", decode.string)
  use roles <- decode.optional_field("roles", [], decode.list(decode.string))
  use amr <- decode.optional_field("amr", [], decode.list(decode.string))
  use acr <- decode.optional_field("acr", None, decode.optional(decode.string))
  decode.success(SessionResponse(
    access_token: access_token,
    token_type: token_type,
    expires_at: expires_at,
    refresh_token: refresh_token,
    refresh_expires_at: refresh_expires_at,
    shared_user_id: shared_user_id,
    provider: provider,
    roles: roles,
    amr: amr,
    acr: acr,
  ))
}

pub fn passwordless_accepted_decoder() -> decode.Decoder(PasswordlessAccepted) {
  use accepted <- decode.field("accepted", decode.bool)
  decode.success(PasswordlessAccepted(accepted: accepted))
}

pub fn step_up_response_decoder() -> decode.Decoder(StepUpResponse) {
  use access_token <- decode.field("access_token", decode.string)
  use token_type <- decode.field("token_type", decode.string)
  use expires_at <- decode.field("expires_at", decode.int)
  use amr <- decode.optional_field("amr", [], decode.list(decode.string))
  use acr <- decode.optional_field("acr", None, decode.optional(decode.string))
  decode.success(StepUpResponse(
    access_token: access_token,
    token_type: token_type,
    expires_at: expires_at,
    amr: amr,
    acr: acr,
  ))
}

pub fn introspection_decoder() -> decode.Decoder(Introspection) {
  use active <- decode.field("active", decode.bool)
  use sub <- decode.optional_field("sub", None, decode.optional(decode.string))
  use sid <- decode.optional_field("sid", None, decode.optional(decode.string))
  use project <- decode.optional_field(
    "project",
    None,
    decode.optional(decode.string),
  )
  use provider <- decode.optional_field(
    "provider",
    None,
    decode.optional(decode.string),
  )
  use provider_tenant <- decode.optional_field(
    "provider_tenant",
    None,
    decode.optional(decode.string),
  )
  use provider_subject <- decode.optional_field(
    "provider_subject",
    None,
    decode.optional(decode.string),
  )
  use email <- decode.optional_field(
    "email",
    None,
    decode.optional(decode.string),
  )
  use email_verified <- decode.optional_field(
    "email_verified",
    None,
    decode.optional(decode.bool),
  )
  use roles <- decode.optional_field("roles", [], decode.list(decode.string))
  use amr <- decode.optional_field("amr", [], decode.list(decode.string))
  use acr <- decode.optional_field("acr", None, decode.optional(decode.string))
  use exp <- decode.optional_field("exp", None, decode.optional(decode.int))
  decode.success(Introspection(
    active: active,
    sub: sub,
    sid: sid,
    project: project,
    provider: provider,
    provider_tenant: provider_tenant,
    provider_subject: provider_subject,
    email: email,
    email_verified: email_verified,
    roles: roles,
    amr: amr,
    acr: acr,
    exp: exp,
  ))
}

pub fn jwks_decoder() -> decode.Decoder(Jwks) {
  use keys <- decode.field("keys", decode.list(decode.dynamic))
  decode.success(Jwks(keys: keys))
}

pub fn capabilities_decoder() -> decode.Decoder(Capabilities) {
  use mfa_enabled <- decode.field("mfa_enabled", decode.bool)
  use methods <- decode.optional_field(
    "methods",
    [],
    decode.list(decode.string),
  )
  use threefa_import_scheme <- decode.optional_field(
    "threefa_import_scheme",
    None,
    decode.optional(decode.string),
  )
  use biometric_model <- decode.optional_field(
    "biometric_model",
    None,
    decode.optional(decode.string),
  )
  decode.success(Capabilities(
    mfa_enabled: mfa_enabled,
    methods: methods,
    threefa_import_scheme: threefa_import_scheme,
    biometric_model: biometric_model,
  ))
}

pub fn factor_decoder() -> decode.Decoder(Factor) {
  use factor_id <- decode.field("factor_id", decode.string)
  use kind <- decode.field("kind", decode.string)
  use label <- decode.optional_field(
    "label",
    None,
    decode.optional(decode.string),
  )
  use enabled <- decode.field("enabled", decode.bool)
  use confirmed_at <- decode.optional_field(
    "confirmed_at",
    None,
    decode.optional(decode.string),
  )
  use last_used_at <- decode.optional_field(
    "last_used_at",
    None,
    decode.optional(decode.string),
  )
  use created_at <- decode.field("created_at", decode.string)
  decode.success(Factor(
    factor_id: factor_id,
    kind: kind,
    label: label,
    enabled: enabled,
    confirmed_at: confirmed_at,
    last_used_at: last_used_at,
    created_at: created_at,
  ))
}

pub fn totp_enrollment_decoder() -> decode.Decoder(TotpEnrollment) {
  use factor_id <- decode.field("factor_id", decode.string)
  use secret_base32 <- decode.field("secret_base32", decode.string)
  use otpauth_uri <- decode.field("otpauth_uri", decode.string)
  use threefa_import_uri <- decode.field("threefa_import_uri", decode.string)
  decode.success(TotpEnrollment(
    factor_id: factor_id,
    secret_base32: secret_base32,
    otpauth_uri: otpauth_uri,
    threefa_import_uri: threefa_import_uri,
  ))
}

pub fn challenge_start_decoder() -> decode.Decoder(ChallengeStart) {
  use challenge_id <- decode.field("challenge_id", decode.string)
  use expires_at <- decode.field("expires_at", decode.string)
  use delivery <- decode.field("delivery", decode.string)
  decode.success(ChallengeStart(
    challenge_id: challenge_id,
    expires_at: expires_at,
    delivery: delivery,
  ))
}

pub fn ceremony_start_decoder() -> decode.Decoder(CeremonyStart) {
  use challenge_id <- decode.field("challenge_id", decode.string)
  use options <- decode.field("options", decode.dynamic)
  use expires_at <- decode.field("expires_at", decode.string)
  decode.success(CeremonyStart(
    challenge_id: challenge_id,
    options: options,
    expires_at: expires_at,
  ))
}
