#![forbid(unsafe_code)]

//! One-use 3FA proximity request mint and consume.
//!
//! Shared Auth servers have no Bluetooth dependency. The radio relay is opaque.
//! Only an independently verified consume on the authenticated 3FA-to-Shared-Auth
//! channel may contribute `threefa_app`. Unavailable authorities stay `degraded`.

use std::collections::HashMap;
use std::fmt;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

pub const PROTOCOL: &str = "shared-auth.proximity-step-up.v1";
pub const PURPOSE: &str = "shared-auth:step-up:relay";
pub const THREEFA_APP_AMR: &str = "threefa_app";
pub const STEP_UP_ACR: &str = "urn:oresoftware:loa:2";
pub const MAX_TTL_MS: u64 = 120_000;
pub const TRANSPORT_NEVER_AMR: &[&str] = &[
    "bluetooth",
    "nearby",
    "proximity",
    "rssi",
    "pairing",
    "bonding",
];

type HmacSha512 = Hmac<Sha512>;

/// Signed one-use proximity request. Matches the interfaces JSON Schema.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProximityStepUpRequest {
    pub protocol: String,
    pub purpose: String,
    pub request_id: String,
    pub issuer: String,
    pub audience: String,
    pub recipient_device_id: String,
    pub exchange_id: String,
    pub requested_acr: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub nonce: String,
    pub sealed_request: String,
    pub sealed_request_sha256: String,
    pub signing_key_id: String,
    pub signature: String,
}

impl fmt::Debug for ProximityStepUpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProximityStepUpRequest")
            .field("request_id", &self.request_id)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("recipient_device_id", &self.recipient_device_id)
            .field("exchange_id", &self.exchange_id)
            .field("signing_key_id", &self.signing_key_id)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field("nonce", &"<redacted>")
            .field("sealed_request", &"<redacted>")
            .field("sealed_request_sha256", &"<redacted>")
            .field("signature", &"<redacted>")
            .finish()
    }
}

impl ProximityStepUpRequest {
    pub fn log_view(&self) -> ProximityLogView {
        ProximityLogView {
            request_id: self.request_id.clone(),
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            recipient_device_id: self.recipient_device_id.clone(),
            exchange_id: self.exchange_id.clone(),
            signing_key_id: self.signing_key_id.clone(),
            expires_at_unix_ms: self.expires_at_unix_ms,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProximityLogView {
    pub request_id: String,
    pub issuer: String,
    pub audience: String,
    pub recipient_device_id: String,
    pub exchange_id: String,
    pub signing_key_id: String,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProximityConsumeResult {
    Completed {
        request_id: String,
        audience: String,
        recipient_device_id: String,
        exchange_id: String,
        amr: Vec<String>,
        acr: String,
    },
    Rejected {
        code: RejectCode,
    },
    Degraded {
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectCode {
    Replay,
    Expired,
    Tampered,
    WrongIssuer,
    WrongAudience,
    WrongDevice,
    WrongExchange,
    RevokedDevice,
    UnenrolledDevice,
    UnauthenticatedChannel,
    UnknownKey,
    TtlExceeded,
}

#[derive(Clone, Debug)]
pub struct MintCommand {
    pub request_id: String,
    pub audience: String,
    pub recipient_device_id: String,
    pub exchange_id: String,
    pub nonce: String,
    pub sealed_plaintext: Vec<u8>,
    pub ttl_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ConsumeContext {
    pub issuer: String,
    pub audience: String,
    pub recipient_device_id: String,
    pub exchange_id: String,
    /// Ordinary authenticated 3FA-to-Shared-Auth channel, not the radio.
    pub authenticated_channel: bool,
    /// When false, consume returns `degraded` and never success.
    pub authority_available: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeviceState {
    Enrolled,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestRecord {
    Minted,
    Consumed,
}

/// Durable mint/consume authority. The map is the durable store; callers persist it.
#[derive(Clone, Debug)]
pub struct ProximityAuthority {
    issuer: String,
    keys: HashMap<String, Vec<u8>>,
    active_kid: String,
    devices: HashMap<String, DeviceState>,
    records: HashMap<String, RequestRecord>,
}

impl ProximityAuthority {
    pub fn new(issuer: impl Into<String>, kid: impl Into<String>, key: Vec<u8>) -> Self {
        let kid = kid.into();
        Self {
            issuer: issuer.into(),
            keys: HashMap::from([(kid.clone(), key)]),
            active_kid: kid,
            devices: HashMap::new(),
            records: HashMap::new(),
        }
    }

    pub fn enroll_device(&mut self, device_id: impl Into<String>) {
        self.devices.insert(device_id.into(), DeviceState::Enrolled);
    }

    pub fn revoke_device(&mut self, device_id: &str) {
        if let Some(state) = self.devices.get_mut(device_id) {
            *state = DeviceState::Revoked;
        }
    }

    /// Rotate the active mint key. Previous keys remain for in-flight consume.
    pub fn rotate_key(&mut self, kid: impl Into<String>, key: Vec<u8>) {
        let kid = kid.into();
        self.keys.insert(kid.clone(), key);
        self.active_kid = kid;
    }

    /// Drop a signing key. In-flight requests signed with it fail as unknown_key.
    pub fn forget_key(&mut self, kid: &str) {
        self.keys.remove(kid);
    }

    pub fn mint(
        &mut self,
        command: MintCommand,
        now_unix_ms: u64,
    ) -> Result<ProximityStepUpRequest, RejectCode> {
        if command.ttl_ms == 0 || command.ttl_ms > MAX_TTL_MS {
            return Err(RejectCode::TtlExceeded);
        }
        match self.devices.get(&command.recipient_device_id) {
            Some(DeviceState::Enrolled) => {}
            Some(DeviceState::Revoked) => return Err(RejectCode::RevokedDevice),
            None => return Err(RejectCode::UnenrolledDevice),
        }
        if self.records.contains_key(&command.request_id) {
            return Err(RejectCode::Replay);
        }

        let sealed_request = b64url(&command.sealed_plaintext);
        let digest = sha256_hex(&command.sealed_plaintext);
        let request = ProximityStepUpRequest {
            protocol: PROTOCOL.to_owned(),
            purpose: PURPOSE.to_owned(),
            request_id: command.request_id.clone(),
            issuer: self.issuer.clone(),
            audience: command.audience,
            recipient_device_id: command.recipient_device_id,
            exchange_id: command.exchange_id,
            requested_acr: STEP_UP_ACR.to_owned(),
            issued_at_unix_ms: now_unix_ms,
            expires_at_unix_ms: now_unix_ms.saturating_add(command.ttl_ms),
            nonce: command.nonce,
            sealed_request,
            sealed_request_sha256: digest,
            signing_key_id: self.active_kid.clone(),
            signature: String::new(),
        };
        let signature = sign(
            self.keys.get(&self.active_kid).expect("active mint key"),
            &canonical(&request),
        );
        let mut signed = request;
        signed.signature = signature;
        self.records
            .insert(command.request_id, RequestRecord::Minted);
        Ok(signed)
    }

    pub fn consume(
        &mut self,
        request: &ProximityStepUpRequest,
        context: &ConsumeContext,
        now_unix_ms: u64,
    ) -> ProximityConsumeResult {
        if !context.authority_available {
            return ProximityConsumeResult::Degraded {
                reason: "shared-auth unavailable".to_owned(),
            };
        }
        if !context.authenticated_channel {
            return reject(RejectCode::UnauthenticatedChannel);
        }
        if let Err(code) = self.verify_and_consume(request, context, now_unix_ms) {
            return reject(code);
        }
        ProximityConsumeResult::Completed {
            request_id: request.request_id.clone(),
            audience: request.audience.clone(),
            recipient_device_id: request.recipient_device_id.clone(),
            exchange_id: request.exchange_id.clone(),
            amr: vec![THREEFA_APP_AMR.to_owned()],
            acr: STEP_UP_ACR.to_owned(),
        }
    }

    fn verify_and_consume(
        &mut self,
        request: &ProximityStepUpRequest,
        context: &ConsumeContext,
        now_unix_ms: u64,
    ) -> Result<(), RejectCode> {
        if request.protocol != PROTOCOL || request.purpose != PURPOSE {
            return Err(RejectCode::Tampered);
        }
        if request.requested_acr != STEP_UP_ACR {
            return Err(RejectCode::Tampered);
        }
        if request.issuer != self.issuer || request.issuer != context.issuer {
            return Err(RejectCode::WrongIssuer);
        }
        if request.audience != context.audience {
            return Err(RejectCode::WrongAudience);
        }
        if request.recipient_device_id != context.recipient_device_id {
            return Err(RejectCode::WrongDevice);
        }
        if request.exchange_id != context.exchange_id {
            return Err(RejectCode::WrongExchange);
        }
        let ttl = request
            .expires_at_unix_ms
            .saturating_sub(request.issued_at_unix_ms);
        if ttl == 0 || ttl > MAX_TTL_MS {
            return Err(RejectCode::TtlExceeded);
        }
        if now_unix_ms >= request.expires_at_unix_ms {
            return Err(RejectCode::Expired);
        }
        match self.devices.get(&request.recipient_device_id) {
            Some(DeviceState::Enrolled) => {}
            Some(DeviceState::Revoked) => return Err(RejectCode::RevokedDevice),
            None => return Err(RejectCode::UnenrolledDevice),
        }
        let key = self
            .keys
            .get(&request.signing_key_id)
            .ok_or(RejectCode::UnknownKey)?;
        if !verify_signature(key, &canonical(request), &request.signature) {
            return Err(RejectCode::Tampered);
        }
        let sealed = b64url_decode(&request.sealed_request).ok_or(RejectCode::Tampered)?;
        if sha256_hex(&sealed) != request.sealed_request_sha256 {
            return Err(RejectCode::Tampered);
        }
        match self.records.get(&request.request_id).copied() {
            Some(RequestRecord::Consumed) => return Err(RejectCode::Replay),
            Some(RequestRecord::Minted) => {}
            None => return Err(RejectCode::Tampered),
        }
        self.records
            .insert(request.request_id.clone(), RequestRecord::Consumed);
        Ok(())
    }
}

fn reject(code: RejectCode) -> ProximityConsumeResult {
    ProximityConsumeResult::Rejected { code }
}

fn canonical(request: &ProximityStepUpRequest) -> String {
    format!(
        "v1|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        request.protocol,
        request.purpose,
        request.request_id,
        request.issuer,
        request.audience,
        request.recipient_device_id,
        request.exchange_id,
        request.requested_acr,
        request.issued_at_unix_ms,
        request.expires_at_unix_ms,
        request.nonce,
        request.sealed_request_sha256
    )
}

fn sign(key: &[u8], canonical: &str) -> String {
    let mut mac = HmacSha512::new_from_slice(key).expect("hmac key");
    mac.update(canonical.as_bytes());
    b64url(mac.finalize().into_bytes())
}

fn verify_signature(key: &[u8], canonical: &str, signature: &str) -> bool {
    let Some(bytes) = b64url_decode(signature) else {
        return false;
    };
    let Ok(mut mac) = HmacSha512::new_from_slice(key) else {
        return false;
    };
    mac.update(canonical.as_bytes());
    mac.verify_slice(&bytes).is_ok()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn b64url(bytes: impl AsRef<[u8]>) -> String {
    base64_encode(bytes.as_ref())
}

fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    base64_decode(input)
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let digit = |index: u8| TABLE[index as usize] as char;
    bytes
        .chunks(3)
        .flat_map(|chunk| {
            let (b0, b1, b2) = match *chunk {
                [b0, b1, b2] => (b0, b1, b2),
                [b0, b1] => (b0, b1, 0),
                [b0] => (b0, 0, 0),
                _ => unreachable!("chunks(3) yields 1..=3 bytes"),
            };
            let chars = [
                digit(b0 >> 2),
                digit(((b0 & 0x03) << 4) | (b1 >> 4)),
                digit(((b1 & 0x0f) << 2) | (b2 >> 6)),
                digit(b2 & 0x3f),
            ];
            let n = match chunk.len() {
                3 => 4,
                2 => 3,
                _ => 2,
            };
            chars.into_iter().take(n)
        })
        .collect()
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    if bytes.iter().any(|&c| matches!(c, b'=' | b'+' | b'/')) {
        return None;
    }
    let values: Vec<u8> = bytes.iter().copied().map(val).collect::<Option<_>>()?;
    values
        .chunks(4)
        .try_fold(Vec::new(), |mut out, chunk| match chunk {
            [a, b, c, d] => {
                let buf = (u32::from(*a) << 18)
                    | (u32::from(*b) << 12)
                    | (u32::from(*c) << 6)
                    | u32::from(*d);
                out.extend_from_slice(&[(buf >> 16) as u8, (buf >> 8) as u8, buf as u8]);
                Some(out)
            }
            [a, b, c] => {
                let buf = (u32::from(*a) << 12) | (u32::from(*b) << 6) | u32::from(*c);
                out.extend_from_slice(&[(buf >> 10) as u8, (buf >> 2) as u8]);
                Some(out)
            }
            [a, b] => {
                let buf = (u32::from(*a) << 6) | u32::from(*b);
                out.push((buf >> 4) as u8);
                Some(out)
            }
            _ => None,
        })
}

/// Delivery/proximity observations are never AMR and never raise AAL.
pub fn proximity_delivery_amr() -> &'static [&'static str] {
    &[]
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://auth.example.invalid";
    const AUDIENCE: &str = "cliptown";
    const DEVICE: &str = "22222222-2222-4222-8222-222222222222";
    const EXCHANGE: &str = "33333333-3333-4333-8333-333333333333";
    const REQUEST: &str = "11111111-1111-4111-8111-111111111111";
    const NOW: u64 = 1_787_590_800_000;

    fn authority() -> ProximityAuthority {
        let mut auth = ProximityAuthority::new(ISSUER, "kid-1", vec![7; 64]);
        auth.enroll_device(DEVICE);
        auth
    }

    fn command() -> MintCommand {
        MintCommand {
            request_id: REQUEST.to_owned(),
            audience: AUDIENCE.to_owned(),
            recipient_device_id: DEVICE.to_owned(),
            exchange_id: EXCHANGE.to_owned(),
            nonce: "AQIDBAUGBwgJCgsMDQ4PEA".to_owned(),
            sealed_plaintext: b"opaque-shared-auth-step-up".to_vec(),
            ttl_ms: 120_000,
        }
    }

    fn context() -> ConsumeContext {
        ConsumeContext {
            issuer: ISSUER.to_owned(),
            audience: AUDIENCE.to_owned(),
            recipient_device_id: DEVICE.to_owned(),
            exchange_id: EXCHANGE.to_owned(),
            authenticated_channel: true,
            authority_available: true,
        }
    }

    fn mint_default() -> (ProximityAuthority, ProximityStepUpRequest) {
        let mut auth = authority();
        let request = auth.mint(command(), NOW).expect("mint");
        (auth, request)
    }

    #[test]
    fn mint_binds_issuer_audience_device_exchange_acr_nonce_and_ttl() {
        let (_, request) = mint_default();
        assert_eq!(request.issuer, ISSUER);
        assert_eq!(request.audience, AUDIENCE);
        assert_eq!(request.recipient_device_id, DEVICE);
        assert_eq!(request.exchange_id, EXCHANGE);
        assert_eq!(request.requested_acr, STEP_UP_ACR);
        assert_eq!(
            request.expires_at_unix_ms - request.issued_at_unix_ms,
            120_000
        );
        assert_eq!(request.signature.len(), 86);
        assert_eq!(proximity_delivery_amr(), &[] as &[&str]);
        assert!(!TRANSPORT_NEVER_AMR.contains(&THREEFA_APP_AMR));
    }

    #[test]
    fn consume_succeeds_once_with_threefa_app_completion() {
        let (mut auth, request) = mint_default();
        let result = auth.consume(&request, &context(), NOW + 1_000);
        match result {
            ProximityConsumeResult::Completed { amr, acr, .. } => {
                assert_eq!(amr, vec![THREEFA_APP_AMR.to_owned()]);
                assert_eq!(acr, STEP_UP_ACR);
            }
            other => panic!("expected completed, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_and_replay_are_rejected() {
        let (mut auth, request) = mint_default();
        assert!(matches!(
            auth.consume(&request, &context(), NOW + 1),
            ProximityConsumeResult::Completed { .. }
        ));
        assert_eq!(
            auth.consume(&request, &context(), NOW + 2),
            ProximityConsumeResult::Rejected {
                code: RejectCode::Replay
            }
        );
    }

    #[test]
    fn wrong_issuer_audience_device_and_exchange_are_rejected() {
        let (mut auth, request) = mint_default();
        let mut ctx = context();
        ctx.issuer = "https://other.invalid".to_owned();
        assert_eq!(
            auth.consume(&request, &ctx, NOW + 1),
            reject(RejectCode::WrongIssuer)
        );

        let (mut auth, request) = mint_default();
        let mut ctx = context();
        ctx.audience = "other-rp".to_owned();
        assert_eq!(
            auth.consume(&request, &ctx, NOW + 1),
            reject(RejectCode::WrongAudience)
        );

        let (mut auth, request) = mint_default();
        let mut ctx = context();
        ctx.recipient_device_id = "44444444-4444-4444-8444-444444444444".to_owned();
        assert_eq!(
            auth.consume(&request, &ctx, NOW + 1),
            reject(RejectCode::WrongDevice)
        );

        let (mut auth, request) = mint_default();
        let mut ctx = context();
        ctx.exchange_id = "55555555-5555-4555-8555-555555555555".to_owned();
        assert_eq!(
            auth.consume(&request, &ctx, NOW + 1),
            reject(RejectCode::WrongExchange)
        );
    }

    #[test]
    fn expiry_and_overlong_ttl_are_rejected() {
        let mut auth = authority();
        assert_eq!(
            auth.mint(
                MintCommand {
                    ttl_ms: 120_001,
                    ..command()
                },
                NOW
            )
            .unwrap_err(),
            RejectCode::TtlExceeded
        );
        let (mut auth, request) = mint_default();
        assert_eq!(
            auth.consume(&request, &context(), NOW + 120_000),
            reject(RejectCode::Expired)
        );
    }

    #[test]
    fn tampering_and_digest_mismatch_are_rejected() {
        let (mut auth, mut request) = mint_default();
        request.nonce = "BBBBBBBBBBBBBBBBBBBBBB".to_owned();
        assert_eq!(
            auth.consume(&request, &context(), NOW + 1),
            reject(RejectCode::Tampered)
        );

        let (mut auth, mut request) = mint_default();
        request.signature = "B".repeat(86);
        assert_eq!(
            auth.consume(&request, &context(), NOW + 1),
            reject(RejectCode::Tampered)
        );

        let (mut auth, mut request) = mint_default();
        request.sealed_request_sha256 = "ab".repeat(32);
        assert_eq!(
            auth.consume(&request, &context(), NOW + 1),
            reject(RejectCode::Tampered)
        );
    }

    #[test]
    fn revoked_device_and_key_rotation_fail_closed() {
        let mut auth = authority();
        auth.revoke_device(DEVICE);
        assert_eq!(
            auth.mint(command(), NOW).unwrap_err(),
            RejectCode::RevokedDevice
        );

        let (mut auth, request) = mint_default();
        auth.revoke_device(DEVICE);
        assert_eq!(
            auth.consume(&request, &context(), NOW + 1),
            reject(RejectCode::RevokedDevice)
        );

        let (mut auth, request) = mint_default();
        auth.rotate_key("kid-2", vec![9; 64]);
        assert!(matches!(
            auth.consume(&request, &context(), NOW + 1),
            ProximityConsumeResult::Completed { .. }
        ));

        let (mut auth, request) = mint_default();
        auth.forget_key("kid-1");
        assert_eq!(
            auth.consume(&request, &context(), NOW + 1),
            reject(RejectCode::UnknownKey)
        );
    }

    #[test]
    fn unavailable_authority_is_degraded_not_offline_success() {
        let (mut auth, request) = mint_default();
        let mut ctx = context();
        ctx.authority_available = false;
        let result = auth.consume(&request, &ctx, NOW + 1);
        assert_eq!(
            result,
            ProximityConsumeResult::Degraded {
                reason: "shared-auth unavailable".to_owned()
            }
        );
        assert!(!matches!(result, ProximityConsumeResult::Completed { .. }));
        // The request remains unused so a later available consume can still decide.
        assert!(matches!(
            auth.consume(&request, &context(), NOW + 1),
            ProximityConsumeResult::Completed { .. }
        ));
    }

    #[test]
    fn unauthenticated_channel_cannot_consume() {
        let (mut auth, request) = mint_default();
        let mut ctx = context();
        ctx.authenticated_channel = false;
        assert_eq!(
            auth.consume(&request, &ctx, NOW + 1),
            reject(RejectCode::UnauthenticatedChannel)
        );
    }

    #[test]
    fn debug_and_log_view_redact_request_material() {
        let (_, request) = mint_default();
        let debug = format!("{request:?}");
        assert!(!debug.contains(&request.sealed_request));
        assert!(!debug.contains(&request.signature));
        assert!(!debug.contains(&request.nonce));
        assert!(!debug.contains(&request.sealed_request_sha256));
        let view = serde_json::to_value(request.log_view()).unwrap();
        assert!(view.get("sealed_request").is_none());
        assert!(view.get("signature").is_none());
        assert!(view.get("nonce").is_none());
        assert!(view.get("sealed_request_sha256").is_none());
    }
}
