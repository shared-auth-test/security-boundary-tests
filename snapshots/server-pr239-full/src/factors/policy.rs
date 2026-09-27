// Authorization policy for MFA credential-management operations.
//
// Verifying an enrolled factor is an authentication ceremony and remains
// reachable from AAL1. Creating, confirming, or deleting a factor changes the
// credentials capable of producing AAL2, so those operations use a separate
// freshness policy with a narrowly scoped first-factor bootstrap exception.

const FACTOR_MANAGEMENT_MAX_AUTH_AGE_SECS: u64 = 600;
const FACTOR_BOOTSTRAP_MAX_TOKEN_AGE_SECS: u64 = 900;
const FACTOR_MANAGEMENT_CLOCK_SKEW_SECS: u64 = 60;
const TOTP_ENROLLMENT_CONFIRM_WINDOW_SECS: i64 = 900;
const MAX_FACTORS_PER_USER: i64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FactorSecurityState {
    total: i64,
    enabled: i64,
    email_verified: bool,
    phone_verified: bool,
}

impl FactorSecurityState {
    fn has_usable_factor(self, state: &AppState) -> bool {
        self.enabled > 0
            || (self.email_verified && email_otp_is_enabled(state))
            || (self.phone_verified && sms_otp_is_enabled(state))
    }
}

include!("policy/service.rs");
include!("policy/claims.rs");

#[cfg(test)]
include!("policy/tests.rs");
