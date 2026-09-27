#![forbid(unsafe_code)]

//! Pure admission checks for the executable consumer policy.
//!
//! Parsing `.shared-auth.toml` is not enough: request surfaces must consume the
//! resolved policy rather than admitting it at startup and then discarding it.
//! This module is intentionally persistence- and transport-free so HTTP, BEAM,
//! proxy, CLI, desktop, and function adapters can all enforce the same decision.

use thiserror::Error;

use crate::config::{AuthPage, FactorMethod, ResolvedSharedAuthConfig};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumerPolicyAction {
    RenderPage(AuthPage),
    UseTwoFactor(FactorMethod),
    UseThreeFactor(FactorMethod),
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConsumerPolicyDenied {
    #[error("authentication page is disabled by consumer policy: {0:?}")]
    PageDisabled(AuthPage),
    #[error("two-factor method is disabled by consumer policy: {0:?}")]
    TwoFactorMethodDisabled(FactorMethod),
    #[error("three-factor authentication is disabled by consumer policy")]
    ThreeFactorDisabled,
    #[error("three-factor method is disabled by consumer policy: {0:?}")]
    ThreeFactorMethodDisabled(FactorMethod),
}

impl ResolvedSharedAuthConfig {
    /// Admit one request-surface action against the immutable policy snapshot
    /// resolved during startup.
    ///
    /// This is an allow-list operation. A method being implemented by the
    /// runtime does not make it policy-admitted, and a three-factor method does
    /// not silently count as a two-factor method (or vice versa).
    pub fn require_consumer_action(
        &self,
        action: ConsumerPolicyAction,
    ) -> Result<(), ConsumerPolicyDenied> {
        match action {
            ConsumerPolicyAction::RenderPage(page) => {
                if self.pages.show.contains(&page) {
                    return Ok(());
                }
                return Err(ConsumerPolicyDenied::PageDisabled(page));
            }
            ConsumerPolicyAction::UseTwoFactor(method) => {
                if self.factors.two_factor.methods.contains(&method) {
                    return Ok(());
                }
                return Err(ConsumerPolicyDenied::TwoFactorMethodDisabled(method));
            }
            ConsumerPolicyAction::UseThreeFactor(method) => {
                if !self.factors.three_factor.enabled {
                    return Err(ConsumerPolicyDenied::ThreeFactorDisabled);
                }
                if self.factors.three_factor.methods.contains(&method) {
                    return Ok(());
                }
                return Err(ConsumerPolicyDenied::ThreeFactorMethodDisabled(method));
            }
        }
    }

    #[must_use]
    pub fn consumer_action_is_admitted(&self, action: ConsumerPolicyAction) -> bool {
        return self.require_consumer_action(action).is_ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::central_config::central_shared_auth_policy;
    use crate::config::{
        Compatibility, ExactCompatibility, FactorsPolicyOverlay, PagesPolicyOverlay,
        SharedAuthConfigOverlay, SharedAuthDefaults, TwoFactorPolicyOverlay,
    };

    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn central_policy_admits_only_declared_pages() {
        let policy = central_shared_auth_policy().expect("central policy must resolve");

        assert!(
            policy.consumer_action_is_admitted(ConsumerPolicyAction::RenderPage(AuthPage::SignIn,))
        );
        assert!(!policy
            .consumer_action_is_admitted(ConsumerPolicyAction::RenderPage(AuthPage::SignUp,)));
    }

    #[test]
    fn two_factor_methods_are_an_allow_list() {
        let policy = central_shared_auth_policy().expect("central policy must resolve");

        assert!(policy
            .consumer_action_is_admitted(ConsumerPolicyAction::UseTwoFactor(FactorMethod::Totp,)));
        assert!(
            policy.consumer_action_is_admitted(ConsumerPolicyAction::UseTwoFactor(
                FactorMethod::Passkey,
            ))
        );
        assert!(
            !policy.consumer_action_is_admitted(ConsumerPolicyAction::UseTwoFactor(
                FactorMethod::EmailOtp,
            ))
        );
        assert!(
            !policy.consumer_action_is_admitted(ConsumerPolicyAction::UseTwoFactor(
                FactorMethod::SmsOtp,
            ))
        );
    }

    #[test]
    fn disabled_three_factor_policy_cannot_be_bypassed_by_a_listed_method() {
        let policy = central_shared_auth_policy().expect("central policy must resolve");

        assert_eq!(
            policy
                .require_consumer_action(ConsumerPolicyAction::UseThreeFactor(FactorMethod::Totp,)),
            Err(ConsumerPolicyDenied::ThreeFactorDisabled),
        );
    }

    #[test]
    fn consumer_overlay_changes_the_executable_admission_result() {
        let overlay = SharedAuthConfigOverlay {
            schema_version: 1,
            compatibility: Compatibility::Exact(ExactCompatibility {
                repository: crate::config::SHARED_AUTH_INTERFACES_REPOSITORY.to_owned(),
                commit: REVISION.to_owned(),
            }),
            factors: Some(FactorsPolicyOverlay {
                two_factor: Some(TwoFactorPolicyOverlay {
                    required: Some(true),
                    methods: Some(vec![FactorMethod::Passkey, FactorMethod::EmailOtp]),
                }),
                three_factor: None,
            }),
            pages: Some(PagesPolicyOverlay {
                show: Some(vec![AuthPage::SignIn, AuthPage::SignUp, AuthPage::Recovery]),
            }),
            styling: None,
        };
        let policy = overlay
            .resolve(SharedAuthDefaults::default())
            .expect("overlay must resolve");

        assert!(
            policy.consumer_action_is_admitted(ConsumerPolicyAction::RenderPage(AuthPage::SignUp,))
        );
        assert!(
            policy.consumer_action_is_admitted(ConsumerPolicyAction::UseTwoFactor(
                FactorMethod::EmailOtp,
            ))
        );
        assert!(!policy
            .consumer_action_is_admitted(ConsumerPolicyAction::UseTwoFactor(FactorMethod::Totp,)));
    }
}
