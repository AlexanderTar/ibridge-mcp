// SPDX-License-Identifier: Apache-2.0

//! Credentials, credential sources and the iCloud host allowlist.

mod call;
mod credentials;
mod hosts;
mod platform;
mod source;

pub use call::{call_credentials, with_call_credentials};
pub use credentials::{
    AuthError, AuthMethod, Credentials, ServiceCheck, ValidationReport, Validator,
};
pub use hosts::is_allowed_host;
pub use source::{CredentialSource, EnvSource, FileSource, KeyringSource};

#[cfg(test)]
mod tests {
    use super::{AuthError, ServiceCheck, ValidationReport, Validator};

    fn require_send<T: Send>(value: T) -> T {
        value
    }

    struct NullValidator;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "null validator returns immediately"
    )]
    impl Validator for NullValidator {
        async fn validate(&self) -> Result<ValidationReport, AuthError> {
            Err(AuthError::Validation)
        }
    }

    fn assert_validator_send<V: Validator + ?Sized>(validator: &V) {
        let _future = require_send(validator.validate());
    }

    #[test]
    fn provider_futures_are_send() {
        assert_validator_send(&NullValidator);
    }

    #[test]
    fn validation_report_any_service_ok() {
        let calendar_only = ValidationReport {
            mail: ServiceCheck::Failed {
                reason: "mail is off".to_owned(),
            },
            calendar: ServiceCheck::Ok,
            contacts: ServiceCheck::Failed {
                reason: "contacts are off".to_owned(),
            },
        };
        assert!(
            calendar_only.any_service_ok(),
            "sign-in succeeds if any service validates"
        );

        let none = ValidationReport {
            mail: ServiceCheck::Failed {
                reason: "no".to_owned(),
            },
            calendar: ServiceCheck::Failed {
                reason: "no".to_owned(),
            },
            contacts: ServiceCheck::Failed {
                reason: "no".to_owned(),
            },
        };
        assert!(
            !none.any_service_ok(),
            "sign-in fails when every service fails"
        );
    }
}
