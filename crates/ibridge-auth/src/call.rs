// SPDX-License-Identifier: Apache-2.0

//! The password a hosted call opened, visible to the code that runs that call.
//!
//! A hosted server opens the password from the caller's token for one tool call.
//! Code that needs it, such as a pool opening a new connection, reads it here
//! instead of keeping a copy of its own.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::credentials::Credentials;

/// What iCloud said to the logins one call made.
///
/// A server counts rejected logins toward revoking a credential, so it needs to
/// know what the server answered, not only that the call failed.
#[derive(Debug, Default)]
pub struct LoginLog {
    rejected: AtomicBool,
    accepted: AtomicBool,
}

impl LoginLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a login in this call was refused for its password.
    #[must_use]
    pub fn rejected(&self) -> bool {
        self.rejected.load(Ordering::SeqCst)
    }

    /// Whether a login in this call was accepted.
    #[must_use]
    pub fn accepted(&self) -> bool {
        self.accepted.load(Ordering::SeqCst)
    }
}

struct Call {
    credentials: Arc<Credentials>,
    log: Arc<LoginLog>,
}

tokio::task_local! {
    static CALL: Call;
}

/// Runs `work` with `credentials` visible to [`call_credentials`] and logins noted in `log`.
///
/// The scope ends with `work`. A task `work` spawns does not inherit it.
pub async fn with_call_credentials<F: Future>(
    credentials: Arc<Credentials>,
    log: Arc<LoginLog>,
    work: F,
) -> F::Output {
    CALL.scope(Call { credentials, log }, work).await
}

/// Passes the current call's credentials to `read`.
///
/// Returns `None` outside [`with_call_credentials`].
pub fn call_credentials<T>(read: impl FnOnce(&Credentials) -> T) -> Option<T> {
    CALL.try_with(|call| read(&call.credentials)).ok()
}

/// What a server said to a login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoginVerdict {
    /// The server accepted the password.
    Accepted,
    /// The server refused the password.
    Rejected,
}

/// Notes the result of a login the current call made. Does nothing outside a call.
///
/// Report only the server's verdict on the password, not a network failure or throttling.
pub fn report_login(verdict: LoginVerdict) {
    let _ = CALL.try_with(|call| {
        let flag = match verdict {
            LoginVerdict::Accepted => &call.log.accepted,
            LoginVerdict::Rejected => &call.log.rejected,
        };
        flag.store(true, Ordering::SeqCst);
    });
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ibridge_core::AppleId;

    use super::{LoginLog, LoginVerdict, call_credentials, report_login, with_call_credentials};
    use crate::credentials::Credentials;

    #[tokio::test]
    async fn credentials_are_visible_only_inside_the_call() {
        let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
        let credentials = Arc::new(Credentials::new(apple_id, "pw-1"));
        assert!(
            call_credentials(|_| ()).is_none(),
            "nothing before the call"
        );

        let log = Arc::new(LoginLog::new());
        let seen = with_call_credentials(Arc::clone(&credentials), Arc::clone(&log), async {
            report_login(LoginVerdict::Rejected);
            call_credentials(|inside| inside.with_secret(ToOwned::to_owned))
        })
        .await;
        report_login(LoginVerdict::Accepted);

        assert_eq!(seen.as_deref(), Some("pw-1"), "the call reads its password");
        assert!(log.rejected(), "a login reported inside the call is logged");
        assert!(!log.accepted(), "a login reported outside the call is not");
        assert!(call_credentials(|_| ()).is_none(), "nothing after the call");
        assert_eq!(
            Arc::strong_count(&credentials),
            1,
            "the scope gave back its copy"
        );
    }
}
