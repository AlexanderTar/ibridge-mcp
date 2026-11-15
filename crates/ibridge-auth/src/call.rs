// SPDX-License-Identifier: Apache-2.0

//! The password a hosted call opened, visible to the code that runs that call.
//!
//! A hosted server opens the password from the caller's token for one tool call.
//! Code that needs it, such as a pool opening a new connection, reads it here
//! instead of keeping a copy of its own.

use std::future::Future;
use std::sync::Arc;

use crate::credentials::Credentials;

tokio::task_local! {
    static CALL: Arc<Credentials>;
}

/// Runs `work` with `credentials` visible to [`call_credentials`].
///
/// The scope ends with `work`. A task `work` spawns does not inherit it.
pub async fn with_call_credentials<F: Future>(credentials: Arc<Credentials>, work: F) -> F::Output {
    CALL.scope(credentials, work).await
}

/// Passes the current call's credentials to `read`.
///
/// Returns `None` outside [`with_call_credentials`].
pub fn call_credentials<T>(read: impl FnOnce(&Credentials) -> T) -> Option<T> {
    CALL.try_with(|credentials| read(credentials)).ok()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ibridge_core::AppleId;

    use super::{call_credentials, with_call_credentials};
    use crate::credentials::Credentials;

    #[tokio::test]
    async fn credentials_are_visible_only_inside_the_call() {
        let apple_id = AppleId::try_from("ada@icloud.com").expect("apple id");
        let credentials = Arc::new(Credentials::new(apple_id, "pw-1"));
        assert!(
            call_credentials(|_| ()).is_none(),
            "nothing before the call"
        );

        let seen = with_call_credentials(Arc::clone(&credentials), async {
            call_credentials(|inside| inside.with_secret(ToOwned::to_owned))
        })
        .await;

        assert_eq!(seen.as_deref(), Some("pw-1"), "the call reads its password");
        assert!(call_credentials(|_| ()).is_none(), "nothing after the call");
        assert_eq!(
            Arc::strong_count(&credentials),
            1,
            "the scope gave back its copy"
        );
    }
}
