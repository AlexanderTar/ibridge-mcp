// SPDX-License-Identifier: Apache-2.0

//! The account cap on an open service.

use axum::http::StatusCode;

use super::test_support::{ASP_ALL, Harness, harness_capped};

/// Signs in as `apple_id` from its own address and returns the page's reply.
async fn sign_in(harness: &Harness, apple_id: &str, ip: &str) -> super::test_support::Reply {
    let page = harness
        .get_authorize(&Harness::authorize_path(&[], &[]), ip)
        .await;
    harness.post_form(&page, ip, apple_id, ASP_ALL, None).await
}

fn has_code(reply: &super::test_support::Reply) -> bool {
    reply.status == StatusCode::SEE_OTHER
        && reply
            .location()
            .query_pairs()
            .any(|(name, _)| name == "code")
}

#[tokio::test]
async fn signup_cap_50_enforced() {
    let harness = harness_capped(50).await;
    for n in 0..50 {
        let reply = sign_in(
            &harness,
            &format!("user{n}@icloud.com"),
            &format!("203.0.113.{n}"),
        )
        .await;
        assert!(
            has_code(&reply),
            "account {n} fits under the cap: {}",
            reply.status
        );
    }

    let full = sign_in(&harness, "user50@icloud.com", "198.51.100.1").await;
    assert!(!has_code(&full), "the 51st new account is refused");
    assert_eq!(
        full.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        full.text
    );
    assert!(
        full.text.contains("not taking new accounts"),
        "the page says why: {}",
        full.text
    );

    let again = sign_in(&harness, "user7@icloud.com", "198.51.100.2").await;
    assert!(
        has_code(&again),
        "an existing account still signs in at the cap"
    );
}
