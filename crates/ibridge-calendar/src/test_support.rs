// SPDX-License-Identifier: Apache-2.0

//! Shared setup for the provider tests.

use ibridge_auth::Credentials;
use ibridge_core::AppleId;
use ibridge_dav::DavClient;
use ibridge_testkit::dav_mock::FakeCalDav;

use crate::CalDavProvider;

/// A fake server with one event calendar, `work`, and a provider on it.
pub(crate) async fn setup() -> (FakeCalDav, CalDavProvider) {
    let fake = FakeCalDav::start().await;
    fake.add_collection("work", "Work", &["VEVENT"]);
    let credentials = Credentials::new(
        AppleId::try_from("ada@icloud.com").expect("primary address"),
        "test-secret",
    );
    let client = DavClient::for_test_server(credentials, &fake.base_url()).expect("test client");
    (fake, CalDavProvider::new(client))
}

/// Wraps component text, with `\n` line ends, into a `VCALENDAR` object.
pub(crate) fn vcalendar(body: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//ibridge//test//EN\r\n{}\r\nEND:VCALENDAR\r\n",
        body.replace('\n', "\r\n")
    )
}
