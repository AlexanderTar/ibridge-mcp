// SPDX-License-Identifier: Apache-2.0

//! JSON logs for the hosted server.
//!
//! Railway keeps what the process prints, so a line must never carry a secret or
//! a message. Nothing in this workspace formats a request body, a header or a tool
//! result; the request log in `oauth` records only the method, the redacted path and
//! the outcome. Dependencies are another matter: `rmcp` logs every tool result at
//! `debug` and `trace`. So only our own crates and the request log get the level
//! the operator picked; every other crate is held to `warn`.

use tracing::Level;
use tracing::Subscriber;
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;

/// The crates that may log at the operator's level.
const OURS: [&str; 10] = [
    "ibridge",
    "ibridge_auth",
    "ibridge_calendar",
    "ibridge_contacts",
    "ibridge_core",
    "ibridge_dav",
    "ibridge_hosted",
    "ibridge_mail",
    "ibridge_server",
    "tower_http::trace",
];

/// A subscriber that writes one JSON object per event to `writer`.
///
/// Our crates log at `level` and above. Every other crate logs `warn` and above.
pub fn json_subscriber<W>(writer: W, level: Level) -> impl Subscriber + Send + Sync
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let filter = OURS.into_iter().fold(
        Targets::new().with_default(Level::WARN),
        |filter, target| filter.with_target(target, level),
    );
    tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(writer)
            .with_ansi(false)
            .with_filter(filter),
    )
}

/// Sends JSON logs to stdout, which is where Railway reads them. `IBRIDGE_LOG` sets the level.
///
/// A second call, or a subscriber set earlier, is left alone.
pub fn init() {
    let level = std::env::var("IBRIDGE_LOG")
        .ok()
        .and_then(|value| value.parse::<Level>().ok())
        .unwrap_or(Level::INFO);
    let _already_set =
        tracing::subscriber::set_global_default(json_subscriber(std::io::stdout, level));
}
