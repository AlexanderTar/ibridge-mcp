// SPDX-License-Identifier: Apache-2.0

//! JSON logs for the hosted server.
//!
//! Railway keeps what the process prints, so a line must never carry a secret or
//! a message. Nothing in this workspace formats a request body, a header or a tool
//! result; the request log in `oauth` records only the method, the redacted path and
//! the outcome. Dependencies are another matter: `rmcp` logs every tool result at
//! `debug` and `trace`. So only our own crates and the request log get the level
//! the operator picked; every other crate is held to `warn`.

use std::fmt;

use serde_json::{Map, Value};
use tracing::span::Record;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer as _;
use tracing_subscriber::field::RecordFields;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime as _, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields, MakeWriter};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::registry::LookupSpan;

use crate::store::RedactingFields;

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

/// Formats a span's fields as one JSON object with every value scrubbed.
///
/// `tracing-subscriber`'s own JSON event format ignores a custom field formatter and writes
/// values as they are, so this formatter owns both event and span fields.
struct ScrubbedFields;

impl<'writer> FormatFields<'writer> for ScrubbedFields {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        let mut map = Map::new();
        fields.record(&mut RedactingFields::new(&mut map));
        write!(writer, "{}", Value::Object(map))
    }

    /// A later `span.record` merges into the object already there, so it stays one JSON value.
    fn add_fields(
        &self,
        current: &'writer mut FormattedFields<Self>,
        fields: &Record<'_>,
    ) -> fmt::Result {
        let mut map = serde_json::from_str(&current.fields).unwrap_or_default();
        fields.record(&mut RedactingFields::new(&mut map));
        current.fields = Value::Object(map).to_string();
        Ok(())
    }
}

/// One JSON object per event: time, level, scrubbed fields, target and the scrubbed spans around it.
struct ScrubbedJson;

impl<S> FormatEvent<S, ScrubbedFields> for ScrubbedJson
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn format_event(
        &self,
        context: &FmtContext<'_, S, ScrubbedFields>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut timestamp = String::new();
        SystemTime.format_time(&mut Writer::new(&mut timestamp))?;
        let mut fields = Map::new();
        event.record(&mut RedactingFields::new(&mut fields));
        let meta = event.metadata();
        let mut line = Map::new();
        line.insert("timestamp".to_owned(), timestamp.into());
        line.insert("level".to_owned(), meta.level().as_str().into());
        line.insert("fields".to_owned(), Value::Object(fields));
        line.insert("target".to_owned(), meta.target().into());
        if let Some(scope) = context.event_scope() {
            let spans: Vec<Value> = scope
                .from_root()
                .map(|span| {
                    let mut entry = span
                        .extensions()
                        .get::<FormattedFields<ScrubbedFields>>()
                        .and_then(|fields| serde_json::from_str::<Map<String, Value>>(fields).ok())
                        .unwrap_or_default();
                    entry.insert("name".to_owned(), span.name().into());
                    Value::Object(entry)
                })
                .collect();
            line.insert("spans".to_owned(), Value::Array(spans));
        }
        writeln!(writer, "{}", Value::Object(line))
    }
}

/// A subscriber that writes one JSON object per event to `writer`.
///
/// Our crates log at `level` and above. Every other crate logs `warn` and above. Every
/// field value, on events and spans, goes through [`RedactingFields`] before it is written.
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
            .fmt_fields(ScrubbedFields)
            .event_format(ScrubbedJson)
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

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex, PoisonError};

    use serde_json::Value;
    use tracing::Level;
    use tracing_subscriber::fmt::MakeWriter;

    use super::json_subscriber;

    /// Collects what the subscriber writes.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl MakeWriter<'_> for Captured {
        type Writer = Self;

        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn json_logs_redact_secret_fields() {
        let logs = Captured::default();
        let subscriber = json_subscriber(logs.clone(), Level::TRACE);
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("http", path = "/cb?code=ibc_spansecret&state=x");
            let _entered = span.enter();
            tracing::info!(
                header = "Authorization: Bearer iba_headersecret",
                query = %"access_token=ibf_querysecret&other=1",
                "signed in with token=ibr_messagesecret"
            );
        });
        let bytes = logs
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let text = String::from_utf8(bytes).expect("utf8 logs");
        assert!(!text.is_empty(), "the event was logged at all");
        for line in text.lines() {
            serde_json::from_str::<Value>(line)
                .unwrap_or_else(|error| panic!("log lines are JSON ({error}): {line}"));
        }
        for secret in [
            "iba_headersecret",
            "ibf_querysecret",
            "ibr_messagesecret",
            "ibc_spansecret",
        ] {
            assert!(!text.contains(secret), "{secret} reached the log:\n{text}");
        }
        assert!(
            text.contains("[REDACTED]"),
            "the values were scrubbed, not dropped:\n{text}"
        );
        assert!(
            text.contains("signed in with"),
            "the rest of the message stays:\n{text}"
        );
        assert!(
            text.contains("/cb"),
            "the rest of the span field stays:\n{text}"
        );
    }

    #[test]
    fn span_fields_recorded_later_stay_valid_json_and_scrubbed() {
        let logs = Captured::default();
        let subscriber = json_subscriber(logs.clone(), Level::TRACE);
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "http",
                path = "/cb",
                outcome = tracing::field::Empty,
                detail = tracing::field::Empty
            );
            span.record("outcome", "token=ibr_latesecret");
            span.record("detail", "kept");
            let _entered = span.enter();
            tracing::info!("inside");
        });
        let bytes = logs
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let text = String::from_utf8(bytes).expect("utf8 logs");
        assert!(
            !text.contains("ibr_latesecret"),
            "secret reached the log:\n{text}"
        );
        let line: Value =
            serde_json::from_str(text.lines().next().expect("one line")).expect("log line is JSON");
        let span = &line["spans"][0];
        assert_eq!(
            span["path"], "/cb",
            "the field set at creation stays:\n{text}"
        );
        assert_eq!(span["detail"], "kept", "a later record is kept:\n{text}");
        assert!(
            span["outcome"]
                .as_str()
                .is_some_and(|v| v.contains("[REDACTED]")),
            "a later record is scrubbed:\n{text}"
        );
    }
}
