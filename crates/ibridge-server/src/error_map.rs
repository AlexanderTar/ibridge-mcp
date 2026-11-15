// SPDX-License-Identifier: Apache-2.0

//! Maps [`ibridge_core::CoreError`] onto MCP errors.

use std::borrow::Cow;

use ibridge_core::CoreError;
use rmcp::model::ErrorData;

/// A provider failure the tool layer can return.
#[derive(Debug)]
#[non_exhaustive]
pub enum MappedError {
    /// A JSON-RPC error. The message has no secrets and no raw server text.
    Rpc(ErrorData),
    /// A tool error the model can act on. Not a protocol failure.
    Tool(Cow<'static, str>),
}

/// Turns a provider error into an MCP error.
///
/// Bad input is `invalid_params`. Not found and conflict are tool errors that
/// say what to do next. Authentication tells the user to run `ibridge login`.
/// Every other failure is an internal error whose message drops protocol text.
#[must_use]
pub fn map_core_error(error: &CoreError) -> MappedError {
    match error {
        CoreError::InvalidInput(message) => {
            MappedError::Rpc(ErrorData::invalid_params(message.clone(), None))
        }
        CoreError::NotFound => {
            MappedError::Tool(Cow::Borrowed("not found; check the id and fetch it again"))
        }
        CoreError::Conflict => {
            MappedError::Tool(Cow::Borrowed("changed since you read it; fetch it again"))
        }
        CoreError::Auth => {
            MappedError::Tool(Cow::Borrowed("authentication failed; run ibridge login"))
        }
        // Protocol text, and every other provider failure, stay off the wire.
        _ => MappedError::Rpc(ErrorData::internal_error("internal error", None)),
    }
}

#[cfg(test)]
mod tests {
    use ibridge_core::CoreError;
    use rmcp::model::ErrorCode;

    use super::{MappedError, map_core_error};

    #[test]
    fn error_map_hides_server_text() {
        let raw = "NO [ALERT] password=hunter2 imap banner from the server";
        let mapped = map_core_error(&CoreError::Protocol(raw.to_owned()));
        let MappedError::Rpc(data) = mapped else {
            panic!("a protocol failure is an internal error");
        };
        let rendered = format!("{data} {:?}", data.data);
        assert!(
            !rendered.contains("hunter2") && !rendered.contains("imap banner"),
            "raw server text leaked into the MCP error: {rendered}"
        );
        assert_eq!(
            data.code,
            ErrorCode::INTERNAL_ERROR,
            "a protocol failure is an internal error, got {}",
            data.code.0
        );
    }
}
