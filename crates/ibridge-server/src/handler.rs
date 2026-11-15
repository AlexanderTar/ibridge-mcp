// SPDX-License-Identifier: Apache-2.0

//! Server handler. Tool methods are registered with the mail tools.

/// MCP server for one account.
///
/// The tool router is added with the mail tools. `read_only` is the local
/// flag that hides write tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IbridgeServer {
    read_only: bool,
}

impl IbridgeServer {
    /// Hides write tools from `tools/list`.
    #[must_use]
    pub const fn read_only() -> Self {
        Self { read_only: true }
    }

    /// Shows read and write tools.
    #[must_use]
    pub const fn read_write() -> Self {
        Self { read_only: false }
    }

    /// Whether write tools are hidden.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }
}
