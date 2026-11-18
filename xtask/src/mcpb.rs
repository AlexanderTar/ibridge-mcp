// SPDX-License-Identifier: Apache-2.0

//! Builds a Claude Desktop extension bundle (`.mcpb`) from your own build.
//!
//! The bundle holds `manifest.json`, the `ibridge` binary you built and the
//! licence. Claude Desktop asks for the Apple ID and the app-specific password
//! and passes them to the server as environment variables, so the password
//! never lands in a config file.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

/// The platform a bundle runs on: the one `cargo xtask mcpb` itself runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Darwin,
    Linux,
    Win32,
}

impl Platform {
    fn host() -> Self {
        if cfg!(target_os = "macos") {
            Self::Darwin
        } else if cfg!(windows) {
            Self::Win32
        } else {
            Self::Linux
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Darwin => "darwin",
            Self::Linux => "linux",
            Self::Win32 => "win32",
        }
    }

    fn binary(self) -> &'static str {
        match self {
            Self::Win32 => "ibridge.exe",
            Self::Darwin | Self::Linux => "ibridge",
        }
    }
}

/// Everything that can go wrong while building a bundle.
#[derive(Debug, thiserror::Error)]
pub(crate) enum McpbError {
    #[error("usage: cargo xtask mcpb [--binary PATH] [--out DIR]")]
    Usage,
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{tool} failed: {detail}")]
    Tool { tool: &'static str, detail: String },
    #[error("{0} not found; build it first with `cargo build --release -p ibridge`")]
    NoBinary(PathBuf),
}

/// The extension manifest, spec 0.3, for one platform.
fn manifest(version: &str, platform: Platform) -> Value {
    let binary = format!("server/{}", platform.binary());
    json!({
        "manifest_version": "0.3",
        "name": "ibridge",
        "display_name": "iBridge",
        "version": version,
        "description": "Read, search and manage iCloud Mail, Calendar and Contacts from Claude.",
        "long_description": "Runs on your machine and talks to iCloud with an app-specific password. The password is kept by Claude Desktop and passed to the server as an environment variable.",
        "author": { "name": "Alexander Tar", "url": "https://github.com/AlexanderTar" },
        "repository": { "type": "git", "url": "https://github.com/AlexanderTar/icloud-mcp" },
        "homepage": "https://ibridge.fyi",
        "license": "Apache-2.0",
        "keywords": ["icloud", "mail", "calendar", "contacts"],
        "server": {
            "type": "binary",
            "entry_point": binary,
            "mcp_config": {
                "command": "${__dirname}/server/ibridge",
                "args": ["serve", "--stdio"],
                "env": {
                    "IBRIDGE_APPLE_ID": "${user_config.apple_id}",
                    "IBRIDGE_APP_PASSWORD": "${user_config.app_password}"
                },
                "platform_overrides": {
                    "win32": { "command": "${__dirname}/server/ibridge.exe" }
                }
            }
        },
        "user_config": {
            "apple_id": {
                "type": "string",
                "title": "Apple ID",
                "description": "The email address you sign in to iCloud with.",
                "required": true
            },
            "app_password": {
                "type": "string",
                "title": "App-specific password",
                "description": "Create one at account.apple.com under Sign-In and Security. It is not your Apple ID password.",
                "sensitive": true,
                "required": true
            }
        },
        "compatibility": { "platforms": [platform.name()] }
    })
}

/// `mcpb [--binary PATH] [--out DIR]`: packs your own build of `ibridge` into
/// `ibridge-<version>-<platform>.mcpb`. `--binary` defaults to
/// `target/release/ibridge` and `--out` to `target/mcpb`. Needs `zip` on PATH.
pub(crate) fn run(
    root: &Path,
    mut args: impl Iterator<Item = String>,
) -> Result<Vec<PathBuf>, McpbError> {
    let platform = Platform::host();
    let mut binary = root.join("target/release").join(platform.binary());
    let mut out = root.join("target/mcpb");
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--binary" => &mut binary,
            "--out" => &mut out,
            _ => return Err(McpbError::Usage),
        };
        *slot = PathBuf::from(args.next().ok_or(McpbError::Usage)?);
    }
    if !binary.is_file() {
        return Err(McpbError::NoBinary(binary));
    }
    fs::create_dir_all(&out)?;
    Ok(vec![bundle(root, platform, &binary, &out)?])
}

fn bundle(
    root: &Path,
    platform: Platform,
    binary: &Path,
    out: &Path,
) -> Result<PathBuf, McpbError> {
    let stage = out.join("stage");
    if stage.exists() {
        fs::remove_dir_all(&stage)?;
    }
    let server = stage.join("bundle/server");
    fs::create_dir_all(&server)?;
    fs::copy(binary, server.join(platform.binary()))?;
    fs::copy(root.join("LICENSE"), stage.join("bundle/LICENSE"))?;
    let mut text = serde_json::to_string_pretty(&manifest(env!("CARGO_PKG_VERSION"), platform))
        .map_err(io::Error::other)?;
    text.push('\n');
    fs::write(stage.join("bundle/manifest.json"), text)?;

    let bundle = out.join(format!(
        "ibridge-{}-{}.mcpb",
        env!("CARGO_PKG_VERSION"),
        platform.name()
    ));
    if bundle.exists() {
        fs::remove_file(&bundle)?;
    }
    tool(
        "zip",
        Command::new("zip")
            .current_dir(stage.join("bundle"))
            .args(["-X", "-q", "-r"])
            .arg(&bundle)
            .arg("."),
    )?;
    fs::remove_dir_all(&stage)?;
    Ok(bundle)
}

fn tool(name: &'static str, command: &mut Command) -> Result<(), McpbError> {
    let output = command.output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(McpbError::Tool {
            tool: name,
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_snapshot_per_platform() {
        for platform in [Platform::Darwin, Platform::Linux, Platform::Win32] {
            insta::assert_json_snapshot!(
                format!("manifest_{}", platform.name()),
                manifest("0.1.0", platform)
            );
        }
    }

    #[test]
    fn manifest_passes_the_password_as_a_sensitive_env_value() {
        let manifest = manifest("0.1.0", Platform::Darwin);
        assert_eq!(manifest["server"]["type"], "binary", "binary server type");
        assert_eq!(
            manifest["server"]["mcp_config"]["env"]["IBRIDGE_APP_PASSWORD"],
            "${user_config.app_password}",
            "the password reaches the server through the environment"
        );
        assert_eq!(
            manifest["user_config"]["app_password"]["sensitive"], true,
            "Claude Desktop masks and keeps the password"
        );
    }

    #[test]
    fn manifest_name_matches_the_server_name() {
        assert_eq!(manifest("0.1.0", Platform::Linux)["name"], "ibridge");
    }
}
