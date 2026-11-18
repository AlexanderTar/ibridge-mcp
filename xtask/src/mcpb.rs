// SPDX-License-Identifier: Apache-2.0

//! Builds the Claude Desktop extension bundles (`.mcpb`) from dist's archives.
//!
//! One bundle per release target. Each holds `manifest.json`, the `ibridge`
//! binary dist built and the licence. Claude Desktop asks for the Apple ID and
//! the app-specific password and passes them to the server as environment
//! variables, so the password never lands in a config file.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

/// A release target, as dist names it, and the manifest platform it runs on.
#[derive(Debug, Clone, Copy)]
struct Target {
    triple: &'static str,
    platform: Platform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Darwin,
    Linux,
    Win32,
}

impl Platform {
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

    /// dist ships Windows as `.zip` and everything else as `.tar.xz`.
    fn archive_extension(self) -> &'static str {
        match self {
            Self::Win32 => "zip",
            Self::Darwin | Self::Linux => "tar.xz",
        }
    }
}

/// The targets in `dist-workspace.toml`.
const TARGETS: [Target; 5] = [
    Target {
        triple: "aarch64-apple-darwin",
        platform: Platform::Darwin,
    },
    Target {
        triple: "x86_64-apple-darwin",
        platform: Platform::Darwin,
    },
    Target {
        triple: "aarch64-unknown-linux-musl",
        platform: Platform::Linux,
    },
    Target {
        triple: "x86_64-unknown-linux-musl",
        platform: Platform::Linux,
    },
    Target {
        triple: "x86_64-pc-windows-msvc",
        platform: Platform::Win32,
    },
];

/// The target triples a release builds a bundle for.
pub(crate) fn triples() -> impl Iterator<Item = &'static str> {
    TARGETS.iter().map(|target| target.triple)
}

/// Everything that can go wrong while building a bundle.
#[derive(Debug, thiserror::Error)]
pub(crate) enum McpbError {
    #[error("usage: cargo xtask mcpb [--dist DIR] [--out DIR]")]
    Usage,
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{tool} failed: {detail}")]
    Tool { tool: &'static str, detail: String },
    #[error("no {0} in the archive")]
    NoBinary(&'static str),
}

/// The extension manifest, spec 0.3, for one platform.
fn manifest(version: &str, platform: Platform) -> Value {
    let binary = format!("server/{}", platform.binary());
    json!({
        "manifest_version": "0.3",
        "name": "ibridge",
        "display_name": "ibridge",
        "version": version,
        "description": "Read and search iCloud Mail, Calendar, Reminders and Contacts from Claude.",
        "long_description": "Runs on your machine and talks to iCloud with an app-specific password. The password is kept by Claude Desktop and passed to the server as an environment variable.",
        "author": { "name": "Alexander Tar", "url": "https://github.com/AlexanderTar" },
        "repository": { "type": "git", "url": "https://github.com/AlexanderTar/icloud-mcp" },
        "homepage": "https://github.com/AlexanderTar/icloud-mcp",
        "license": "Apache-2.0",
        "keywords": ["icloud", "mail", "calendar", "reminders", "contacts"],
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

/// `mcpb [--dist DIR] [--out DIR]`: reads `ibridge-<triple>` archives from
/// `--dist` (default `target/distrib`) and writes `ibridge-<triple>.mcpb` files
/// to `--out` (default `target/mcpb`). Needs `tar`, `unzip` and `zip` on PATH.
pub(crate) fn run(
    root: &Path,
    mut args: impl Iterator<Item = String>,
) -> Result<Vec<PathBuf>, McpbError> {
    let mut dist = root.join("target/distrib");
    let mut out = root.join("target/mcpb");
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--dist" => &mut dist,
            "--out" => &mut out,
            _ => return Err(McpbError::Usage),
        };
        *slot = PathBuf::from(args.next().ok_or(McpbError::Usage)?);
    }
    fs::create_dir_all(&out)?;
    TARGETS
        .iter()
        .map(|target| bundle(*target, &dist, &out))
        .collect()
}

fn bundle(target: Target, dist: &Path, out: &Path) -> Result<PathBuf, McpbError> {
    let archive = dist.join(format!(
        "ibridge-{}.{}",
        target.triple,
        target.platform.archive_extension()
    ));
    let stage = out.join(format!("stage-{}", target.triple));
    if stage.exists() {
        fs::remove_dir_all(&stage)?;
    }
    let unpacked = stage.join("unpacked");
    let server = stage.join("bundle/server");
    fs::create_dir_all(&unpacked)?;
    fs::create_dir_all(&server)?;

    match target.platform {
        Platform::Win32 => tool(
            "unzip",
            Command::new("unzip")
                .arg("-q")
                .arg(&archive)
                .arg("-d")
                .arg(&unpacked),
        )?,
        Platform::Darwin | Platform::Linux => tool(
            "tar",
            Command::new("tar")
                .arg("-xJf")
                .arg(&archive)
                .arg("-C")
                .arg(&unpacked),
        )?,
    }
    let binary = find(&unpacked, target.platform.binary())?
        .ok_or(McpbError::NoBinary(target.platform.binary()))?;
    fs::copy(&binary, server.join(target.platform.binary()))?;
    if let Some(licence) = find(&unpacked, "LICENSE")? {
        fs::copy(licence, stage.join("bundle/LICENSE"))?;
    }
    let mut text =
        serde_json::to_string_pretty(&manifest(env!("CARGO_PKG_VERSION"), target.platform))
            .map_err(io::Error::other)?;
    text.push('\n');
    fs::write(stage.join("bundle/manifest.json"), text)?;

    let bundle = out.join(format!("ibridge-{}.mcpb", target.triple));
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

/// Finds the first file called `name` under `dir`, depth first.
fn find(dir: &Path, name: &str) -> io::Result<Option<PathBuf>> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            if let Some(found) = find(&path, name)? {
                return Ok(Some(found));
            }
        } else if path.file_name().is_some_and(|file| file == name) {
            return Ok(Some(path));
        }
    }
    Ok(None)
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
