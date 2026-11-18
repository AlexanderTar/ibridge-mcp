// SPDX-License-Identifier: Apache-2.0

//! Checks `server.json`, the listing for the official MCP Registry.
//!
//! `check` validates it against the registry's JSON schema (vendored in
//! `xtask/schemas`) and ties it to the rest of the repository: the Dockerfile
//! label and the README line the registry reads to prove ownership, the release
//! URLs of the `.mcpb` bundles, the image tag and the hosted URL. `fill` writes
//! the SHA-256 of the released bundles into it. See `docs/release.md`.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::mcpb;

/// The schema the registry validates against, from its `$id` URL.
const SCHEMA: &str = include_str!("../schemas/server.schema.json");

/// What `server.json` holds until `fill` writes the real hash. The schema needs
/// 64 hex digits, so the placeholder is all zeros.
pub(crate) const PLACEHOLDER_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

const SERVER_NAME: &str = "io.github.AlexanderTar/ibridge";
const RELEASE_BASE: &str = "https://github.com/AlexanderTar/icloud-mcp/releases/download";
const IMAGE: &str = "ghcr.io/alexandertar/ibridge";
const REMOTE_URL: &str = "https://mcp.ibridge.fyi/mcp";
const LABEL: &str = "io.modelcontextprotocol.server.name";

/// Everything that can go wrong while checking or filling `server.json`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RegistryError {
    #[error("usage: cargo xtask registry check [--release] | cargo xtask registry fill --mcpb DIR")]
    Usage,
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("server.json is not JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("server.json has problems:\n{}", .0.join("\n"))]
    Invalid(Vec<String>),
}

/// What a passing check found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Checked {
    /// `fileSha256` values that are still the placeholder.
    pub(crate) placeholders: usize,
}

/// `registry check [--release]` or `registry fill --mcpb DIR`.
pub(crate) fn run(
    root: &Path,
    mut args: impl Iterator<Item = String>,
) -> Result<String, RegistryError> {
    match args.next().as_deref() {
        Some("check") => {
            let release = match args.next().as_deref() {
                None => false,
                Some("--release") => true,
                Some(_) => return Err(RegistryError::Usage),
            };
            let checked = check(root)?;
            if release && checked.placeholders > 0 {
                return Err(RegistryError::Invalid(vec![format!(
                    "{} fileSha256 value(s) are still the placeholder; run `cargo xtask registry fill`",
                    checked.placeholders
                )]));
            }
            Ok(format!(
                "server.json ok ({} placeholder hash(es))",
                checked.placeholders
            ))
        }
        Some("fill") => match (args.next().as_deref(), args.next()) {
            (Some("--mcpb"), Some(dir)) => {
                let filled = fill(root, Path::new(&dir))?;
                Ok(format!("wrote {filled} hash(es) into server.json"))
            }
            _ => Err(RegistryError::Usage),
        },
        _ => Err(RegistryError::Usage),
    }
}

fn server_json_path(root: &Path) -> PathBuf {
    root.join("server.json")
}

/// Validates `server.json` under `root` and everything it has to agree with.
pub(crate) fn check(root: &Path) -> Result<Checked, RegistryError> {
    let text = fs::read_to_string(server_json_path(root))?;
    let server: Value = serde_json::from_str(&text)?;
    let mut problems = schema_problems(&server);

    let version = env!("CARGO_PKG_VERSION");
    expect_eq(&mut problems, "name", &server["name"], SERVER_NAME);
    expect_eq(&mut problems, "version", &server["version"], version);
    expect_eq(&mut problems, "$schema", &server["$schema"], &schema_id());

    match fs::read_to_string(root.join("Dockerfile")) {
        Ok(dockerfile) => {
            let label = format!("LABEL {LABEL}=\"{SERVER_NAME}\"");
            if !dockerfile.lines().any(|line| line.trim() == label) {
                problems.push(format!("Dockerfile has no line `{label}`"));
            }
        }
        Err(error) => problems.push(format!("Dockerfile: {error}")),
    }
    match fs::read_to_string(root.join("README.md")) {
        Ok(readme) => {
            if !has_mcp_name(&readme, SERVER_NAME) {
                problems.push(format!("README.md has no `mcp-name: {SERVER_NAME}` line"));
            }
        }
        Err(error) => problems.push(format!("README.md: {error}")),
    }

    let packages = server["packages"].as_array().map_or(&[][..], Vec::as_slice);
    let mut placeholders = 0;
    let mut bundles = Vec::new();
    for package in packages {
        match package["registryType"].as_str() {
            Some("mcpb") => {
                bundles.push(
                    package["identifier"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                );
                if package["fileSha256"] == PLACEHOLDER_SHA256 {
                    placeholders += 1;
                }
            }
            Some("oci") => expect_eq(
                &mut problems,
                "oci identifier",
                &package["identifier"],
                &format!("{IMAGE}:{version}"),
            ),
            _ => problems.push("a package is neither mcpb nor oci".to_owned()),
        }
    }
    let mut expected: Vec<String> = mcpb::triples()
        .map(|triple| format!("{RELEASE_BASE}/v{version}/ibridge-{triple}.mcpb"))
        .collect();
    expected.sort();
    bundles.sort();
    if bundles != expected {
        problems.push(format!(
            "mcpb identifiers are {bundles:?}, expected one per release target: {expected:?}"
        ));
    }

    let remotes = server["remotes"].as_array().map_or(&[][..], Vec::as_slice);
    let hosted = remotes
        .iter()
        .any(|remote| remote["type"] == "streamable-http" && remote["url"] == REMOTE_URL);
    if !hosted {
        problems.push(format!("remotes has no streamable-http {REMOTE_URL}"));
    }

    if problems.is_empty() {
        Ok(Checked { placeholders })
    } else {
        Err(RegistryError::Invalid(problems))
    }
}

fn schema_id() -> String {
    serde_json::from_str::<Value>(SCHEMA)
        .ok()
        .and_then(|schema| schema["$id"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn schema_problems(server: &Value) -> Vec<String> {
    let schema: Value = match serde_json::from_str(SCHEMA) {
        Ok(schema) => schema,
        Err(error) => return vec![format!("the vendored schema is not JSON: {error}")],
    };
    match jsonschema::validator_for(&schema) {
        Ok(validator) => validator
            .iter_errors(server)
            .map(|error| format!("schema: {error} at {}", error.instance_path()))
            .collect(),
        Err(error) => vec![format!("the vendored schema does not compile: {error}")],
    }
}

fn expect_eq(problems: &mut Vec<String>, what: &str, got: &Value, want: &str) {
    if got != want {
        problems.push(format!("{what} is {got}, expected \"{want}\""));
    }
}

/// Whether `readme` has `mcp-name: <name>` followed by a boundary. The registry
/// rejects the token glued to trailing characters.
fn has_mcp_name(readme: &str, name: &str) -> bool {
    let token = format!("mcp-name: {name}");
    readme.match_indices(&token).any(|(at, _)| {
        let rest = &readme[at + token.len()..];
        rest.chars()
            .next()
            .is_none_or(|next| next.is_whitespace() || rest.starts_with("-->"))
    })
}

/// Writes the SHA-256 of each `ibridge-<target>.mcpb` in `dir` into `server.json`,
/// in place, so the file keeps its layout. Returns how many hashes it wrote.
pub(crate) fn fill(root: &Path, dir: &Path) -> Result<usize, RegistryError> {
    let path = server_json_path(root);
    let mut text = fs::read_to_string(&path)?;
    let server: Value = serde_json::from_str(&text)?;
    let mut filled = 0;
    for package in server["packages"].as_array().map_or(&[][..], Vec::as_slice) {
        if package["registryType"] != "mcpb" {
            continue;
        }
        let identifier = package["identifier"].as_str().unwrap_or_default();
        let file = identifier.rsplit('/').next().unwrap_or_default();
        let digest = Sha256::digest(fs::read(dir.join(file))?);
        let mut hex = String::with_capacity(64);
        for byte in digest {
            write!(hex, "{byte:02x}").map_err(io::Error::other)?;
        }
        text = replace_hash(&text, identifier, &hex)?;
        filled += 1;
    }
    fs::write(&path, text)?;
    Ok(filled)
}

/// Replaces the `fileSha256` value that follows `identifier` in `text`.
fn replace_hash(text: &str, identifier: &str, hex: &str) -> Result<String, RegistryError> {
    const KEY: &str = "\"fileSha256\": \"";
    let missing = || {
        RegistryError::Invalid(vec![format!(
            "no `fileSha256` line follows the identifier {identifier}"
        )])
    };
    let start = text.find(identifier).ok_or_else(missing)?;
    let value = start + text[start..].find(KEY).ok_or_else(missing)? + KEY.len();
    let end = value + text[value..].find('"').ok_or_else(missing)?;
    Ok(format!("{}{hex}{}", &text[..value], &text[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The repository this crate lives in.
    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is a workspace member")
            .to_path_buf()
    }

    /// A copy of the files `check` reads, to break one thing at a time.
    fn copy_of_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        for file in ["server.json", "Dockerfile", "README.md"] {
            fs::copy(repo().join(file), dir.path().join(file)).expect("copy");
        }
        dir
    }

    fn problems(result: Result<Checked, RegistryError>) -> String {
        match result {
            Err(RegistryError::Invalid(problems)) => problems.join("\n"),
            other => panic!("expected problems, got {other:?}"),
        }
    }

    #[test]
    fn the_repos_server_json_passes_the_registry_schema_and_matches_the_repo() {
        let checked = check(&repo()).expect("server.json is valid");
        let all = mcpb::triples().count();
        assert!(
            checked.placeholders == 0 || checked.placeholders == all,
            "{} of {all} bundle hashes are still the placeholder; `registry fill` writes all or none",
            checked.placeholders
        );
    }

    #[test]
    fn a_description_over_100_characters_fails_the_schema() {
        let dir = copy_of_repo();
        let path = dir.path().join("server.json");
        let mut server: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("json");
        server["description"] = Value::String("x".repeat(101));
        fs::write(&path, server.to_string()).expect("write");
        assert!(problems(check(dir.path())).contains("schema:"));
    }

    #[test]
    fn a_missing_dockerfile_label_is_reported() {
        let dir = copy_of_repo();
        let path = dir.path().join("Dockerfile");
        let text = fs::read_to_string(&path).expect("read");
        fs::write(&path, text.replace(LABEL, "io.example.other")).expect("write");
        assert!(problems(check(dir.path())).contains("Dockerfile has no line"));
    }

    #[test]
    fn the_readme_line_must_match_the_name_and_end_at_a_boundary() {
        assert!(has_mcp_name(
            "<!-- mcp-name: io.github.AlexanderTar/ibridge -->",
            SERVER_NAME
        ));
        assert!(has_mcp_name(
            "mcp-name: io.github.AlexanderTar/ibridge\nmore",
            SERVER_NAME
        ));
        assert!(!has_mcp_name(
            "mcp-name: io.github.AlexanderTar/ibridge.",
            SERVER_NAME
        ));
        assert!(!has_mcp_name(
            "mcp-name: io.github.AlexanderTar/other",
            SERVER_NAME
        ));
    }

    #[test]
    fn fill_writes_each_bundles_hash_and_keeps_the_layout() {
        let dir = copy_of_repo();
        let bundles = tempfile::tempdir().expect("temp dir");
        for triple in mcpb::triples() {
            fs::write(
                bundles.path().join(format!("ibridge-{triple}.mcpb")),
                triple.as_bytes(),
            )
            .expect("bundle");
        }
        let before = fs::read_to_string(dir.path().join("server.json")).expect("read");
        assert_eq!(
            fill(dir.path(), bundles.path()).expect("fill"),
            mcpb::triples().count()
        );
        let after = fs::read_to_string(dir.path().join("server.json")).expect("read");
        assert_eq!(
            after.replace(PLACEHOLDER_SHA256, "").lines().count(),
            before.replace(PLACEHOLDER_SHA256, "").lines().count(),
            "only the hash values change"
        );
        assert_eq!(
            check(dir.path()).expect("still valid").placeholders,
            0,
            "no placeholder is left"
        );
        assert!(!after.contains(PLACEHOLDER_SHA256));
    }

    #[test]
    fn release_mode_refuses_a_placeholder() {
        let dir = copy_of_repo();
        let path = dir.path().join("server.json");
        let mut server: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("json");
        for package in server["packages"].as_array_mut().expect("packages") {
            if package.get("fileSha256").is_some() {
                package["fileSha256"] = Value::String(PLACEHOLDER_SHA256.to_owned());
            }
        }
        fs::write(&path, server.to_string()).expect("write");
        let args = ["check", "--release"].map(str::to_owned);
        let error = run(dir.path(), args.into_iter()).expect_err("placeholders remain");
        assert!(error.to_string().contains("placeholder"));
    }
}
