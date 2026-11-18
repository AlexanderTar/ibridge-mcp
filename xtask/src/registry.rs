// SPDX-License-Identifier: Apache-2.0

//! Checks `server.json`, the listing for the official MCP Registry.
//!
//! `check` validates it against the registry's JSON schema (vendored in
//! `xtask/schemas`) and ties it to the rest of the repository: the README line
//! the registry reads to prove ownership of the crate, the version, the `cargo`
//! package and the hosted URL. See `docs/release.md`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// The schema the registry validates against, from its `$id` URL.
const SCHEMA: &str = include_str!("../schemas/server.schema.json");

const SERVER_NAME: &str = "io.github.AlexanderTar/ibridge";
const CRATE: &str = "ibridge";
const REMOTE_URL: &str = "https://mcp.ibridge.fyi/mcp";

/// Everything that can go wrong while checking `server.json`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RegistryError {
    #[error("usage: cargo xtask registry check")]
    Usage,
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("server.json is not JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("server.json has problems:\n{}", .0.join("\n"))]
    Invalid(Vec<String>),
}

/// `registry check`.
pub(crate) fn run(
    root: &Path,
    mut args: impl Iterator<Item = String>,
) -> Result<String, RegistryError> {
    match (args.next().as_deref(), args.next()) {
        (Some("check"), None) => {
            check(root)?;
            Ok("server.json ok".to_owned())
        }
        _ => Err(RegistryError::Usage),
    }
}

fn server_json_path(root: &Path) -> PathBuf {
    root.join("server.json")
}

/// Validates `server.json` under `root` and everything it has to agree with.
pub(crate) fn check(root: &Path) -> Result<(), RegistryError> {
    let text = fs::read_to_string(server_json_path(root))?;
    let server: Value = serde_json::from_str(&text)?;
    let mut problems = schema_problems(&server);

    let version = env!("CARGO_PKG_VERSION");
    expect_eq(&mut problems, "name", &server["name"], SERVER_NAME);
    expect_eq(&mut problems, "version", &server["version"], version);
    expect_eq(&mut problems, "$schema", &server["$schema"], &schema_id());

    match fs::read_to_string(root.join("README.md")) {
        Ok(readme) => {
            if !has_mcp_name(&readme, SERVER_NAME) {
                problems.push(format!("README.md has no `mcp-name: {SERVER_NAME}` line"));
            }
            if readme_hides_mcp_name(&readme) {
                problems.push(
                    "README.md hides the `mcp-name:` line in an HTML comment; crates.io strips it"
                        .to_owned(),
                );
            }
        }
        Err(error) => problems.push(format!("README.md: {error}")),
    }

    let packages = server["packages"].as_array().map_or(&[][..], Vec::as_slice);
    let [package] = packages else {
        problems.push(format!(
            "packages has {} entries, expected one cargo package",
            packages.len()
        ));
        return Err(RegistryError::Invalid(problems));
    };
    expect_eq(
        &mut problems,
        "package registryType",
        &package["registryType"],
        "cargo",
    );
    expect_eq(
        &mut problems,
        "package identifier",
        &package["identifier"],
        CRATE,
    );
    expect_eq(
        &mut problems,
        "package version",
        &package["version"],
        version,
    );

    let remotes = server["remotes"].as_array().map_or(&[][..], Vec::as_slice);
    let hosted = remotes
        .iter()
        .any(|remote| remote["type"] == "streamable-http" && remote["url"] == REMOTE_URL);
    if !hosted {
        problems.push(format!("remotes has no streamable-http {REMOTE_URL}"));
    }

    if problems.is_empty() {
        Ok(())
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
        readme[at + token.len()..]
            .chars()
            .next()
            .is_none_or(char::is_whitespace)
    })
}

/// Whether the `mcp-name:` line sits inside an HTML comment.
fn readme_hides_mcp_name(readme: &str) -> bool {
    readme
        .lines()
        .any(|line| line.contains("<!--") && line.contains("mcp-name:"))
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
        for file in ["server.json", "README.md"] {
            fs::copy(repo().join(file), dir.path().join(file)).expect("copy");
        }
        dir
    }

    fn edit_server(dir: &Path, edit: impl FnOnce(&mut Value)) {
        let path = dir.join("server.json");
        let mut server: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("json");
        edit(&mut server);
        fs::write(&path, server.to_string()).expect("write");
    }

    fn problems(result: Result<(), RegistryError>) -> String {
        match result {
            Err(RegistryError::Invalid(problems)) => problems.join("\n"),
            other => panic!("expected problems, got {other:?}"),
        }
    }

    #[test]
    fn the_repos_server_json_passes_the_registry_schema_and_matches_the_repo() {
        check(&repo()).expect("server.json is valid");
    }

    #[test]
    fn a_description_over_100_characters_fails_the_schema() {
        let dir = copy_of_repo();
        edit_server(dir.path(), |server| {
            server["description"] = Value::String("x".repeat(101));
        });
        assert!(problems(check(dir.path())).contains("schema:"));
    }

    #[test]
    fn a_package_that_is_not_the_cargo_crate_is_reported() {
        let dir = copy_of_repo();
        edit_server(dir.path(), |server| {
            server["packages"][0]["registryType"] = Value::String("oci".to_owned());
        });
        assert!(problems(check(dir.path())).contains("package registryType"));
    }

    #[test]
    fn a_package_version_that_differs_from_the_crate_is_reported() {
        let dir = copy_of_repo();
        edit_server(dir.path(), |server| {
            server["packages"][0]["version"] = Value::String("0.0.1".to_owned());
        });
        assert!(problems(check(dir.path())).contains("package version"));
    }

    #[test]
    fn a_missing_remote_is_reported() {
        let dir = copy_of_repo();
        edit_server(dir.path(), |server| {
            server["remotes"] = Value::Array(Vec::new());
        });
        assert!(problems(check(dir.path())).contains("remotes has no"));
    }

    #[test]
    fn the_readme_line_must_match_the_name_and_end_at_a_boundary() {
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
    fn the_readme_line_may_not_hide_in_a_comment() {
        let dir = copy_of_repo();
        fs::write(
            dir.path().join("README.md"),
            "<!-- mcp-name: io.github.AlexanderTar/ibridge -->\n",
        )
        .expect("write");
        assert!(problems(check(dir.path())).contains("HTML comment"));
    }
}
