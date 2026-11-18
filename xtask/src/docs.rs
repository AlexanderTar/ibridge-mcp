// SPDX-License-Identifier: Apache-2.0

//! Lints the prose in the README and the docs.
//!
//! - The product is "iBridge" in prose. Lowercase `ibridge` is for identifiers:
//!   the binary and its commands, crates, environment variables, domains and paths.
//!   Put those in backticks, or they read as a misspelt name.
//! - The hosted connector is `mcp.ibridge.fyi`. The bare `ibridge.fyi` is the product
//!   site, which has no MCP endpoint, sign-in or health route.
//! - The README says Reminders only in its own section, which states the limit.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use regex::Regex;

/// The files whose prose is checked.
fn documents(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = vec![
        root.join("README.md"),
        root.join("CONTRIBUTING.md"),
        root.join("SECURITY.md"),
    ];
    for entry in fs::read_dir(root.join("docs"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "md") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// Every problem found under `root`, as `file:line: message`.
pub(crate) fn check(root: &Path) -> io::Result<Vec<String>> {
    let mut problems = Vec::new();
    for path in documents(root)? {
        let name = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let text = fs::read_to_string(&path)?;
        problems.extend(brand_problems(&name, &text));
        problems.extend(url_problems(&name, &text));
        if name == "README.md" {
            problems.extend(readme_problems(&text));
        }
    }
    Ok(problems)
}

/// Lines of `text` outside fenced code blocks, with inline code, link targets, bare
/// URLs and HTML comments blanked out. Line numbers start at 1.
fn prose_lines(text: &str) -> Vec<(usize, String)> {
    let link_target = Regex::new(r"\]\([^)]*\)").expect("link pattern");
    let url = Regex::new(r"https?://\S+").expect("url pattern");
    let comment = Regex::new(r"<!--.*?-->").expect("comment pattern");
    let mut fenced = false;
    let mut lines = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let mut prose = String::new();
        for (at, part) in line.split('`').enumerate() {
            if at % 2 == 0 {
                prose.push_str(part);
            } else {
                prose.push(' ');
            }
        }
        let prose = comment.replace_all(&prose, " ");
        let prose = link_target.replace_all(&prose, "]");
        let prose = url.replace_all(&prose, " ");
        lines.push((index + 1, prose.into_owned()));
    }
    lines
}

/// Whether the `ibridge` at `start..end` of `line` is part of an identifier: a
/// domain (`ibridge.fyi`), a crate (`ibridge-hosted`), a path or a variable.
fn is_identifier(line: &str, start: usize, end: usize) -> bool {
    let before = line[..start].chars().next_back();
    let mut after = line[end..].chars();
    let next = after.next();
    let then = after.next();
    let word = |c: char| c.is_alphanumeric() || c == '_';
    before.is_some_and(|c| word(c) || matches!(c, '.' | '/' | '@' | '-'))
        || next.is_some_and(|c| word(c) || matches!(c, '/' | '@'))
        || (matches!(next, Some('.' | '-')) && then.is_some_and(word))
}

fn brand_problems(file: &str, text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for (number, line) in prose_lines(text) {
        let lower = line.to_lowercase();
        for (start, found) in lower.match_indices("ibridge") {
            let end = start + found.len();
            // `to_lowercase` can change byte offsets for non-ASCII text, so compare chars.
            if !line.is_char_boundary(start) || !line.is_char_boundary(end) {
                continue;
            }
            if is_identifier(&line, start, end) || &line[start..end] == "iBridge" {
                continue;
            }
            problems.push(format!(
                "{file}:{number}: write the product as `iBridge` in prose, or put the identifier `{}` in backticks",
                &line[start..end]
            ));
        }
    }
    problems
}

fn url_problems(file: &str, text: &str) -> Vec<String> {
    let product_site_route = Regex::new(
        r"https?://ibridge\.fyi/(mcp|authorize|token|register|signin|billing|readyz|healthz|account|\.well-known)",
    )
    .expect("route pattern");
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            product_site_route.find(line).map(|found| {
                format!(
                    "{file}:{}: `{}` is a server route; the server is https://mcp.ibridge.fyi",
                    index + 1,
                    found.as_str()
                )
            })
        })
        .collect()
}

fn readme_problems(text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for url in ["https://mcp.ibridge.fyi/mcp", "https://ibridge.fyi"] {
        if !text.contains(url) {
            problems.push(format!("README.md: does not mention {url}"));
        }
    }
    let mut section = String::new();
    let mut has_section = false;
    for (index, line) in text.lines().enumerate() {
        if let Some(title) = line.strip_prefix("## ") {
            title.trim().clone_into(&mut section);
            has_section |= section == "Reminders";
        }
        if section != "Reminders" && line.to_lowercase().contains("reminder") {
            problems.push(format!(
                "README.md:{}: Reminders belongs in the `## Reminders` section only",
                index + 1
            ));
        }
    }
    if !has_section {
        problems.push("README.md: has no `## Reminders` section stating the limit".to_owned());
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is a workspace member")
            .to_path_buf()
    }

    #[test]
    fn the_readme_and_docs_follow_the_naming_and_url_rules() {
        let problems = check(&repo()).expect("docs are readable");
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    #[test]
    fn lowercase_ibridge_in_prose_is_a_problem_but_identifiers_are_not() {
        let text = "ibridge reads mail. Use `ibridge login`, the ibridge-hosted crate, \
            IBRIDGE_LOG, mcp.ibridge.fyi, ibridge.fyi and [x](docs/ibridge/y.md). \
            See https://ibridge.fyi/privacy.\n\
            ```sh\nibridge serve\n```\n\
            Self-hosting ibridge. IBridge too.\n";
        let problems = brand_problems("f.md", text);
        assert_eq!(
            problems,
            [
                "f.md:1: write the product as `iBridge` in prose, or put the identifier `ibridge` in backticks",
                "f.md:5: write the product as `iBridge` in prose, or put the identifier `ibridge` in backticks",
                "f.md:5: write the product as `iBridge` in prose, or put the identifier `IBridge` in backticks",
            ]
        );
    }

    #[test]
    fn the_product_site_has_no_server_routes() {
        let problems = url_problems(
            "f.md",
            "https://ibridge.fyi/mcp and https://mcp.ibridge.fyi/mcp and https://ibridge.fyi/privacy",
        );
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("https://ibridge.fyi/mcp"));
    }

    #[test]
    fn reminders_may_only_appear_in_their_own_readme_section() {
        let good = "https://mcp.ibridge.fyi/mcp https://ibridge.fyi\n## Mail\ntext\n## Reminders\nreminders limit\n";
        assert_eq!(readme_problems(good), Vec::<String>::new());
        let bad = "https://mcp.ibridge.fyi/mcp https://ibridge.fyi\nMail and Reminders\n## Reminders\nx\n";
        assert_eq!(readme_problems(bad).len(), 1);
        assert_eq!(
            readme_problems("## Mail\n").len(),
            3,
            "two missing URLs and the missing section"
        );
    }
}
