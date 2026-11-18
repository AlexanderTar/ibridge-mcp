# Contributing

Thanks for helping. Please read the [Code of Conduct](CODE_OF_CONDUCT.md) first. To report a security problem, use [SECURITY.md](SECURITY.md), not an issue.

## Build from source

You need Rust 1.100 (`rust-toolchain.toml` pins it; the minimum supported version is 1.98) and, for the integration tests only, Docker. [docs/local-development.md](docs/local-development.md) has the toolchain and CI tool install.

```sh
git clone https://github.com/AlexanderTar/icloud-mcp
cd icloud-mcp
cargo build --workspace
cargo nextest run --workspace
```

## Checks to run before you open a pull request

CI runs these. Run each once on a clean tree:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace
cargo nextest run --workspace --profile integration --no-tests=pass
cargo +1.98 check --workspace --all-features
cargo hack check --each-feature --no-dev-deps
cargo deny check
cargo shear
cargo xtask check-headers
cargo xtask check-docs
cargo xtask registry check
cargo llvm-cov nextest --workspace
```

The integration profile needs Docker. If you touch the site, also run `node site/scripts/check.mjs`.

## Tests first

Write the test that fails before you write the fix or the feature, and check that it fails for the reason you expect. Tests must exercise behaviour: a test that only matches source text or asserts that a mock was called is not evidence. Never weaken, skip or loosen a test to get a green run. Tests never reach Apple, Firebase or Stripe; they use the fakes in `ibridge-testkit` and in `ibridge-hosted`.

## Rust style

The project follows [Beautiful Rust](https://github.com/morganlinton/BeautifulRust):

- Workspace lints are in `Cargo.toml`. Silence a lint with `#[expect(lint, reason = "...")]` on the narrowest item. Do not use `#[allow]`, and do not put `#![deny(warnings)]` in source.
- `unsafe` is forbidden. Secrets are `secrecy` types with no `Serialize` and no `Debug`; they never appear in logs, errors or tool output.
- `anyhow` is allowed only in `crates/ibridge`. Every other crate uses `thiserror`, and its public error enum is `#[non_exhaustive]`.
- Dependencies point one way: `ibridge-core`, `ibridge-auth`, `ibridge-mail` and `ibridge-dav`, `ibridge-calendar` and `ibridge-contacts`, `ibridge-server`, `ibridge-hosted`, `ibridge`. Provider crates never depend on `rmcp`.
- All `cfg(target_os)` code lives under a `platform/` module path.
- Every `.rs` file starts with `// SPDX-License-Identifier: Apache-2.0`.

`AGENTS.md` has the full rules, including the error mapping and the host allowlist. Add no outbound host without updating `docs/security-model.md`.

## Prose

Write the product as "iBridge". Use lowercase `ibridge` only for identifiers (the binary, crates, environment variables, domains and paths), in backticks. `cargo xtask check-docs` checks this.

## Commits and pull requests

Use short conventional messages (`fix: ...`, `feat: ...`, `docs: ...`, `chore: ...`) and keep each commit to one logical change.

This project uses the [Developer Certificate of Origin](https://developercertificate.org/) version 1.1. There is no contributor licence agreement. Sign off every commit:

```sh
git commit -s
```

That adds a `Signed-off-by` line. By adding it, you certify the DCO: you wrote the change, or you can submit it under the project's Apache-2.0 licence. Commits are also GPG-signed. Do not pass `--no-gpg-sign` or set `commit.gpgsign` to false.

Open the pull request against `main`, fill in the template, and make sure every check above passes. Keep it small and focused; open an issue first for a large change.
