# Agent instructions

The binary, crates, keychain service and env prefix are `ibridge`. The git repository stays `icloud-mcp`.

## BeautifulRust

Use `rust-best-practices` while writing Rust and `rust-review` while reviewing it. Install the skills at user scope, at commit `b9718436d77ee7bcf17cdcb6aa27628feb95d97a`, and do not commit them:

```sh
npx skills add morganlinton/BeautifulRust@b9718436d77ee7bcf17cdcb6aa27628feb95d97a
```

Never enable BeautifulRust's remote MCP server.

Workspace lints are that commit's `lints/lints.toml`, plus `unsafe_code = "forbid"`. Silence a lint with `#[expect(lint, reason = "...")]` on the narrowest item. Do not use `#[allow]` except in generated code. Do not put `#![deny(warnings)]` in source. CI passes `-D warnings`.

## Crate boundaries

Dependencies point one way:

`ibridge-core` ← `ibridge-auth` ← `ibridge-mail` and `ibridge-dav` ← `ibridge-calendar` and `ibridge-contacts` ← `ibridge-server` ← `ibridge-hosted` ← `ibridge`.

Provider crates never depend on `rmcp`. `anyhow` is allowed only in `crates/ibridge`. Every other crate uses `thiserror`, and its public error enum is `#[non_exhaustive]`. `ibridge-testkit` is `publish = false`.

Binary features: `mail`, `calendar`, `contacts`, `stdio` and `http` are on by default. `hosted` is off by default.

## Error mapping

Each provider crate maps protocol failures onto `Auth`, `Network`, `Protocol`, `NotFound`, `Conflict`, `RateLimited`, `Unsupported`, `HostNotAllowed` and `InvalidInput`. One conversion in `ibridge-server` turns those into MCP errors:

- Bad input becomes `invalid_params`.
- `NotFound` and `Conflict` become tool errors that say what to do next.
- `Auth` in local mode says to run `ibridge login`. Auth failures are never retried inside a call.
- Every other failure becomes an internal error. The message has no secrets and no raw server text.

## Secrets

Every secret is a `secrecy` type with no `Serialize` and no `Debug`. Secrets never appear in logs, errors or tool output. Never print, commit or put in a brief an Apple app-specific password or the Railway token.

A hosted call's password is wiped after use (`Zeroizing` copies, sensitive headers). One known limit: lettre keeps the SMTP password in a plain `String` until it sends `AUTH` and does not wipe it, so that copy lives until the send finishes and its memory is freed.

The live test account lives outside the repo, in `~/.config/ibridge/test-account.env` (`IBRIDGE_TEST_APPLE_ID`, `IBRIDGE_TEST_APP_PASSWORD`). CI never reads it.

## Host allowlist

Credentials go only to these hosts: `imap.mail.me.com`, `smtp.mail.me.com`, `caldav.icloud.com`, `contacts.icloud.com`, `p*-caldav.icloud.com`, `p*-contacts.icloud.com`. A redirect to any other host drops the credentials and fails.

## Platform code

All `cfg(target_os)` code lives under a `platform/` module path.

## CI

Run each of these once, on a clean tree, before pushing:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo nextest run --workspace`
- `cargo +1.98 check --workspace --all-features`
- `cargo hack check --each-feature --no-dev-deps`
- `cargo deny check`
- `cargo shear`
- `cargo xtask check-headers`

Docker tests match `test(/(^|::)integration::/)`: a crate-root `mod integration` (the name is `integration::…`, with no leading `::`) or any `…::integration::…`. A top-level test in `tests/integration.rs` has no module prefix, so it runs in the default profile; put it in `mod integration` in that file. The filter does not use `binary(integration)`, because nextest rejects a binary predicate that matches no binary and this repo has none until a Docker suite lands. The default nextest profile excludes the set. Run them with `cargo nextest run --workspace --profile integration`. CI adds `--no-tests=pass` so an empty group does not fail the build; a failing test still does.

Every `.rs` file starts with `// SPDX-License-Identifier: Apache-2.0`. Sign off commits with `git commit -s` and leave GPG signing on. See `docs/local-development.md` for the toolchain and the tool install.
