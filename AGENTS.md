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

Each provider crate maps protocol failures onto `Auth`, `Network`, `Protocol`, `NotFound`, `Conflict`, `Forbidden`, `RateLimited`, `Unsupported`, `HostNotAllowed` and `InvalidInput`. One conversion in `ibridge-server` turns those into MCP errors:

- Bad input becomes `invalid_params`.
- `NotFound` and `Conflict` become tool errors that say what to do next.
- `Auth` in local mode says to run `ibridge login`. Auth failures are never retried inside a call.
- `Forbidden` is a refused change (a write to a read-only shared calendar, or an item iCloud rejects). The password was accepted. DAV maps only a 401, or a bare 403 on a read, to `Auth`; a bare 403 on a write is `Forbidden` and never counts toward revoking a grant.
- Every other failure becomes an internal error. The message has no secrets and no raw server text.

## Secrets

Every secret is a `secrecy` type with no `Serialize` and no `Debug`. Secrets never appear in logs, errors or tool output. Never print, commit or put in a brief an Apple app-specific password or the Railway token.

A hosted call's password is wiped after use (`Zeroizing` copies, sensitive headers). One known limit: lettre keeps the SMTP password in a plain `String` until it sends `AUTH` and does not wipe it, so that copy lives until the send finishes and its memory is freed.

The live test account lives outside the repo, in `~/.config/ibridge/test-account.env` (`IBRIDGE_TEST_APPLE_ID`, `IBRIDGE_TEST_APP_PASSWORD`). CI never reads it.

## Host allowlist

Credentials go only to these hosts: `imap.mail.me.com`, `smtp.mail.me.com`, `caldav.icloud.com`, `contacts.icloud.com`, `p*-caldav.icloud.com`, `p*-contacts.icloud.com`. A redirect to any other host drops the credentials and fails.

The hosted server also calls, with their own credentials only: when Sign in with Apple is on, `appleid.apple.com`, `identitytoolkit.googleapis.com` and `www.googleapis.com`; when billing is on, `api.stripe.com`. Add no other outbound host without updating `docs/security-model.md`.

## Fakes and the Stripe sandbox test

Tests never reach Apple, Firebase or Stripe: `identity/fakes.rs` (`FakeApple`, `FakeFirebase`) and `billing/fakes.rs` (`FakeStripe`, built from real payloads in `billing/fixtures/` at the pinned `STRIPE_API_VERSION`) run on loopback. The one exception is the ignored `stripe_sandbox_round_trip` test in `billing/stripe.rs`. It talks to the Stripe sandbox, refuses a non-test key, and reads `IBRIDGE_TEST_STRIPE_SECRET_KEY`, `IBRIDGE_TEST_STRIPE_API_VERSION`, `IBRIDGE_TEST_STRIPE_TAX`, `IBRIDGE_TEST_STRIPE_PRICE_MONTHLY` and `IBRIDGE_TEST_STRIPE_PRICE_YEARLY` from `~/.config/ibridge/stripe-sandbox.env` (outside the repo, mode 0600). Run it with `set -a; . ~/.config/ibridge/stripe-sandbox.env; set +a; cargo nextest run -p ibridge-hosted --run-ignored only -E 'test(stripe_sandbox_round_trip)'`. CI never runs it. Raise `STRIPE_API_VERSION` only after re-recording the fixtures and re-running this test.

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

Tests that use `#[tokio::test(start_paused = true)]` must wait for something the code does, never for a fixed number of `yield_now()` calls: `tokio::fs` runs on the blocking pool, outside the paused clock, and a loaded runner finishes it late. Never raise the yield count, retry or loosen the assertion. Reproduce with `cargo nextest run -p <crate> -E 'test(/<module>::tests/)' --stress-count 300` under CPU load. See "Tests with a paused clock" in `docs/local-development.md`.

Every `.rs` file starts with `// SPDX-License-Identifier: Apache-2.0`. Sign off commits with `git commit -s` and leave GPG signing on. See `docs/local-development.md` for the toolchain and the tool install.
