# Local development

`rust-toolchain.toml` pins the dev toolchain at 1.100. The minimum supported version is 1.98 (`rust-version` in the workspace manifest). `cargo +1.98 check` is the MSRV check, so both toolchains need to be installed:

```sh
rustup toolchain install 1.100.0 --profile minimal --component rustfmt,clippy,llvm-tools-preview
rustup toolchain install 1.98.0
```

Install the CI tools with the pinned toolchain. `cargo-shear` 1.14.1 does not build on rustc 1.91, which is what an un-updated `stable` may still be:

```sh
cargo +1.100.0 install --locked cargo-nextest cargo-hack cargo-deny cargo-shear cargo-llvm-cov cargo-dist
```

`cargo-dist` installs a binary named `dist`. `actionlint` checks the workflow files (`brew install actionlint`).

The commands CI runs are listed in `AGENTS.md`. Run that list on a clean tree before pushing. Docker is required only for `cargo nextest run --workspace --profile integration`. The default nextest profile does not run those tests.

The live Apple test account is `~/.config/ibridge/test-account.env`. Do not create a repo `.env`, and do not print the password.

BeautifulRust is installed with the command in `AGENTS.md`, at the commit named there. Do not enable its remote MCP server.
