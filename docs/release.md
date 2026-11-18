# Releasing

iBridge ships source only: a git tag, a GitHub Release with notes, the crates on crates.io and a listing in the official MCP Registry. There are no prebuilt binaries, installers, Homebrew formula, signed or notarized builds, published Docker image or published Claude Desktop extension. Nothing here runs from CI: the maintainer does each step by hand.

## Cutting a release

1. Pick the version (semantic versioning). Set `version` under `[workspace.package]` in `Cargo.toml`, and the `version = "..."` on each `ibridge-*` entry under `[workspace.dependencies]`. Set `version` and the package `version` in `server.json` to the same value. Run `cargo check` and commit the `Cargo.lock` change.
2. Move the `[Unreleased]` entries in `CHANGELOG.md` under a new `## [x.y.z] - date` heading and update the compare links at the bottom.
3. Run every command in "Checks to run before you open a pull request" in `CONTRIBUTING.md` on a clean tree, then `cargo xtask registry check` (it fails until `server.json` and the crate version match).
4. Merge to `main`, then tag the merged commit and push the tag: `git tag -s vX.Y.Z -m "iBridge X.Y.Z" && git push origin vX.Y.Z`.
5. Create the GitHub Release from the tag with the changelog entry as its notes: `gh release create vX.Y.Z --title "iBridge X.Y.Z" --notes-file <notes>`. Attach no binaries.

## Publishing the crates

Check first, then publish. `cargo publish --workspace` publishes every crate that is not `publish = false` in dependency order (`ibridge-core`, `ibridge-auth`, `ibridge-server`, `ibridge-dav`, `ibridge-mail`, `ibridge-calendar`, `ibridge-contacts`, `ibridge-hosted`, `ibridge`) and waits for each to reach the index before the next:

```sh
cargo publish --workspace --dry-run
cargo publish --workspace
```

`ibridge-testkit` and `xtask` are `publish = false` and are never published. `ibridge-hosted` embeds copies of the site's design files from `crates/ibridge-hosted/assets/design/`, because a published crate cannot include files outside its own directory. A test fails when a copy differs from `site/design/`; copy the file again when the site's changes.

Apple's Sign in with Apple logo (`crates/ibridge-hosted/assets/apple-logo-*.svg` and the `NOTICE` beside them) is not Apache-2.0 and stays out of the package: `exclude` in `crates/ibridge-hosted/Cargo.toml` drops it, and the build falls back to a text-only button. Check with `cargo package --list -p ibridge-hosted`: no `apple-logo` file may appear.

## Listing in the official MCP Registry

`server.json` at the repository root is the listing for the [official MCP Registry](https://registry.modelcontextprotocol.io): the name `io.github.AlexanderTar/ibridge`, the `cargo` package `ibridge` and the hosted connector at `https://mcp.ibridge.fyi/mcp`. `cargo xtask registry check` validates it against the registry's JSON schema (a copy is in `xtask/schemas/server.schema.json`; it also runs in the test suite on every pull request) and checks that the version matches the crate version, that the package is the `ibridge` crate and that the remote is present.

For a `cargo` package the registry reads the crate's README on crates.io and looks for a visible `mcp-name: io.github.AlexanderTar/ibridge` line. The README ends with that line. crates.io strips HTML comments, so never hide it in one; the check fails if you do.

Publish the crate first, so its README is on crates.io, then:

1. Install `mcp-publisher` ([quickstart](https://modelcontextprotocol.io/registry/quickstart)).
2. From the tagged commit: `mcp-publisher validate`, `mcp-publisher login github` (as `AlexanderTar`) and `mcp-publisher publish`. The registry is in preview, so check the quickstart for changes first.

## Claude Desktop extension

`cargo xtask mcpb [--binary PATH] [--out DIR]` packs your own build of `ibridge` (default `target/release/ibridge`; run `cargo build --release -p ibridge` first) into `target/mcpb/ibridge-<version>-<platform>.mcpb` for the platform it runs on. It needs `zip`. It is for people who build from source; no bundle is published. The manifest follows spec 0.3 with a binary server, a sensitive `app_password` and the Apple ID, both passed to the server as `IBRIDGE_APPLE_ID` and `IBRIDGE_APP_PASSWORD`. Its snapshot is in `xtask/src/snapshots`; review the diff when you change the manifest.
