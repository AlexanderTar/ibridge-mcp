# Releasing

Nothing is published until you push a version tag. The release workflow (`.github/workflows/release.yml`) runs on tags that start with `v`, such as `v0.2.0`. It never runs on pull requests or branch pushes.

## What a tag does

1. **plan** runs `dist plan` for the tag.
2. **build-local-artifacts** builds and archives `ibridge` for macOS (arm64, x64), Linux musl (arm64, x64) and Windows (x64). On macOS dist signs the binary with the Developer ID certificate and the hardened runtime.
3. **build-global-artifacts** makes the shell and PowerShell installers, the Homebrew formula and the checksums.
4. **notarize-macos** submits both signed macOS binaries to Apple's notary service and fails unless Apple accepts them. A bare binary cannot be stapled, so Gatekeeper looks the ticket up online.
5. **host** creates the GitHub release and uploads the archives and installers. It waits for notarization.
6. **publish-homebrew-formula** commits the formula to `AlexanderTar/homebrew-tap`.
7. **build-mcpb** runs `cargo xtask mcpb` on dist's archives and attaches one `ibridge-<target>.mcpb` bundle per target to the release.

## Cutting a release

1. Set `version` under `[workspace.package]` in `Cargo.toml`, run `cargo check`, and commit the `Cargo.lock` change. Set the same version in `server.json`: its `version`, the version in each `.mcpb` URL and the image tag. Reset every `fileSha256` to 64 zeros. `cargo xtask registry check` fails until they match.
2. Run `dist plan` and the commands in `AGENTS.md`.
3. Tag the commit and push the tag: `git tag v0.2.0 && git push origin v0.2.0`. The tag must match the crate version, or `plan` fails.

## Secrets you add

Add these as repository secrets (Settings, Secrets and variables, Actions) before the first tag. `GITHUB_TOKEN` is provided by GitHub.

**None of them is set today**, so a tag pushed now fails: the first release (0.1.0) needs all seven.

| Secret | Set today | Used by | What it is |
|---|---|---|---|
| `CODESIGN_CERTIFICATE` | missing | build-local-artifacts | Your Developer ID Application certificate and private key, exported as a `.p12` and base64-encoded. |
| `CODESIGN_CERTIFICATE_PASSWORD` | missing | build-local-artifacts | The password you set when exporting the `.p12`. |
| `CODESIGN_IDENTITY` | missing | build-local-artifacts | The certificate's name, for example `Developer ID Application: Your Name (TEAMID)`. |
| `NOTARY_API_KEY` | missing | notarize-macos | The full text of an App Store Connect API key (`AuthKey_XXXX.p8`). |
| `NOTARY_KEY_ID` | missing | notarize-macos | That key's ID. |
| `NOTARY_ISSUER_ID` | missing | notarize-macos | The issuer ID shown on the App Store Connect Keys page. |
| `HOMEBREW_TAP_TOKEN` | missing | publish-homebrew-formula | A fine-grained personal access token with Contents read and write on `AlexanderTar/homebrew-tap`. |

If a signing secret is missing, dist warns and ships an unsigned binary. `notarize-macos` then fails, so an unsigned or unnotarized macOS build is never hosted. Update the "Set today" column when you add a secret.

Create the `AlexanderTar/homebrew-tap` repository on GitHub before the first tag; it does not exist yet. The `.mcpb` bundles need no extra secret.

## Editing the workflow by hand

dist generates `release.yml`, and four edits are made by hand: the tag filter is narrowed to `v*`, and the `notarize-macos`, `build-mcpb` and `docker-image` jobs are added. `docker-image` builds the `Dockerfile` and pushes `ghcr.io/<owner>/ibridge` once `host` succeeds on a `v*` tag; it needs the `packages: write` permission and uses the built-in `GITHUB_TOKEN`, so it needs no extra secret. `allow-dirty = ["ci"]` in `dist-workspace.toml` stops `dist plan` from rejecting those edits. After `dist` is upgraded, regenerate the file in a scratch copy (comment out `allow-dirty`, run `dist generate --mode ci`), then merge the difference into `release.yml` by hand. `.github/build-setup.yml` holds the step that turns on the hardened runtime. `.github/actionlint.yaml` tells actionlint to skip shellcheck style notes in the generated file.

## After the first release: make the image public

The first `docker-image` run creates `ghcr.io/alexandertar/ibridge` as a private package, so `docker pull` and Railway's image source cannot read it. Do this once, after the first `v*` tag has pushed it:

1. Open the package from your GitHub profile (Packages, `ibridge`), then Package settings.
2. Check it is linked to `AlexanderTar/icloud-mcp`. The workflow's metadata step labels the image with its source repository, so GitHub normally links it on its own; if the package page shows no repository, link it here.
3. Under "Danger Zone", change the visibility to Public.
4. Check from a machine that is not logged in to ghcr.io: `docker logout ghcr.io; docker pull ghcr.io/alexandertar/ibridge:<version>`.

Later tags reuse the same package, so this is a one-time step. The visibility is a package setting, not part of `release.yml`, so the workflow cannot do it for you.

## Listing in the official MCP Registry

`server.json` at the repository root is the listing for the [official MCP Registry](https://registry.modelcontextprotocol.io): the name `io.github.AlexanderTar/ibridge`, the five `.mcpb` bundles on the GitHub release, the `ghcr.io/alexandertar/ibridge` image and the hosted connector at `https://mcp.ibridge.fyi/mcp`. `cargo xtask registry check` validates it against the registry's JSON schema (a copy is in `xtask/schemas/server.schema.json`; it runs in the test suite on every pull request) and checks that the `LABEL io.modelcontextprotocol.server.name` line in the `Dockerfile` and the `mcp-name:` line in `README.md` carry the same name, that the version matches the crate version, and that the bundle URLs and image tag match the release.

The `fileSha256` of each bundle is `000…0` (64 zeros) until a release exists, because the schema needs 64 hex digits and the bundle does not exist yet. Fill them after the release, then publish:

1. Wait for the `build-mcpb` job and for the `docker-image` job, and make the image public (above).
2. Download the bundles: `gh release download v0.1.0 --repo AlexanderTar/icloud-mcp --pattern '*.mcpb' --dir /tmp/ibridge-mcpb`.
3. Write the hashes into `server.json`: `cargo xtask registry fill --mcpb /tmp/ibridge-mcpb`.
4. Check that none is left: `cargo xtask registry check --release`. Commit the change and merge it. Publish from the merged commit.
5. Install `mcp-publisher` ([quickstart](https://modelcontextprotocol.io/registry/quickstart)), then `mcp-publisher validate`, `mcp-publisher login github` (as `AlexanderTar`) and `mcp-publisher publish`. The registry is in preview, so check the quickstart for changes first.

The registry reads the `mcp-name:` README line only for npm, PyPI, NuGet and Cargo packages; this listing has none, so the line is a hidden HTML comment. If a crate is ever published, make it visible text: crates.io strips HTML comments.

## Claude Desktop extension

`cargo xtask mcpb [--dist DIR] [--out DIR]` reads `ibridge-<target>` archives from `target/distrib` and writes `ibridge-<target>.mcpb` files to `target/mcpb`. It needs `tar`, `unzip` and `zip`. The manifest follows spec 0.3 with a binary server, a sensitive `app_password` and the Apple ID, both passed to the server as `IBRIDGE_APPLE_ID` and `IBRIDGE_APP_PASSWORD`. Its snapshot is in `xtask/src/snapshots`; review the diff when you change the manifest.
