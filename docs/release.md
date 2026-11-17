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

1. Set `version` under `[workspace.package]` in `Cargo.toml`, run `cargo check`, and commit the `Cargo.lock` change.
2. Run `dist plan` and the commands in `AGENTS.md`.
3. Tag the commit and push the tag: `git tag v0.2.0 && git push origin v0.2.0`. The tag must match the crate version, or `plan` fails.

## Secrets you add

Add these as repository secrets (Settings, Secrets and variables, Actions) before the first tag. `GITHUB_TOKEN` is provided by GitHub.

| Secret | Used by | What it is |
|---|---|---|
| `CODESIGN_CERTIFICATE` | build-local-artifacts | Your Developer ID Application certificate and private key, exported as a `.p12` and base64-encoded. |
| `CODESIGN_CERTIFICATE_PASSWORD` | build-local-artifacts | The password you set when exporting the `.p12`. |
| `CODESIGN_IDENTITY` | build-local-artifacts | The certificate's name, for example `Developer ID Application: Your Name (TEAMID)`. |
| `NOTARY_API_KEY` | notarize-macos | The full text of an App Store Connect API key (`AuthKey_XXXX.p8`). |
| `NOTARY_KEY_ID` | notarize-macos | That key's ID. |
| `NOTARY_ISSUER_ID` | notarize-macos | The issuer ID shown on the App Store Connect Keys page. |
| `HOMEBREW_TAP_TOKEN` | publish-homebrew-formula | A fine-grained personal access token with Contents read and write on `AlexanderTar/homebrew-tap`. |

If a signing secret is missing, dist warns and ships an unsigned binary. `notarize-macos` then fails, so an unsigned or unnotarized macOS build is never hosted.

Create the `AlexanderTar/homebrew-tap` repository on GitHub before the first tag. The `.mcpb` bundles need no extra secret.

## Editing the workflow by hand

dist generates `release.yml`, and four edits are made by hand: the tag filter is narrowed to `v*`, and the `notarize-macos`, `build-mcpb` and `docker-image` jobs are added. `docker-image` builds the `Dockerfile` and pushes `ghcr.io/<owner>/ibridge` once `host` succeeds on a `v*` tag; it needs the `packages: write` permission and uses the built-in `GITHUB_TOKEN`, so it needs no extra secret. `allow-dirty = ["ci"]` in `dist-workspace.toml` stops `dist plan` from rejecting those edits. After `dist` is upgraded, regenerate the file in a scratch copy (comment out `allow-dirty`, run `dist generate --mode ci`), then merge the difference into `release.yml` by hand. `.github/build-setup.yml` holds the step that turns on the hardened runtime. `.github/actionlint.yaml` tells actionlint to skip shellcheck style notes in the generated file.

## Claude Desktop extension

`cargo xtask mcpb [--dist DIR] [--out DIR]` reads `ibridge-<target>` archives from `target/distrib` and writes `ibridge-<target>.mcpb` files to `target/mcpb`. It needs `tar`, `unzip` and `zip`. The manifest follows spec 0.3 with a binary server, a sensitive `app_password` and the Apple ID, both passed to the server as `IBRIDGE_APPLE_ID` and `IBRIDGE_APP_PASSWORD`. Its snapshot is in `xtask/src/snapshots`; review the diff when you change the manifest.
