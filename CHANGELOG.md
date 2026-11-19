# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-11-19

### Added

- `server.json` lists the iBridge icons (`icons`), and `cargo xtask registry check` verifies them.

## [1.0.0] - 2026-11-18

First release. iBridge is distributed as source: build it with Rust, or use the hosted connector.

### Added

- Mail tools over IMAP and SMTP: list mailboxes, search, read messages and attachments, create drafts, send, move and set flags.
- Calendar tools over CalDAV: list calendars, search and read events, create, update and delete them. Reminder tools read and change old-style reminder lists only.
- Contacts tools over CardDAV: search and read contacts, create, update and delete them.
- Local use: `ibridge serve --stdio` for Claude Code and other MCP clients, `ibridge login` to keep an app-specific password in the system keychain, `ibridge doctor`, and a loopback daemon (`ibridge daemon install`) with a bearer token.
- Read-only mode (`--read-only`), which hides and rejects every tool that changes anything.
- `cargo xtask mcpb` builds a Claude Desktop extension from your own build.
- Hosted server (`ibridge serve --hosted`) with OAuth 2.1, Sign in with Apple, paid plans through Stripe, sealed credential storage, daily database backups and operator commands. The public instance is at `https://mcp.ibridge.fyi/mcp`.
- A `Dockerfile` for self-hosting, and guides for Fly.io and Railway.

### Security

- Credentials are sent only to Apple's iCloud hosts; a redirect to any other host drops them and fails.
- Your Apple ID password is never used, only an app-specific password.
- Secrets are never logged and are wiped after use. The hosted server stores each password sealed with a key derived from the token that unlocks it, so nothing in its settings or storage can decrypt it.
- Mail, event, reminder and contact text reaches the client as plain JSON fields. Hidden Unicode (tag characters, bidirectional controls, zero-width characters) is stripped from it, and HTML mail loses text hidden with `display:none`, `visibility:hidden`, `font-size:0`, `opacity:0`, a zero height with `overflow:hidden` or the `hidden` attribute (CSS comments and character references in the style are resolved first), plus `<script>`, `<style>`, `<head>` and comments, before it becomes text. Each read tool's description says where its text comes from.

[Unreleased]: https://github.com/AlexanderTar/ibridge-mcp/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/AlexanderTar/ibridge-mcp/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/AlexanderTar/ibridge-mcp/releases/tag/v1.0.0
