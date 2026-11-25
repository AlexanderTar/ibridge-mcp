# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `mail_get_message` reports whether a message offers unsubscribe (`List-Unsubscribe`, RFC 2369) and by which methods: `one_click`, `mailto` or `link`.
- `mail_unsubscribe` unsubscribes from a sender by email. It takes a message id (and an optional method, below): the address, subject and body come from the message's own `mailto:` entry, and only `subject` and `body` are read from it. The email goes out through the normal send path, so the send limits apply and a copy is saved in Sent Messages. A message that offers only a web link returns the link and sends nothing. Read-only mode hides the tool.
- `mail_unsubscribe` uses RFC 8058 one-click when a message has `List-Unsubscribe-Post: List-Unsubscribe=One-Click` and an `https` link, in local and hosted mode. The server POSTs `List-Unsubscribe=One-Click` to that link, preferring it over the mailto, with no account credentials, cookies or redirects. It refuses links that are not `https` on port 443, and hosts that resolve to a loopback, private, link-local or other non-public address, and it connects to the address it checked. A failure names its class (blocked address, unreachable, certificate, timeout, redirect, refused, bad reply) and says whether a mailto exists, but sends nothing. Nothing the sender's server answers reaches the model.
- `mail_unsubscribe` takes an optional `method`, `one_click` or `mailto`. After a failed one-click, `method: "mailto"` sends the message's own unsubscribe email; it never takes an address or link from the caller. A method the message does not offer is a tool error and sends nothing. Omitted, the choice is unchanged: one-click first.
- One-click unsubscribe POSTs are capped at 10 an hour per account (`SendLimits::max_one_click_per_hour`), counted apart from sends. A call past the cap is refused as rate limited and makes no request. See `docs/security-model.md` for the residual risk.

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
