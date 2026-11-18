# ibridge

An [MCP](https://modelcontextprotocol.io) server that gives Claude access to your iCloud Mail, Calendar, Reminders and Contacts. It runs on your machine and talks to iCloud over IMAP, SMTP, CalDAV and CardDAV with an app-specific password. Your Apple ID password is never used.

## Start read-only

Mail tools can send, move and delete messages. While you are finding out what Claude does with them, run the server read-only: every tool that changes mail is hidden and rejected.

```sh
ibridge serve --stdio --read-only
```

Drop `--read-only` once you trust the setup. The Claude Desktop extension (below) has no read-only switch yet; use Claude Code if you want one.

## Before you install

Create an app-specific password at [account.apple.com](https://account.apple.com) under Sign-In and Security. Use one password per tool, so you can revoke it on its own.

## Install

Releases are built for macOS (Apple silicon and Intel), Linux (x64 and arm64) and Windows (x64). Pick one:

**Homebrew** (macOS and Linux):

```sh
brew install AlexanderTar/tap/ibridge
```

**Install script** (macOS and Linux):

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/AlexanderTar/icloud-mcp/releases/latest/download/ibridge-installer.sh | sh
```

**PowerShell** (Windows):

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/AlexanderTar/icloud-mcp/releases/latest/download/ibridge-installer.ps1 | iex"
```

You can also download an archive from the [releases page](https://github.com/AlexanderTar/icloud-mcp/releases) and put `ibridge` on your `PATH`.

## Connect Claude Code

Store the password in your system keychain, then register the server:

```sh
ibridge login
claude mcp add ibridge -- ibridge serve --stdio --read-only
```

`ibridge login` checks the password against iCloud before it stores it, and prints the `claude mcp add` line for your install. `ibridge doctor` checks the keychain, the network and the sign-in for each service.

To keep one server running in the background on macOS or Linux, `ibridge daemon install` starts it on loopback and prints the `claude mcp add --transport http` line, with its bearer token.

## Connect Claude Desktop

Download `ibridge-<target>.mcpb` for your platform from the releases page and open it. Claude Desktop asks for your Apple ID and the app-specific password, keeps the password out of the config file and passes it to the server as an environment variable.

## Hosted service

The hosted service at [ibridge.fyi](https://ibridge.fyi) is for Claude.ai and other remote MCP clients. Sign in with Apple, then connect your iCloud address with an app-specific password. It costs US$1.99 per month or US$19.99 per year. Running it locally or [self-hosting](docs/self-host.md) is free and never gated.

## Security

Credentials are only ever sent to Apple's iCloud hosts. Mail, event and contact text reaches Claude marked as untrusted content. See [SECURITY.md](SECURITY.md) to report a problem. The hosted server's sealing, its limits and its threat model are in [docs/security-model.md](docs/security-model.md), and running your own copy is in [docs/self-host.md](docs/self-host.md).

## Contributing and releases

See [CONTRIBUTING.md](CONTRIBUTING.md), [docs/local-development.md](docs/local-development.md) and [docs/release.md](docs/release.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
