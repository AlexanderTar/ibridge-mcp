# Security

## Reporting a vulnerability

Report a vulnerability privately through [GitHub private vulnerability reporting](https://github.com/AlexanderTar/ibridge-mcp/security/advisories/new). Do not open a public issue or pull request for a security report.

Do not include an app-specific password, a token or message contents. A description and the steps to reproduce are enough.

We will acknowledge the report and agree on a fix and a disclosure date with you before anything is made public.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| Older | No |

## Scope

In scope: the `ibridge` binary and its crates, the hosted server (`ibridge serve --hosted`) and its OAuth, sealing and billing code, and the Docker image built from this repository. [docs/security-model.md](docs/security-model.md) says what the hosted server protects and where that protection ends.

Out of scope: weaknesses in iCloud, Apple's services, Firebase or Stripe themselves; reports that need physical access to an unlocked machine; and the product site at `https://ibridge.fyi`, which has no server routes.
