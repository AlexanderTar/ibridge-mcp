# Security model of the hosted server

This page describes what the hosted ibridge server (`ibridge serve --hosted`) protects, how, and where the protection ends. The local modes (`serve --stdio`, the loopback daemon) keep the password in your OS keychain and are not covered here. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## What is stored

The server needs your iCloud app-specific password to log in to iCloud for you. It keeps it only sealed:

- The database (`ibridge.db`) holds your iCloud address, one row per connected app or API key, and for each one a ciphertext of your password, a nonce, and a lookup hash of the token.
- It never stores a token. It stores a one-way lookup hash, so it can find the right row when a token arrives.
- There is no master key and no key file. Nothing in the server's settings or storage can decrypt a stored password.

## Sealing

When you sign in, the server checks the password with iCloud, then seals one copy per token it issues:

1. The token (an access token `iba_…`, a refresh token `ibf_…`, or an API key `ibr_…`) is the secret input.
2. Two independent keys come out of it with HKDF-SHA-256 (`ibridge-seal-v1` for encryption, `ibridge-lookup-v1` for the lookup hash). The lookup hash is not the encryption key.
3. The password is encrypted with AES-256-GCM under a random 96-bit nonce. The associated data is the iCloud address and the grant it belongs to, so a ciphertext cannot be moved to another account or grant.
4. Each connected app or key has its own sealed copy. Revoking one removes only its copy.

On each `/mcp` request the server derives the key from the bearer token the request carries, opens that copy, logs in to iCloud, and wipes its working copy of the password.

A copy of the database, the backups and every server setting is not enough to read a password: the key exists only in the token that the client holds.

## Limits of sealing

Sealing protects data at rest. It does not stop the running server from seeing the password:

- **The server sees the password at two moments**: when you type it on the sign-in page, and while a request runs. Anyone who controls the running process at those moments, such as an operator or an attacker who changes the code it runs, can capture it. The code is open source and a deployment names the exact commit it runs, which makes a change visible but does not prevent one.
- **Memory.** Working copies of the password are wiped after use, but the mail client library (lettre) keeps the SMTP password in a plain `String` until it sends `AUTH`, and that copy is not wiped. It lives until the send finishes and its memory is freed. A memory dump taken during a call could contain it.
- **Idle mail sessions.** Logged-in mail connections are kept for up to five minutes after a request to save logging in again. The password is not kept with them.
- **Mail, event and contact text** passes through the server in clear text while a request runs. Sealing covers only the password.
- **Tokens are bearer secrets.** Whoever holds a valid token can use the account until it expires or is revoked: access tokens last one hour, refresh tokens 90 days of non-use, API keys until revoked. Sign-in codes last 60 seconds.
- **The only complete revocation is at Apple.** Revoking the app-specific password at account.apple.com makes it useless everywhere, whatever anyone holds. Deleting an account on the server removes its sealed copies but cannot revoke the password for you. Backups keep deleted data for up to seven days, sealed.
- **Single point of trust in TLS.** The public URL is served by the hosting platform's TLS. The platform and anyone who controls the domain can read traffic. Self-hosting on your own domain moves that trust to you.
- **Rate limiting depends on client addresses.** Sign-in attempts are limited by client address. Behind a platform proxy the server does not yet read the forwarded address, so visitors share one budget (see [self-host.md](self-host.md), Known limits).

## Threat model

| Threat | What happens |
|---|---|
| Database or backup stolen | Ciphertexts and lookup hashes only. No password can be recovered without a token. |
| Logs read | One JSON line per request with the method, the path with any token removed, and the result. No bodies, headers, passwords, tokens or mail. Dependencies are held to `warn` so a tool result is never logged. |
| Token stolen from a client | Attacker can read and act on that account until the token is revoked on the `/account` page. Other tokens of the account are unaffected. Revoke the app-specific password at Apple to be certain. |
| Wrong host receives credentials | Credentials go only to the iCloud hosts allowed in `AGENTS.md`. A redirect to any other host drops the credentials and fails. |
| Malicious mail, event or contact text | Reaches Claude marked as untrusted content. A model can still be tricked, so use a read-only connection (an API key or a connection created with read-only scope) where you do not need to send mail. |
| Password guessing at sign-in | Apple's validation decides; the server also rate-limits attempts per address and per iCloud address. |
| Hostile operator or compromised server code | Can capture passwords at the two moments above. Self-host, or only connect to an instance whose operator you trust. |
| Someone else's account on a shared instance | Each call builds its own session from its own token. An allowlist limits who can sign in on a private instance. |

## What the server does not do

It does not store mail, calendars or contacts, send analytics, or contact anything except iCloud and, when a client identifies itself by a metadata URL, that URL (a three-second fetch).
