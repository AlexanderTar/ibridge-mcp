# Security model of the hosted server

This page describes what the hosted ibridge server (`ibridge serve --hosted`) protects, how, and where the protection ends. The local modes (`serve --stdio`, the loopback daemon) keep the password in your OS keychain and are not covered here. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## What is stored

The server needs your iCloud app-specific password to log in to iCloud for you. It keeps it only sealed:

- The database (`ibridge.db`) holds your iCloud address, one row per connected app or API key, and for each one a ciphertext of your password, a nonce, and a lookup hash of the token.
- It never stores a token. It stores a one-way lookup hash, so it can find the right row when a token arrives.
- There is no master key and no key file. Nothing in the server's settings or storage can decrypt a stored password.

When Sign in with Apple is on (see [Identity and billing](#identity-and-billing)), the database also holds one row per user: the Firebase user id, Apple's user id, the Apple email (a private relay address is fine), a link to the one iCloud account the user connected, and, with billing on, the Stripe customer and subscription ids, the subscription status and its period end, and a complimentary flag. It never holds Apple's or Firebase's tokens or any card detail.

## Sealing

When you sign in, the server checks the password with iCloud, then seals one copy per token it issues:

1. The token (an access token `iba_…`, a refresh token `ibf_…`, or an API key `ibr_…`) is the secret input.
2. Two independent keys come out of it with HKDF-SHA-256 (`ibridge-seal-v1` for encryption, `ibridge-lookup-v1` for the lookup hash). The lookup hash is not the encryption key.
3. The password is encrypted with AES-256-GCM under a random 96-bit nonce. The associated data is the iCloud address and the grant it belongs to, so a ciphertext cannot be moved to another account or grant.
4. Each connected app or key has its own sealed copy. Revoking one removes only its copy.
5. A refresh re-seals the password under the new access and refresh tokens and deletes the old access copy, so the previous access token stops working at once. The refresh token it used keeps a sealed copy for two minutes, and a repeat refresh inside that window leaves the access token the first one issued in place. That is deliberate: two concurrent refreshes from one client must not invalidate each other's access token. That token expires an hour after it was issued. Spent sign-in codes and spent refresh tokens leave an empty marker for 90 days, so reusing one revokes the grant, and then the marker is deleted.

On each `/mcp` request the server derives the key from the bearer token the request carries, opens that copy, logs in to iCloud, and wipes its working copy of the password.

A copy of the database, the backups and every server setting is not enough to read a password: the key exists only in the token that the client holds.

## Limits of sealing

Sealing protects data at rest. It does not stop the running server from seeing the password:

- **The server sees the password at two moments**: when you type it on the sign-in page, and while a request runs. Anyone who controls the running process at those moments, such as an operator or an attacker who changes the code it runs, can capture it. The code is open source and a deployment names the exact commit it runs, which makes a change visible but does not prevent one.
- **Memory.** Working copies of the password are wiped after use, but the mail client library (lettre) keeps the SMTP password in a plain `String` until it sends `AUTH`, and that copy is not wiped. It lives until the send finishes and its memory is freed. A memory dump taken during a call could contain it.
- **Runs as root on Railway.** The image runs as the unprivileged `nonroot` user, but Railway mounts volumes as root, so the public instance sets `RAILWAY_RUN_UID=0` and the server runs as root there. A flaw in the server would have root inside its container.
- **Idle mail sessions.** Logged-in mail connections are kept for up to five minutes after a request to save logging in again. The password is not kept with them.
- **Mail, event and contact text** passes through the server in clear text while a request runs. Sealing covers only the password.
- **Tokens are bearer secrets.** Whoever holds a valid token can use the account until it expires or is revoked: access tokens last one hour, refresh tokens 90 days of non-use, API keys until revoked. Sign-in codes last 60 seconds.
- **The only complete revocation is at Apple.** Revoking the app-specific password at account.apple.com makes it useless everywhere, whatever anyone holds. Deleting an account on the server removes its sealed copies but cannot revoke the password for you. Backups keep deleted data for up to seven days, sealed.
- **Single point of trust in TLS.** The public URL is served by the hosting platform's TLS. The platform and anyone who controls the domain can read traffic. Self-hosting on your own domain moves that trust to you.
- **Rate limiting depends on client addresses.** Sign-in attempts are limited by client address. Behind a platform proxy the operator must set `IBRIDGE_BEHIND_PROXY=true`, so the server reads the forwarded address. Without it, every visitor shares the proxy's budget. With it on and no proxy in front, a client could choose its own address, so it is off by default (see [self-host.md](self-host.md#behind-a-proxy)).

## Identity and billing

Both are optional and off by default. A self-hosted or local server is never gated and needs none of these settings. Partial groups stop the server at startup (see [self-host.md](self-host.md#identity-and-billing-optional)).

- **Sign in with Apple** goes through Firebase. The server redirects the browser to Apple, receives Apple's form post at `/signin/apple/callback`, exchanges the code, and has Firebase turn the Apple identity into a Firebase ID token. It accepts that token only when it is RS256, signed by a key in Google's published set, has audience `ibridge-fyi` (the Firebase project id), the matching Firebase issuer, and is neither expired nor issued in the future. The Apple `client_secret` is an ES256 JWT signed with the Apple key, made per request. Neither the key nor any token is logged or stored.
- **The callback is bound to the browser that started it.** Apple posts it cross-site, so the binder cookie `__Host-ibridge_siwa` is `SameSite=None`. A callback with no cookie, the wrong cookie, a replayed or expired state (10 minutes) is refused. Pending sign-ins and pending authorize requests are capped in number, and `/signin/apple` is rate limited by client address.
- **Delete account** needs a fresh Apple sign-in. The asker's user id travels in the pending sign-in's return target, because the cross-site callback carries no session cookie; the Apple account that signs in must be that user's. The server then cancels every live Stripe subscription on the user's customer at once (and stops the deletion if one that gives access cannot be cancelled), removes the user's rows and sealed copies, ends the user's sessions, revokes the Apple authorization and deletes the Firebase user. Apple and Firebase come last: a failure there is reported, not retried.
- **Stripe** holds the card and the tax. The server never sees a card number. It sends the customer to Stripe-hosted Checkout and the customer portal, and learns the result from `POST /billing/webhook`. The webhook accepts a request only with a valid `Stripe-Signature` (HMAC-SHA-256 over the raw body with `IBRIDGE_STRIPE_WEBHOOK_SECRET`) whose timestamp is within five minutes, ignores an event id it has seen, and takes the subscription's status and period end from a fresh API read, not from the event body. `/billing/return` accepts only a Checkout Session that belongs to the signed-in user. Every Stripe request pins `Stripe-Version`.
- **The access gate** is on `tools/call` only. Without an active plan (or the complimentary flag) a call returns an MCP tool error that links to `/account`; `tools/list` and sign-in still work. `past_due` keeps access. When billing is on, a grant that belongs to no user is denied.
- **Allowlist and billing do not mix for users with no linked address.** A signed-in user who has not connected an iCloud address yet is told the service is private and is not offered a plan, because nobody should pay before the server knows they may join. Comp such a user by uid with `ibridge admin comp`.

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
| Sign-in callback replayed or sent from another browser | Refused: the state is single-use, expires in 10 minutes and must match the binder cookie. |
| Forged Stripe webhook | Refused: bad signature or a timestamp more than five minutes off. A valid event only triggers a re-read from Stripe. |
| Someone else's account on a shared instance | Each call builds its own session from its own token. An allowlist limits who can sign in on a private instance. |

## What the server does not do

It does not store mail, calendars or contacts, or send analytics. It contacts only these hosts:

- iCloud (the hosts in `AGENTS.md`), for the user's own mail, calendar and contacts.
- When a client identifies itself by a metadata URL, that URL (a three-second fetch).
- When Sign in with Apple is on: `appleid.apple.com` (code exchange, revocation), `identitytoolkit.googleapis.com` (Firebase sign-in and user deletion) and `www.googleapis.com` (Google's signing keys for Firebase tokens).
- When billing is on: `api.stripe.com`.

It sends no credential to any of them except that service's own: the Apple key signs only Apple requests, and the Stripe key goes only to `api.stripe.com`.
