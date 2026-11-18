# Deploying the public instance on Railway

This is the runbook for the public instance at `https://ibridge.fyi`. Every step that changes something comes after the account checks in step 1. Do not skip them: this machine's Railway CLI is logged in to a different (work) account, and `vercel` may default to another scope.

Never print the Railway token or an app-specific password. Do not paste either into a command line, a log, an issue or a commit. Steps that read a secret say how to do it without echoing it.

The Railway commands below were checked against `railway` 5.62.1's `--help`. The deploy steps have not been run against a live account; if a command behaves differently, stop and fix the runbook before going on.

## 1. Check the accounts

**Railway.** Use the personal token file for every Railway command in this runbook, and put it on each command itself, as the examples below do. Do not rely on an `export` from an earlier command: an agent runs every command in a fresh shell, and a command without the token falls back to this machine's logged-in work account. Every command after step 3 also names the project with `--project <project id>` (the `id` that `railway init --json` prints), so a command can never act on whatever project the CLI last linked. The CLI refuses `--project` without `--environment` ("--environment is required when using --project"), so each of those commands also carries `--environment production`, the environment `railway init` creates.

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway whoami --json | jq -r .email
```

The address must be the personal account's. If it prints anything else, or `Unauthorized`, stop. Check it again at the start of every new shell, and again before any step that changes something. The variable is `RAILWAY_API_TOKEN` (an account or workspace token), not `RAILWAY_TOKEN` (a project token, which `whoami` rejects). Never run `railway login` for this work, and never `export` the token into a shell you keep.

**Vercel.** `ibridge.fyi` must be in the scope you are about to change:

```sh
vercel whoami
vercel teams ls
vercel domains inspect ibridge.fyi
```

`domains inspect` must say `Domain ibridge.fyi found under <scope>`, and `<scope>` must be one `vercel teams ls` lists for the signed-in user. Pass that scope as `--scope <scope>` on every later `vercel` command. Stop if the domain is not found or the scope is not yours.

## 2. Pick the commit

Deploy a named commit, not a branch. Check out the approved sha in a clean worktree and confirm:

```sh
git rev-parse HEAD && git status --short   # the sha you approved, and no output
docker build -t ibridge:test .             # builds before it is uploaded
```

Write the sha in the deploy notes. `/privacy` tells users each deployment names its exact version, so keep a record.

## 3. Create the project, service and volume

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway init --name ibridge --json
```

Write down the project `id` it prints: it is the `<project id>` in every command below. `railway init` also links the current directory to the project, and `railway add` takes no `--project`, so run `add` from this same directory:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway add --service ibridge
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway volume --project <project id> --environment production --service ibridge add --mount-path /data
```

Run these once. `RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway status --project <project id> --environment production` must show the project you just made and the personal workspace before you continue.

## 4. Set the variables

Start closed, so only you can sign in while you run the datacenter check in step 7:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set --project <project id> --environment production --service ibridge --skip-deploys \
  PORT=8080 RAILWAY_RUN_UID=0 \
  IBRIDGE_SIGNUPS=closed IBRIDGE_SIGNUP_CAP=50 IBRIDGE_BEHIND_PROXY=true \
  IBRIDGE_ALLOWED_APPLE_IDS=<your iCloud address>,<test Apple ID>
printf '%s' '<contact address>' | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_CONTACT --stdin --project <project id> --environment production --service ibridge --skip-deploys
```

The allowlist holds two addresses: yours, and the test Apple ID the datacenter check in step 7 signs in with (`IBRIDGE_TEST_APPLE_ID` in `~/.config/ibridge/test-account.env`). The check refuses an address that is not on the list. Step 14 removes the test account before sign-ups open.

`RAILWAY_RUN_UID=0` is needed because Railway mounts volumes as root, while the image runs as uid 65532. `IBRIDGE_BEHIND_PROXY=true` makes the server rate-limit by the client address Railway's proxy forwards instead of the proxy's own, so visitors get separate sign-in budgets (see [Behind a proxy](self-host.md#behind-a-proxy)). `IBRIDGE_CONTACT` is the address `/privacy` and `/terms` show; the legal review supplies it. To check what is set without showing values, use the dashboard's Variables tab. `railway variable list` prints values, and `--kv` and `--json` print them raw, so none of those forms is safe on a shared screen.

## 5. Deploy and check

Set the start command and health check in the service's settings (Railway dashboard, Settings, Deploy), because the CLI cannot set them:

- Start command: `ibridge serve --hosted --multi-tenant --http 0.0.0.0:8080 --public-url https://ibridge.fyi --data-dir /data`
- Healthcheck path: `/readyz`

Then upload the commit:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway up --project <project id> --environment production --service ibridge --detach
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway logs --project <project id> --environment production --service ibridge
```

The logs must show a line containing `serving MCP over HTTP, hosted`. If the server refuses to start, the message names the setting (for example, closed sign-ups need `IBRIDGE_ALLOWED_APPLE_IDS`). If the container fails with the entrypoint repeated, for example `ibridge ibridge serve`, Railway is appending the start command to the image's entrypoint: remove the leading `ibridge` from the start command, so it starts with `serve`. Do not go on until the deployment is healthy. After the first deploy, record here whether Railway's start command replaced or was added to the image's entrypoint, and whether the apex record needed an ALIAS.

An allowlist limits sign-in even with `--multi-tenant`, so the closed instance accepts only your address.

## 6. Point ibridge.fyi at the service

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway domain ibridge.fyi --project <project id> --environment production --service ibridge --port 8080
```

This prints the DNS records Railway wants (a CNAME target and a `_railway-verify` TXT record). Re-run step 1's `vercel` checks, then add exactly those records, with the scope from step 1:

```sh
vercel dns ls ibridge.fyi --scope <scope>
vercel dns add ibridge.fyi '@' ALIAS <railway target> --scope <scope>
vercel dns add ibridge.fyi '_railway-verify' TXT '<value Railway printed>' --scope <scope>
```

Vercel DNS takes an `ALIAS` record at the apex, where a plain CNAME is not allowed; use the type Railway prints for a subdomain. Add nothing else and do not touch existing records. Then wait for `RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway domain --project <project id> --environment production status ibridge.fyi --service ibridge` to show the certificate issued, and:

```sh
curl -fsS https://ibridge.fyi/readyz     # ready
curl -fsS https://ibridge.fyi/healthz    # ok
```

## 7. Datacenter check

Apple may refuse sign-ins that come from a datacenter address. The server makes the call to Apple when you sign in, so a successful sign-in through the deployed server shows Apple accepts Railway's egress. Run the check from a checkout of the approved commit, with the live test account file in `~/.config/ibridge/test-account.env` (mode `0600`, never printed):

```sh
cargo xtask live-hosted-check --url https://ibridge.fyi
```

It signs in as a client does, calls `account_status`, and prints one line per step with no password, token or code. The account address must be one of the addresses in `IBRIDGE_ALLOWED_APPLE_IDS`. Record the result with the sha and the date. If Apple refuses the sign-in, stop: the public launch cannot go on from this host. Say so, do not retry in a loop, and do not open sign-ups.

This check needs the live test account, and the live recording has not run yet, so it has not run against this host.

## 8. Uptime monitor (you create it)

You create the monitor in your own monitoring service; the runbook does not hold its credentials. Watch `https://ibridge.fyi/healthz` every minute, expect `200` with the body `ok`, and send alerts to yourself. Use `/healthz`, not `/readyz`: Railway already restarts the service on `/readyz`.

## 9. Verify backups

The server writes its first snapshot as soon as it starts, then one a day, and keeps seven.

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway ssh --project <project id> --environment production --service ibridge -- ls -l /data/backups
```

There must be an `ibridge-<UTC time>.db` file. Download it and check it opens, without signing in to anything:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway volume --project <project id> --environment production list
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway volume --project <project id> --environment production files --volume <volume name or id> download /backups/<name> ./check.db
sqlite3 ./check.db 'pragma integrity_check; pragma user_version;'
rm ./check.db
```

`integrity_check` must print `ok`. The file holds only sealed passwords. Check again after 24 hours that a second file appeared. Delete the local copy once you have looked.

## Launch order

The paid-plan launch goes in this order. Each stage must pass before the next starts:

1. Steps 1 to 9: deploy **without** the identity and billing variables, so the instance is the closed app-password server. The datacenter check (step 7) uses that login, and `cargo xtask live-hosted-check` cannot complete a Sign in with Apple, so it must run before step 10.
2. Step 10: set the Sign in with Apple variables.
3. Step 11: the sandbox stage, on the deployed host, with sandbox Stripe keys.
4. Step 12: create the live Stripe objects and swap to live keys.
5. Step 13: the live checks, then link and comp the owner and test user. Do this before you connect Claude.ai and call `account_status`: a grant made before billing was on, such as the datacenter check's, belongs to no user, so it gets the no-plan error. After billing is on, link the owner's address (create an API key on `/account`) and comp it, or disconnect and reconnect Claude.ai so the new grant is tied to the user.
6. Step 14: open sign-ups.

**Status: none of steps 10 to 13 has been run.** Every command and every check in them is untested against the real services, and the restricted live key's permissions are unproven (see step 12).

## 10. Turn on Sign in with Apple

Needs the datacenter check (step 7) to have passed. Values and where they come from:

| Variable | Value | Read in |
|---|---|---|
| `IBRIDGE_APPLE_SERVICES_ID` | `fyi.ibridge.mcp` (App ID `fyi.ibridge`; return URL `https://ibridge.fyi/signin/apple/callback`) | `crates/ibridge-hosted/src/identity/mod.rs` |
| `IBRIDGE_APPLE_TEAM_ID` | `44CQ69ZSP6` | same |
| `IBRIDGE_APPLE_KEY_ID` | `2QKR8GY5WS` | same |
| `IBRIDGE_APPLE_PRIVATE_KEY` | the key file `~/.config/ibridge/AuthKey_2QKR8GY5WS.p8` | same |
| `IBRIDGE_FIREBASE_PROJECT_ID` | `ibridge-fyi` | same |
| `IBRIDGE_FIREBASE_API_KEY` | the Firebase project's web API key (Firebase console, Project settings) | same |

Set every new variable with `--stdin`, so no value is on a command line or in shell history. The Apple key goes in from its file, never printed:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_APPLE_PRIVATE_KEY --stdin --project <project id> --environment production --service ibridge --skip-deploys < ~/.config/ibridge/AuthKey_2QKR8GY5WS.p8
printf '%s' 'fyi.ibridge.mcp' | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_APPLE_SERVICES_ID --stdin --project <project id> --environment production --service ibridge --skip-deploys
printf '%s' '44CQ69ZSP6' | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_APPLE_TEAM_ID --stdin --project <project id> --environment production --service ibridge --skip-deploys
printf '%s' '2QKR8GY5WS' | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_APPLE_KEY_ID --stdin --project <project id> --environment production --service ibridge --skip-deploys
printf '%s' 'ibridge-fyi' | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_FIREBASE_PROJECT_ID --stdin --project <project id> --environment production --service ibridge --skip-deploys
pbpaste | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_FIREBASE_API_KEY --stdin --project <project id> --environment production --service ibridge --skip-deploys   # copy the key first
```

The server refuses to start with half of this group. Do not redeploy yet: step 11 sets the Stripe variables, and billing without identity or `IBRIDGE_CONTACT` (step 4) also stops the server. Keep `IBRIDGE_SIGNUPS=closed` and the allowlist. With billing on, a signed-in person who has not connected an allowlisted iCloud address is told the service is private and is not offered a plan, so everyone who tests must first link an address on the list: on `/account`, create an API key with that address (this links it; the Subscribe button appears afterwards).

## 11. Sandbox stage (deployed host, sandbox Stripe keys)

Do this before any live key goes in. It proves the real Sign in with Apple, a Managed Payments Checkout, the portal and the webhook on the deployed host, none of which a local server or an API-only test can.

| Variable | Sandbox value | Read in |
|---|---|---|
| `IBRIDGE_STRIPE_SECRET_KEY` | a restricted test key (below) | `crates/ibridge-hosted/src/billing/mod.rs` |
| `IBRIDGE_STRIPE_WEBHOOK_SECRET` | the sandbox endpoint's signing secret (below) | same |
| `IBRIDGE_STRIPE_PRICE_MONTHLY`, `IBRIDGE_STRIPE_PRICE_YEARLY` | the sandbox price ids | same |
| `IBRIDGE_STRIPE_TAX` | `managed` | same |

**Keys.** Sandbox account `acct_1UcrvDK0opCePIM6` (Stripe CLI project `ibridge`). Its objects are in `~/.config/ibridge/stripe-sandbox.env`: `IBRIDGE_TEST_STRIPE_SECRET_KEY`, `IBRIDGE_TEST_STRIPE_PRICE_MONTHLY`, `IBRIDGE_TEST_STRIPE_PRICE_YEARLY`, `IBRIDGE_TEST_STRIPE_TAX` and `IBRIDGE_TEST_STRIPE_API_VERSION`. The key in that file is a full `sk_test` key, so it proves nothing about a restricted key. For the server, create a **restricted** test key with exactly the live key's permissions (step 12) in the sandbox Dashboard and use that on the host. If a check below fails with a Stripe permission error, step 12's list is wrong: fix it before going live.

**Webhook endpoint.** Create it on the sandbox with `api_version` equal to the version the server pins (`STRIPE_API_VERSION`, `2026-10-28.endive`, in `crates/ibridge-hosted/src/billing/stripe.rs`), so events carry the shapes the server reads. Stripe returns the signing secret once; pipe it straight into Railway. It needs the full test key (a restricted key without Webhook Endpoints permission is refused):

```sh
(set -eo pipefail; set -a; . ~/.config/ibridge/stripe-sandbox.env; set +a
 curl -fsS https://api.stripe.com/v1/webhook_endpoints -u "$IBRIDGE_TEST_STRIPE_SECRET_KEY:" \
   -d url=https://ibridge.fyi/billing/webhook -d api_version=2026-10-28.endive \
   -d 'enabled_events[]=checkout.session.completed' \
   -d 'enabled_events[]=customer.subscription.created' \
   -d 'enabled_events[]=customer.subscription.updated' \
   -d 'enabled_events[]=customer.subscription.deleted' \
   -d 'enabled_events[]=invoice.paid' \
   -d 'enabled_events[]=invoice.payment_failed' \
 | jq -er .secret \
 | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_STRIPE_WEBHOOK_SECRET --stdin --project <project id> --environment production --service ibridge --skip-deploys)
```

Set the other four the same way, with `--stdin`, never printed: the restricted test key from the Dashboard (`pbpaste | … --stdin`, copy it first; the env file holds only the full key and must not go on the host), and the two price ids and `managed` from the env file inside a subshell. Then deploy and check:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway up --project <project id> --environment production --service ibridge --detach
curl -fsS https://ibridge.fyi/readyz
curl -sS -o /dev/null -w '%{http_code}\n' -X POST https://ibridge.fyi/billing/webhook -d '{}'   # 400: the route exists and rejects an unsigned body (404 means billing is off)
```

**Checks.** Use a browser, a real Apple ID whose iCloud address is on the allowlist, and Stripe's test card `4242 4242 4242 4242`. Record each result with the sha and the date:

1. `/account` offers Sign in with Apple. Sign in: Apple posts to `/signin/apple/callback` and you land on `/account`.
2. Link the address, then connect. On `/account`, create an API key with your allowlisted iCloud address; this links it and Subscribe appears. Connect Claude.ai (`/authorize`): with no plan you are asked to choose one and sent to checkout. Without a linked address the closed host shows "service is private" and offers no checkout.
3. Checkout (Managed Payments): pay with the test card. `/billing/return` returns you to `/account` (or resumes `/authorize`), the status is active and `tools/call` works. A completed Managed Payments Checkout has never been captured, so open the sandbox webhook deliveries, find `checkout.session.completed` and confirm the server answered 2xx.
4. Portal: `/account` opens the customer portal; switch monthly to yearly. The status stays active and a `customer.subscription.updated` delivery arrives.
5. Cancel in the portal. The status stays active until the period end, then access turns off.
6. Renewal and failure. The server creates its customers without a test clock and Stripe cannot move an existing customer onto one, so a test clock cannot advance a Checkout-made subscription. Force a renewal with `stripe subscriptions update <sub id> --billing-cycle-anchor=now --proration-behavior=none --project-name ibridge` (an invoice and `invoice.paid` follow). For a failure, first switch the portal's card to `4000 0000 0000 0341`, then force the renewal: `invoice.payment_failed`, status `past_due`, and access stays on. The test-clock lifecycle itself is covered by `stripe_sandbox_round_trip` (below).
7. Delete: `/account`, delete account, sign in with Apple again. The Stripe subscription is cancelled at once, `tools/call` is refused, the user and its sealed copies are gone, and the Apple authorization and Firebase user are removed (Firebase console, Authentication, Users).
8. An unsigned or stale webhook gets 400.

**The API-only test.** The ignored `stripe_sandbox_round_trip` test runs the Stripe client against the sandbox: customer, Checkout Sessions in both tax modes, a test-clock subscription, portal session, subscription read and delete. It reads `~/.config/ibridge/stripe-sandbox.env` and refuses a key that is not a test key. It cannot complete a Checkout page, so it does not replace the checks above, and CI does not run it:

```sh
(set -a; . ~/.config/ibridge/stripe-sandbox.env; set +a
 cargo nextest run -p ibridge-hosted --run-ignored only -E 'test(stripe_sandbox_round_trip)')
```

## 12. Live Stripe and the swap to live keys

Only after step 11 passes. The live account is `acct_1UcveBK7W1ABbSCm`. The owner reports country GB, charges enabled and Managed Payments activated; the Stripe CLI here cannot read it, so confirm those in the Dashboard first.

Create these in the **live** Dashboard (or the Stripe CLI logged in to the live account by the owner), mirroring the sandbox:

- Product `ibridge hosted`, tax code `txcd_10103000` (SaaS, personal use).
- Monthly price US$1.99 and yearly price US$19.99, both `tax_behavior` exclusive.
- Customer portal configuration: cancel at period end; switch between the two prices (proration `create_prorations`); update payment method; invoice history; default return URL `https://ibridge.fyi/account`.
- Webhook endpoint `https://ibridge.fyi/billing/webhook` with `api_version` `2026-10-28.endive` and the six events from step 11.
- Restricted key `ibridge-server-live`, with exactly the permissions the client's calls need and everything else None. The calls are `POST /v1/customers`, `POST` and `GET /v1/checkout/sessions`, `POST /v1/billing_portal/sessions`, and `GET` and `DELETE /v1/subscriptions/{id}`. So **Write**: Customers, Checkout Sessions, Customer portal, Subscriptions; **Read**: Prices. The server makes no call to `/v1/prices`, so Prices read is a precaution for Checkout naming a price. **This list is unproven**: the sandbox key used so far is a full `sk_test` key. Step 11's restricted test key is the proof; if it needed more or less, change this list to match.

Then swap. Delete the sandbox webhook endpoint (the server holds one secret) and set the live values with `--stdin`:

```sh
pbpaste | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_STRIPE_SECRET_KEY --stdin --project <project id> --environment production --service ibridge --skip-deploys       # copy the live restricted key first
pbpaste | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_STRIPE_WEBHOOK_SECRET --stdin --project <project id> --environment production --service ibridge --skip-deploys   # copy the live endpoint's signing secret first
printf '%s' '<live monthly price id>' | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_STRIPE_PRICE_MONTHLY --stdin --project <project id> --environment production --service ibridge --skip-deploys
printf '%s' '<live yearly price id>' | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_STRIPE_PRICE_YEARLY --stdin --project <project id> --environment production --service ibridge --skip-deploys
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway up --project <project id> --environment production --service ibridge --detach
```

## 13. Live checks and comps

None of these has been run. Tick each with the sha and the date when done:

- [ ] Real Sign in with Apple on `https://ibridge.fyi` with the Services ID `fyi.ibridge.mcp`.
- [ ] The live webhook endpoint exists with the pinned `api_version` and the six events, and its first delivery is answered 2xx.
- [ ] One live Checkout with a user who is **not** comped (the host is closed, so first link an allowlisted address on `/account` by creating an API key), US$1.99 on a real card: `/billing/return` shows an active plan and `tools/call` works. Then cancel from the portal and refund the charge in the Dashboard.
- [ ] Comp the owner and the test user, so they are never charged. Each must have signed in with Apple once and linked their iCloud address (an API key on `/account`), because comp matches a user row and a grant only counts once it belongs to that user. `ibridge admin comp` takes the Apple email (a private relay address is fine) or the Firebase uid:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway ssh --project <project id> --environment production --service ibridge -- ibridge admin comp <owner's Apple email>
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway ssh --project <project id> --environment production --service ibridge -- ibridge admin comp <test user's Apple email>
```

  Each prints `<email> now has the plan for free.`, or fails with `no user has the email or uid …` if that person has not signed in yet. `ibridge admin uncomp <email or uid>` takes the free access away; a subscription the person pays for still counts.
- [ ] The comped owner's `tools/call` works with no subscription; an uncomped user with none gets the tool error that links to `/account`.

## 14. Open sign-ups at 50

Only after steps 5 to 13 pass and you have connected Claude.ai to `https://ibridge.fyi/mcp` and called `account_status` yourself, after the owner's address is linked and comped (step 13); a connection made earlier gets the no-plan error until you reconnect. First remove the test account the datacenter check created, so it does not use up one of the 50 places (it holds a sealed password for the test Apple ID until you do):

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway ssh --project <project id> --environment production --service ibridge -- ibridge admin delete <test Apple ID>
```

It prints how many accounts it deleted; `1` is expected. If you keep the test account instead, it counts toward the cap like any other. Then remove the allowlist and open sign-ups at the cap:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable delete IBRIDGE_ALLOWED_APPLE_IDS --project <project id> --environment production --service ibridge
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_SIGNUPS=open IBRIDGE_SIGNUP_CAP=50 --project <project id> --environment production --service ibridge
```

Your own account was created while the instance was closed, so it counts toward the cap. Check `/` and `/account`, then watch `RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway logs --project <project id> --environment production --service ibridge` for the first sign-ups. To close again, set `IBRIDGE_SIGNUPS=closed` and `IBRIDGE_ALLOWED_APPLE_IDS` back to your address (and the test Apple ID, if you will run the datacenter check again). To raise the cap, change `IBRIDGE_SIGNUP_CAP`.

## Operating

- **Suspend or delete an account:** `RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway ssh --project <project id> --environment production --service ibridge -- ibridge admin suspend <address>` or `... delete <address>`. The command runs outside the server process, so the server refuses the account's tokens from the next call but its idle mail sessions close on their own within five minutes. Then tell the person to revoke the app-specific password at Apple.
- **Comp or uncomp a user:** `... ibridge admin comp <Apple email or Firebase uid>` and `... uncomp <...>`, run the same way (step 13).
- **Deploy a new version:** pick the commit as in step 2, then `RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway up --project <project id> --environment production --service ibridge --detach`. A deploy restarts the service and ends open sessions; people reconnect without signing in again.
- **Rate limits behind Railway's proxy:** `IBRIDGE_BEHIND_PROXY=true` is part of the variables in step 4. If sign-in limits ever lock everyone out together, check it is set with the dashboard's Variables tab, and see [Behind a proxy](self-host.md#behind-a-proxy).
- **Roll back:** redeploy the previous sha with `railway up` (with the token, `--project` and `--environment production`, as above), or use Railway's deployment history. The database is forward-only: `/readyz` fails if a snapshot or a rollback meets a different schema, so restore a snapshot taken by the older build.
