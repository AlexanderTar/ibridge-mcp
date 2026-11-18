# Deploying the public instance on Railway

This is the runbook for the public instance at `https://mcp.ibridge.fyi`, the hosted connector (`https://mcp.ibridge.fyi/mcp`). The product site `https://ibridge.fyi` is a separate site with its own `/privacy` and `/terms`; it is not served by this server. Every step that changes something comes after the account checks in step 1. Do not skip them: this machine's Railway CLI is logged in to a different (work) account, and `vercel` may default to another scope.

Never print the Railway token or an app-specific password. Do not paste either into a command line, a log, an issue or a commit. Steps that read a secret say how to do it without echoing it.

The Railway commands below were checked against `railway` 5.62.1's `--help`. The first deploy has been run once; what it settled is recorded below. If a command behaves differently, stop and fix the runbook before going on.

## The first deploy

What it settled, and where each point is used below:

- **Where it runs.** Railway project `e20f91a4-970a-483e-86af-f10d5107b4d9`, service `ibridge`, environment `production`, deployed from commit `9c1e17a`. These ids are not secrets.
- **Host.** `mcp.ibridge.fyi`, a subdomain: a `CNAME` to `dymkwjd1.up.railway.app` and a `_railway-verify.mcp` `TXT` record, both on Vercel DNS (step 6). The apex `ibridge.fyi` is the product site and is not pointed at Railway.
- **Start command.** Railway's start command replaces the image's entrypoint, so it starts with the program, `ibridge serve ...`, not `serve ...` (step 5).
- **Sign-in domains.** The Apple Services ID's return URL is `<public-url>/signin/apple/callback`, here `https://mcp.ibridge.fyi/signin/apple/callback`, and the Firebase project's authorized domains must include the server's host, `mcp.ibridge.fyi` (step 10).
- **Stripe.** The live objects were created through the Stripe API, and the sandbox stage (step 11) was skipped by the owner's choice. The ids are in step 12.
- **`railway ssh`.** It needs an SSH key registered on the personal Railway account (step 9).
- **Datacenter test account.** It is the owner's own Apple ID, so step 14's `ibridge admin delete` is skipped.

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

Apple's Sign in with Apple logo (`crates/ibridge-hosted/assets/apple-logo-white.svg` and `apple-logo-black.svg`) is committed in the repository, unmodified, so any build from a clean clone shows it: `docker build`, `railway up`, or a Railway deploy that builds the GitHub repository. There is no step to add it and no ignore file to keep it in the upload. It is Apple's artwork, not covered by the Apache-2.0 licence (see `crates/ibridge-hosted/assets/NOTICE`).

## 3. Create the project, service and volume

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway init --name ibridge --json
```

Write down the project `id` it prints: it is the `<project id>` in every command below. `railway init` also links the current directory to the project, and `railway add` takes no `--project`, so run `add` from this same directory:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway add --service ibridge
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway status --project <project id> --environment production --json | jq -c '{env: [.environments.edges[].node | {id, name}], services: [.services.edges[].node | {id, name}]}'
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway volume --project <project id> --environment <environment id> --service <service id> add --mount-path /data --json
```

`railway volume` takes the environment and service **ids** (the first command prints them): with the names `production` and `ibridge`, `railway` 5.62.1 panics (`called Option::unwrap() on a None value`). `railway volume list` can show an empty list right after `add`; the service's `RAILWAY_VOLUME_MOUNT_PATH` variable shows the volume is attached. Run these once. `RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway status --project <project id> --environment production` must show the project you just made and the personal workspace before you continue.

## 4. Set the variables

Start closed, so only you can sign in while you run the datacenter check in step 7:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set --project <project id> --environment production --service ibridge --skip-deploys \
  PORT=8080 RAILWAY_RUN_UID=0 \
  IBRIDGE_SIGNUPS=closed IBRIDGE_SIGNUP_CAP=50 IBRIDGE_BEHIND_PROXY=true \
  IBRIDGE_ALLOWED_APPLE_IDS=<your iCloud address>,<test Apple ID>
printf '%s' '<contact address>' | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_CONTACT --stdin --project <project id> --environment production --service ibridge --skip-deploys
```

The allowlist holds your address and the test Apple ID the datacenter check in step 7 signs in with (`IBRIDGE_TEST_APPLE_ID` in `~/.config/ibridge/test-account.env`). The check refuses an address that is not on the list. For the first deploy the test account is the owner's own Apple ID, so both are the same address. If you use a different test Apple ID, step 14 removes its account before sign-ups open; with your own Apple ID that removal is skipped.

`RAILWAY_RUN_UID=0` is needed because Railway mounts volumes as root, while the image runs as uid 65532. `IBRIDGE_BEHIND_PROXY=true` makes the server rate-limit by the client address Railway's proxy forwards instead of the proxy's own, so visitors get separate sign-in budgets (see [Behind a proxy](self-host.md#behind-a-proxy)). `IBRIDGE_CONTACT` is the address `/privacy` and `/terms` show; the legal review supplies it. To check what is set without showing values, use the dashboard's Variables tab. `railway variable list` prints values, and `--kv` and `--json` print them raw, so none of those forms is safe on a shared screen.

## 5. Deploy and check

Set the start command and health check in the service's settings (Railway dashboard, Settings, Deploy), or through Railway's public API with the same token (the CLI cannot set them):

- Start command: `ibridge serve --hosted --multi-tenant --http 0.0.0.0:8080 --public-url https://mcp.ibridge.fyi --data-dir /data`
- Healthcheck path: `/readyz`

Through the API (`<service id>` and `<environment id>` from step 3; `printf` is a shell builtin, so the token never appears in a process list):

```sh
jq -n --arg s '<service id>' --arg e '<environment id>' '{query: "mutation($s:String!,$e:String!,$i:ServiceInstanceUpdateInput!){serviceInstanceUpdate(serviceId:$s,environmentId:$e,input:$i)}", variables: {s: $s, e: $e, i: {startCommand: "ibridge serve --hosted --multi-tenant --http 0.0.0.0:8080 --public-url https://mcp.ibridge.fyi --data-dir /data", healthcheckPath: "/readyz"}}}' \
  | curl -fsS https://backboard.railway.com/graphql/v2 -H @<(printf 'Authorization: Bearer %s\n' "$(cat ~/.config/railway-personal/token)") -H 'Content-Type: application/json' -d @-
```

It prints `{"data":{"serviceInstanceUpdate":true}}`.

The Dockerfile must not declare `VOLUME`: Railway fails the build with `docker VOLUME ... is not supported, use Railway Volumes`.

Then deploy the commit. The service builds the `Dockerfile` from the GitHub repository `AlexanderTar/icloud-mcp`, so a push to `main` deploys; `railway up` uploads a local checkout and is the manual fallback (an incident, or a commit that is not on `main`).

**Connect the GitHub repository (once).** In the Railway dashboard, open the `ibridge` service, Settings, Source, and connect the repository `AlexanderTar/icloud-mcp`. This needs the Railway GitHub app installed on that repository (Railway asks for it the first time). Then set:

- Branch: `main`.
- Auto-deploy: on, so every push to `main` builds and deploys. Turn on "Wait for CI" so a push deploys only after the repository's checks pass.
- Root directory: leave empty (the `Dockerfile` is at the repository root).

The Dockerfile and the committed logo files are all the build needs: there is no ignore file to keep in sync. Check the Deployments tab for the new build, then `/readyz` and the logs as below. Whoever can push to `main` can deploy, so keep branch protection on `main` (pull requests with the checks required).

**Manual deploy from a checkout (fallback).** Use it only when GitHub deploys are off or the commit is not on `main`:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway up --project <project id> --environment production --service ibridge --detach
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway logs --project <project id> --environment production --service ibridge
```

The logs must show a line containing `serving MCP over HTTP, hosted`. If the server refuses to start, the message names the setting (for example, closed sign-ups need `IBRIDGE_ALLOWED_APPLE_IDS`). Railway's start command replaces the image's entrypoint (the first deploy showed this), so the command above names the program, `ibridge`. Do not go on until the deployment is healthy.

An allowlist limits sign-in even with `--multi-tenant`, so the closed instance accepts only your address.

## 6. Point mcp.ibridge.fyi at the service

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway domain mcp.ibridge.fyi --project <project id> --environment production --service ibridge --port 8080
```

This prints the DNS records Railway wants: a CNAME target (for the first deploy, `dymkwjd1.up.railway.app`) and a `_railway-verify` TXT record. `mcp` is a subdomain, so the records are a plain `CNAME` named `mcp` and a TXT record named `_railway-verify.mcp`. Re-run step 1's `vercel` checks, then add exactly those records on the `ibridge.fyi` zone in Vercel DNS, with the scope from step 1:

```sh
vercel dns ls ibridge.fyi --scope <scope>
vercel dns add ibridge.fyi mcp CNAME <railway target> --scope <scope>
vercel dns add ibridge.fyi _railway-verify.mcp TXT '<value Railway printed>' --scope <scope>
```

Add nothing else and do not touch existing records, above all the apex, which serves the product site. Then wait for `RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway domain --project <project id> --environment production status mcp.ibridge.fyi --service ibridge` to show the certificate issued, and:

```sh
curl -fsS https://mcp.ibridge.fyi/readyz     # ready
curl -fsS https://mcp.ibridge.fyi/healthz    # ok
```

## 7. Datacenter check

Apple may refuse sign-ins that come from a datacenter address. The server makes the call to Apple when you sign in, so a successful sign-in through the deployed server shows Apple accepts Railway's egress. Run the check from a checkout of the approved commit, with the live test account file in `~/.config/ibridge/test-account.env` (mode `0600`, never printed):

```sh
cargo xtask live-hosted-check --url https://mcp.ibridge.fyi
```

It signs in as a client does, calls `account_status`, and prints one line per step with no password, token or code. The account address must be one of the addresses in `IBRIDGE_ALLOWED_APPLE_IDS`. The test account is the owner's own Apple ID, so the sign-in creates the owner's real account on the host. Record the result with the sha and the date. If Apple refuses the sign-in, stop: the public launch cannot go on from this host. Say so, do not retry in a loop, and do not open sign-ups.

**Result on the first deploy:** passed on 2026-11-18 at `9c1e17a` against `https://mcp.ibridge.fyi`: discovery, registration, sign-in, token and `account_status` all ok, with mail, calendar and contacts on. Apple accepts sign-ins from Railway's egress.

## 8. Uptime monitor (you create it)

You create the monitor in your own monitoring service; the runbook does not hold its credentials. Watch `https://mcp.ibridge.fyi/healthz` every minute, expect `200` with the body `ok`, and send alerts to yourself. Use `/healthz`, not `/readyz`: Railway already restarts the service on `/readyz`.

## 9. Verify backups

`railway ssh` needs an SSH key registered on the personal Railway account: without one the command cannot connect. List the registered keys, and register a local one if there is none (`railway ssh keys add` registers a local key, `railway ssh keys github` imports yours from GitHub):

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway ssh keys list
```

This applies to every `railway ssh` command in this runbook: the backup check, the `ibridge admin` commands in steps 13 and 14, and the operating commands.

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
3. Step 11: the sandbox stage, on the deployed host, with sandbox Stripe keys. The owner skipped it for the first launch.
4. Step 12: create the live Stripe objects and swap to live keys. The objects exist; the key swap is not done.
5. Step 13: the live checks, then link and comp the owner and test user. Do this before you connect Claude.ai and call `account_status`: a grant made before billing was on, such as the datacenter check's, belongs to no user, so it gets the no-plan error. After billing is on, comp the owner first, then link the owner's address (create an API key on `/account`; with billing on a key for a new address needs a plan or a comp), or disconnect and reconnect Claude.ai so the new grant is tied to the user.
6. Step 14: open sign-ups.

**Status after the first deploy (2026-11-18):** the service is deployed and `mcp.ibridge.fyi` points at it (step 6); the datacenter check (step 7) passed; the first backup was downloaded and `pragma integrity_check` printed `ok` (step 9); Sign in with Apple is on and the owner signed in with it (step 10); the live Stripe objects and keys are in place (step 12) and the owner is comped (step 13); the live checkout check in step 13 has not run yet. Step 11 was skipped by the owner's choice, so nothing has proved the restricted key's permission list against Stripe; the live Stripe objects in step 12 exist. This runbook does not record the live checks in step 13 or the swap to live keys as done, so treat the commands in steps 10 to 13 as untested against the real services.

## 10. Turn on Sign in with Apple

Needs the datacenter check (step 7) to have passed. Values and where they come from:

| Variable | Value | Read in |
|---|---|---|
| `IBRIDGE_APPLE_SERVICES_ID` | `fyi.ibridge.mcp` (App ID `fyi.ibridge`; the Services ID's return URL is `<public-url>/signin/apple/callback`, here `https://mcp.ibridge.fyi/signin/apple/callback`) | `crates/ibridge-hosted/src/identity/mod.rs` |
| `IBRIDGE_APPLE_TEAM_ID` | `44CQ69ZSP6` | same |
| `IBRIDGE_APPLE_KEY_ID` | `2QKR8GY5WS` | same |
| `IBRIDGE_APPLE_PRIVATE_KEY` | the key file `~/.config/ibridge/AuthKey_2QKR8GY5WS.p8` | same |
| `IBRIDGE_FIREBASE_PROJECT_ID` | `ibridge-fyi` | same |
| `IBRIDGE_FIREBASE_API_KEY` | the Firebase project's web API key (Firebase console, Project settings) | same |

Two things outside Railway must match the host before sign-in works. In the Apple Developer account, the Services ID's return URL must be exactly `https://mcp.ibridge.fyi/signin/apple/callback`, which is the server's `--public-url` plus `/signin/apple/callback`. In the Firebase console (Authentication, Settings, Authorized domains), the project's authorized domains must include `mcp.ibridge.fyi`. A change of `--public-url` means changing both.

Set every new variable with `--stdin`, so no value is on a command line or in shell history. The Apple key goes in from its file, never printed:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_APPLE_PRIVATE_KEY --stdin --project <project id> --environment production --service ibridge --skip-deploys < ~/.config/ibridge/AuthKey_2QKR8GY5WS.p8
printf '%s' 'fyi.ibridge.mcp' | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_APPLE_SERVICES_ID --stdin --project <project id> --environment production --service ibridge --skip-deploys
printf '%s' '44CQ69ZSP6' | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_APPLE_TEAM_ID --stdin --project <project id> --environment production --service ibridge --skip-deploys
printf '%s' '2QKR8GY5WS' | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_APPLE_KEY_ID --stdin --project <project id> --environment production --service ibridge --skip-deploys
printf '%s' 'ibridge-fyi' | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_FIREBASE_PROJECT_ID --stdin --project <project id> --environment production --service ibridge --skip-deploys
pbpaste | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_FIREBASE_API_KEY --stdin --project <project id> --environment production --service ibridge --skip-deploys   # copy the key first
```

The server refuses to start with half of this group. Do not redeploy yet: step 11 sets the Stripe variables, and billing without identity or `IBRIDGE_CONTACT` (step 4) also stops the server. Keep `IBRIDGE_SIGNUPS=closed` and the allowlist. With billing on, a signed-in person who has not connected an allowlisted iCloud address is told the service is private and is not offered a plan, so everyone who tests must first link an address on the list. Linking takes a sign-up slot, so with billing on it needs access: a person with no plan cannot link by creating a key (they are told to choose a plan, and none is offered). Sign in with Apple once, run `ibridge admin comp <Apple email or Firebase uid>` (step 13) for that person, then on `/account` create an API key with the address (this links it). For a tester who should pay, run `ibridge admin uncomp <...>` afterwards; the Subscribe button appears once the address is linked.

## 11. Sandbox stage (deployed host, sandbox Stripe keys)

**Skipped for the first launch, by the owner's choice.** The live objects of step 12 were created without it, so the restricted key's permission list and Managed Payments Checkout have not been proven against Stripe's sandbox. Keep the section for the next change to billing.

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
   -d url=https://mcp.ibridge.fyi/billing/webhook -d api_version=2026-10-28.endive \
   -d 'enabled_events[]=checkout.session.completed' \
   -d 'enabled_events[]=customer.subscription.created' \
   -d 'enabled_events[]=customer.subscription.updated' \
   -d 'enabled_events[]=customer.subscription.deleted' \
   -d 'enabled_events[]=invoice.paid' \
   -d 'enabled_events[]=invoice.payment_failed' \
 | jq -er .secret \
 | RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_STRIPE_WEBHOOK_SECRET --stdin --project <project id> --environment production --service ibridge --skip-deploys)
```

Set the other four the same way, with `--stdin`, never printed: the restricted test key from the Dashboard (`pbpaste | … --stdin`, copy it first; the env file holds only the full key and must not go on the host), and the two price ids and `managed` from the env file inside a subshell. Then deploy (the new variables apply on the next deploy; with GitHub deploys, redeploy the latest from the Deployments tab, or run the fallback below) and check:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway up --project <project id> --environment production --service ibridge --detach
curl -fsS https://mcp.ibridge.fyi/readyz
curl -sS -o /dev/null -w '%{http_code}\n' -X POST https://mcp.ibridge.fyi/billing/webhook -d '{}'   # 400: the route exists and rejects an unsigned body (404 means billing is off)
```

**Checks.** Use a browser, a real Apple ID whose iCloud address is on the allowlist, and Stripe's test card `4242 4242 4242 4242`. Record each result with the sha and the date:

1. `/account` offers Sign in with Apple. Sign in: Apple posts to `/signin/apple/callback` and you land on `/account`.
2. Link the address, then connect. Have the test user comped first (`ibridge admin comp`, step 13), because a key for a new address needs access. On `/account`, create an API key with the allowlisted iCloud address; this links it. Then `ibridge admin uncomp` the user, and Subscribe appears. Connect Claude.ai (`/authorize`): with no plan you are asked to choose one and sent to checkout. Without a linked address the closed host shows "service is private" and offers no checkout.
3. Checkout (Managed Payments): pay with the test card. `/billing/return` returns you to `/account` (or resumes `/authorize`), the status is active and `tools/call` works. A completed Managed Payments Checkout has never been captured, so open the sandbox webhook deliveries, find `checkout.session.completed` and confirm the server answered 2xx.
4. Portal: `/account` opens the customer portal; switch monthly to yearly. The status stays active and a `customer.subscription.updated` delivery arrives.
5. Cancel in the portal. The status stays active until the period end, then access turns off.
6. Renewal and failure. The server creates its customers without a test clock and Stripe cannot move an existing customer onto one, so a test clock cannot advance a Checkout-made subscription. Force a renewal with `stripe subscriptions update <sub id> --billing-cycle-anchor=now --proration-behavior=none --project-name ibridge` (an invoice and `invoice.paid` follow). For a failure, first switch the portal's card to `4000 0000 0000 0341`, then force the renewal: `invoice.payment_failed`, status `past_due`, and access stays on. The test-clock lifecycle itself is covered by `stripe_sandbox_round_trip` (below).
7. Delete: `/account`, delete account, sign in with Apple again. Every live Stripe subscription on the customer is cancelled at once, `tools/call` is refused, the user and its sealed copies are gone, and the Apple authorization and Firebase user are removed (Firebase console, Authentication, Users).
8. An unsigned or stale webhook gets 400.

**The API-only test.** The ignored `stripe_sandbox_round_trip` test runs the Stripe client against the sandbox: customer, Checkout Sessions in both tax modes, a test-clock subscription, portal session, subscription read and delete. It reads `~/.config/ibridge/stripe-sandbox.env` and refuses a key that is not a test key. It cannot complete a Checkout page, so it does not replace the checks above, and CI does not run it:

```sh
(set -a; . ~/.config/ibridge/stripe-sandbox.env; set +a
 cargo nextest run -p ibridge-hosted --run-ignored only -E 'test(stripe_sandbox_round_trip)')
```

## 12. Live Stripe and the swap to live keys

Only after step 11 passes. The live account is `acct_1UcveBK7W1ABbSCm`. The owner reports country GB, charges enabled and Managed Payments activated; the Stripe CLI here cannot read it, so confirm those in the Dashboard first.

The live objects were created through the Stripe API (sandbox stage skipped, see step 11), mirroring the sandbox. Their ids, which are not secrets:

| Object | Id |
|---|---|
| Product (tax code `txcd_10103000`, SaaS, personal use) | `prod_VeTQJWSFlbuWDm` |
| Monthly price, US$1.99 (`IBRIDGE_STRIPE_PRICE_MONTHLY`) | `price_1UdATsK7W1ABbSCmQllObfNX` |
| Yearly price, US$19.99 (`IBRIDGE_STRIPE_PRICE_YEARLY`) | `price_1UdATsK7W1ABbSCmn1p14S1B` |
| Customer portal configuration | `bpc_1UdATsK7W1ABbSCmxHvxhzH7` |
| Webhook endpoint `https://mcp.ibridge.fyi/billing/webhook` | `we_1UdAU7K7W1ABbSCmIshZolTF` |

If you have to create them again (in the **live** Dashboard, the API, or the Stripe CLI logged in to the live account by the owner):

- Product with tax code `txcd_10103000` (SaaS, personal use).
- Monthly price US$1.99 and yearly price US$19.99, both `tax_behavior` exclusive.
- Customer portal configuration: cancel at period end; switch between the two prices (proration `create_prorations`); update payment method; invoice history; default return URL `https://mcp.ibridge.fyi/account`.
- Webhook endpoint `https://mcp.ibridge.fyi/billing/webhook` with `api_version` `2026-10-28.endive` and the six events from step 11. Stripe shows the signing secret only when the endpoint is created, and this runbook does not hold it.
- Restricted key `ibridge-server-live`, with exactly the permissions the client's calls need and everything else None. The calls are `POST /v1/customers`, `POST` and `GET /v1/checkout/sessions`, `POST /v1/billing_portal/sessions`, `GET /v1/subscriptions?customer=...&status=all`, and `GET` and `DELETE /v1/subscriptions/{id}`. So **Write**: Customers, Checkout Sessions, Customer portal, Subscriptions; **Read**: Prices. The server makes no call to `/v1/prices`, so Prices read is a precaution for Checkout naming a price. **This list is unproven**: the sandbox key used so far is a full `sk_test` key. Step 11's restricted test key is the proof; if it needed more or less, change this list to match.

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

- [ ] Real Sign in with Apple on `https://mcp.ibridge.fyi` with the Services ID `fyi.ibridge.mcp`.
- [ ] The live webhook endpoint exists with the pinned `api_version` and the six events, and its first delivery is answered 2xx.
- [ ] One live Checkout with a user who is **not** comped (the host is closed, so first comp them, link an allowlisted address on `/account` by creating an API key, then uncomp them: a key for a new address needs access when billing is on), US$1.99 on a real card: `/billing/return` shows an active plan and `tools/call` works. Then cancel from the portal and refund the charge in the Dashboard.
- [ ] Comp the owner and the test user, so they are never charged. Each must have signed in with Apple once, because comp matches a user row; comp them before they link their iCloud address (an API key on `/account`, which needs access when billing is on), because a grant only counts once it belongs to that user. `ibridge admin comp` takes the Apple email (a private relay address is fine) or the Firebase uid:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway ssh --project <project id> --environment production --service ibridge -- ibridge admin comp <owner's Apple email>
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway ssh --project <project id> --environment production --service ibridge -- ibridge admin comp <test user's Apple email>
```

  Each prints `<email> now has the plan for free.`, or fails with `no user has the email or uid …` if that person has not signed in yet. `ibridge admin uncomp <email or uid>` takes the free access away; a subscription the person pays for still counts.
- [ ] The comped owner's `tools/call` works with no subscription; an uncomped user with none gets the tool error that links to `/account`.

## 14. Open sign-ups at 50

Only after steps 5 to 13 pass and you have connected Claude.ai to `https://mcp.ibridge.fyi/mcp` and called `account_status` yourself, after the owner's address is linked and comped (step 13); a connection made earlier gets the no-plan error until you reconnect. **Skip the delete below for the first launch:** the datacenter test account is the owner's own Apple ID, and `delete` would remove the owner's real account. The owner's account counts toward the cap like any other. If the datacenter check used a test Apple ID that is not the owner's, first remove that account, so it does not use up one of the 50 places (it holds a sealed password for the test Apple ID until you do):

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway ssh --project <project id> --environment production --service ibridge -- ibridge admin delete <test Apple ID>
```

It prints how many accounts it deleted; `1` is expected. Then remove the allowlist and open sign-ups at the cap:

```sh
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable delete IBRIDGE_ALLOWED_APPLE_IDS --project <project id> --environment production --service ibridge
RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway variable set IBRIDGE_SIGNUPS=open IBRIDGE_SIGNUP_CAP=50 --project <project id> --environment production --service ibridge
```

Your own account was created while the instance was closed, so it counts toward the cap. Check `/` and `/account`, then watch `RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway logs --project <project id> --environment production --service ibridge` for the first sign-ups. To close again, set `IBRIDGE_SIGNUPS=closed` and `IBRIDGE_ALLOWED_APPLE_IDS` back to your address (and the test Apple ID, if you will run the datacenter check again). To raise the cap, change `IBRIDGE_SIGNUP_CAP`.

## Operating

- **Suspend or delete an account:** `RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway ssh --project <project id> --environment production --service ibridge -- ibridge admin suspend <address>` or `... delete <address>`. The command runs outside the server process, so the server refuses the account's tokens from the next call but its idle mail sessions close on their own within five minutes. Then tell the person to revoke the app-specific password at Apple.
- **Comp or uncomp a user:** `... ibridge admin comp <Apple email or Firebase uid>` and `... uncomp <...>`, run the same way (step 13).
- **Deploy a new version:** merge the approved pull request into `main`. Railway builds that commit from GitHub and deploys it (step 5 sets this up); watch the Deployments tab and `/readyz`. If GitHub deploys are off, check out the approved sha as in step 2 and run `RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)" railway up --project <project id> --environment production --service ibridge --detach`. A deploy restarts the service and ends open sessions; people reconnect without signing in again.
- **Rate limits behind Railway's proxy:** `IBRIDGE_BEHIND_PROXY=true` is part of the variables in step 4. If sign-in limits ever lock everyone out together, check it is set with the dashboard's Variables tab, and see [Behind a proxy](self-host.md#behind-a-proxy).
- **Roll back:** in the Deployments tab, redeploy the previous successful deployment (it keeps the build of its own commit, so it does not follow `main`). Then land a revert pull request on `main`, or the next push deploys the bad commit again. To roll back to a specific sha from GitHub, revert on `main` back to it. Fallback: check out the previous sha and run `railway up` (with the token, `--project` and `--environment production`, as above). The database is forward-only: `/readyz` fails if a snapshot or a rollback meets a different schema, so restore a snapshot taken by the older build.
