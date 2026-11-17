# Deploying the public instance on Railway

This is the runbook for the public instance at `https://ibridge.fyi`. Every step that changes something comes after the account checks in step 1. Do not skip them: this machine's Railway CLI is logged in to a different (work) account, and `vercel` may default to another scope.

Never print the Railway token or an app-specific password. Do not paste either into a command line, a log, an issue or a commit. Steps that read a secret say how to do it without echoing it.

The Railway commands below were checked against `railway` 5.62.1's `--help`. The deploy steps have not been run against a live account; if a command behaves differently, stop and fix the runbook before going on.

## 1. Check the accounts

**Railway.** Use the personal token file for every Railway command in this runbook. Export it for this shell so the CLI's own login is never used, and unset it when you finish:

```sh
export RAILWAY_API_TOKEN="$(cat ~/.config/railway-personal/token)"
railway whoami --json | jq -r .email
```

The address must be the personal account's. If it prints anything else, or `Unauthorized`, stop. The variable is `RAILWAY_API_TOKEN` (an account or workspace token), not `RAILWAY_TOKEN` (a project token, which `whoami` rejects). Unset it with `unset RAILWAY_API_TOKEN` when you finish. Never run `railway login` for this work.

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
railway init --name ibridge
railway add --service ibridge
railway volume --service ibridge add --mount-path /data
```

Run these once. `railway status` must show the project you just made and the personal workspace before you continue.

## 4. Set the variables

Start closed, so only you can sign in while you run the datacenter check in step 7:

```sh
railway variable set --service ibridge --skip-deploys \
  PORT=8080 RAILWAY_RUN_UID=0 \
  IBRIDGE_SIGNUPS=closed IBRIDGE_SIGNUP_CAP=50 \
  IBRIDGE_ALLOWED_APPLE_IDS=<your iCloud address>
printf '%s' '<contact address>' | railway variable set IBRIDGE_CONTACT --stdin --service ibridge --skip-deploys
```

`RAILWAY_RUN_UID=0` is needed because Railway mounts volumes as root, while the image runs as uid 65532. `IBRIDGE_CONTACT` is the address `/privacy` and `/terms` show; the legal review supplies it. To check what is set without showing values, use the dashboard's Variables tab. `railway variable list` prints values, and `--kv` and `--json` print them raw, so none of those forms is safe on a shared screen.

## 5. Deploy and check

Set the start command and health check in the service's settings (Railway dashboard, Settings, Deploy), because the CLI cannot set them:

- Start command: `ibridge serve --hosted --multi-tenant --http 0.0.0.0:8080 --public-url https://ibridge.fyi --data-dir /data`
- Healthcheck path: `/readyz`

Then upload the commit:

```sh
railway up --service ibridge --detach
railway logs --service ibridge
```

The logs must show a line containing `serving MCP over HTTP, hosted`. If the server refuses to start, the message names the setting (for example, closed sign-ups need `IBRIDGE_ALLOWED_APPLE_IDS`). If the container fails with the entrypoint repeated, for example `ibridge ibridge serve`, Railway is appending the start command to the image's entrypoint: remove the leading `ibridge` from the start command. Do not go on until the deployment is healthy. After the first deploy, record here whether Railway's start command replaced or was added to the image's entrypoint, and whether the apex record needed an ALIAS.

An allowlist limits sign-in even with `--multi-tenant`, so the closed instance accepts only your address.

## 6. Point ibridge.fyi at the service

```sh
railway domain ibridge.fyi --service ibridge --port 8080
```

This prints the DNS records Railway wants (a CNAME target and a `_railway-verify` TXT record). Re-run step 1's `vercel` checks, then add exactly those records, with the scope from step 1:

```sh
vercel dns ls ibridge.fyi --scope <scope>
vercel dns add ibridge.fyi '@' ALIAS <railway target> --scope <scope>
vercel dns add ibridge.fyi '_railway-verify' TXT '<value Railway printed>' --scope <scope>
```

Vercel DNS takes an `ALIAS` record at the apex, where a plain CNAME is not allowed; use the type Railway prints for a subdomain. Add nothing else and do not touch existing records. Then wait for `railway domain status ibridge.fyi --service ibridge` to show the certificate issued, and:

```sh
curl -fsS https://ibridge.fyi/readyz     # ready
curl -fsS https://ibridge.fyi/healthz    # ok
```

## 7. Datacenter check

Apple may refuse sign-ins that come from a datacenter address. The server makes the call to Apple when you sign in, so a successful sign-in through the deployed server shows Apple accepts Railway's egress. Run the check from a checkout of the approved commit, with the live test account file in `~/.config/ibridge/test-account.env` (mode `0600`, never printed):

```sh
cargo xtask live-hosted-check --url https://ibridge.fyi
```

It signs in as a client does, calls `account_status`, and prints one line per step with no password, token or code. The account address must be the one in `IBRIDGE_ALLOWED_APPLE_IDS`. Record the result with the sha and the date. If Apple refuses the sign-in, stop: the public launch cannot go on from this host. Say so, do not retry in a loop, and do not open sign-ups.

This check needs the live test account, and the live recording has not run yet, so it has not run against this host.

## 8. Uptime monitor (you create it)

You create the monitor in your own monitoring service; the runbook does not hold its credentials. Watch `https://ibridge.fyi/healthz` every minute, expect `200` with the body `ok`, and send alerts to yourself. Use `/healthz`, not `/readyz`: Railway already restarts the service on `/readyz`.

## 9. Verify backups

The server writes its first snapshot as soon as it starts, then one a day, and keeps seven.

```sh
railway ssh --service ibridge -- ls -l /data/backups
```

There must be an `ibridge-<UTC time>.db` file. Download it and check it opens, without signing in to anything:

```sh
railway volume list
railway volume files --volume <volume name or id> download /backups/<name> ./check.db
sqlite3 ./check.db 'pragma integrity_check; pragma user_version;'
rm ./check.db
```

`integrity_check` must print `ok`. The file holds only sealed passwords. Check again after 24 hours that a second file appeared. Delete the local copy once you have looked.

## 10. Open sign-ups at 50

Only after steps 5 to 9 pass and you have connected Claude.ai to `https://ibridge.fyi/mcp` and called `account_status` yourself. Remove the allowlist and open sign-ups at the cap:

```sh
railway variable delete IBRIDGE_ALLOWED_APPLE_IDS --service ibridge
railway variable set IBRIDGE_SIGNUPS=open IBRIDGE_SIGNUP_CAP=50 --service ibridge
```

Your own account was created while the instance was closed, so it counts toward the cap. Check `/` and `/account`, then watch `railway logs --service ibridge` for the first sign-ups. To close again, set `IBRIDGE_SIGNUPS=closed` and `IBRIDGE_ALLOWED_APPLE_IDS` back to your address. To raise the cap, change `IBRIDGE_SIGNUP_CAP`.

## Operating

- **Suspend or delete an account:** `railway ssh --service ibridge -- ibridge admin suspend <address>` or `... delete <address>`. Then tell the person to revoke the app-specific password at Apple.
- **Deploy a new version:** pick the commit as in step 2, then `railway up --service ibridge --detach`. A deploy restarts the service and ends open sessions; people reconnect without signing in again.
- **Rate limits behind Railway's proxy:** see Known limits in [self-host.md](self-host.md). All visitors currently share one sign-in budget.
- **Roll back:** redeploy the previous sha with `railway up`, or use Railway's deployment history. The database is forward-only: `/readyz` fails if a snapshot or a rollback meets a different schema, so restore a snapshot taken by the older build.
