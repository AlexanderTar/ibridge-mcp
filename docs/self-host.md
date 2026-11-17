# Self-hosting ibridge

The hosted server lets Claude.ai and other remote MCP clients reach your iCloud Mail, Calendar and Contacts. It speaks OAuth 2.1 and MCP over HTTPS. You run it, so you decide who may sign in. Read [security-model.md](security-model.md) first: it says what the server can and cannot see.

## The image

The release workflow builds `ghcr.io/alexandertar/ibridge` when a `v*` tag is pushed. The image is `gcr.io/distroless/cc-debian12:debug-nonroot` (pinned by digest in the `Dockerfile`) plus one binary, so it has a busybox shell for `docker exec` and `railway ssh`. It runs as the `nonroot` user (uid 65532; the Railway setup below overrides this and runs as root) and keeps its database in `/data`. Build it yourself from a checkout:

```sh
docker build -t ibridge:test .
```

The image's default command prints `ibridge --help`. Start the server with:

```sh
docker run --rm --name ibridge -p 8080:8080 -v ibridge-data:/data \
  -e IBRIDGE_ALLOWED_APPLE_IDS=you@icloud.com \
  ibridge:test serve --hosted --http 0.0.0.0:8080 \
  --public-url https://ibridge.example.com --data-dir /data
```

`--public-url` is the https origin clients reach. It becomes the OAuth issuer, so it must be `https://` and match the address in the client's connector settings. A named volume starts out owned by uid 65532. A bind mount or a platform volume must be writable by that user.

## Settings

| Setting | What it does |
|---|---|
| `--hosted` | Runs the hosted server. It needs `--http`, `--public-url` and `--data-dir`, and cannot be combined with `--stdio` or `--read-only`. |
| `--http ADDR` | Listen address. Inside a container use `0.0.0.0:8080`. |
| `--public-url URL` | The https origin clients reach. |
| `--data-dir DIR` | Holds the database `ibridge.db` and the `backups/` folder. |
| `--multi-tenant` | Lets any iCloud account sign in. Leave it off when you self-host. |
| `--behind-proxy` | Reads the client address from the last `X-Forwarded-For` entry. Same as `IBRIDGE_BEHIND_PROXY=true`. See [Behind a proxy](#behind-a-proxy). |
| `IBRIDGE_ALLOWED_APPLE_IDS` | Comma-separated iCloud addresses that may sign in. |
| `IBRIDGE_SIGNUPS` | `open` (default) or `closed`. `closed` needs the allowlist. |
| `IBRIDGE_SIGNUP_CAP` | Accounts an open public service holds. Default 50. Whole number, at least 1. |
| `IBRIDGE_CONTACT` | Contact address shown on the privacy and terms pages. One line, at most 200 characters. |
| `IBRIDGE_BEHIND_PROXY` | `true` or `false` (default). Turn it on behind Fly's or Railway's proxy. See [Behind a proxy](#behind-a-proxy). |
| `IBRIDGE_LOG` | Log level: `error`, `warn`, `info` (default), `debug` or `trace`. Logs are JSON on stdout. |

The server refuses to start with neither an allowlist nor `--multi-tenant`.

## Allowlist or multi-tenant

- **Allowlist (self-host).** Set `IBRIDGE_ALLOWED_APPLE_IDS` and leave `--multi-tenant` off. Only those addresses can sign in, so the database holds as many accounts as you list. An allowlist restricts sign-in even when `--multi-tenant` is also set.
- **Multi-tenant (public service).** Pass `--multi-tenant` with no allowlist. Anyone with an iCloud address and an app-specific password can sign in, up to `IBRIDGE_SIGNUP_CAP` accounts. That makes you the operator of a service that holds strangers' sealed passwords, with a privacy policy and terms to match. [deploy-railway.md](deploy-railway.md) is the runbook for the public instance.

Each person creates an app-specific password at account.apple.com under Sign-In and Security, and types it on the server's sign-in page. The server stores it sealed under a key made from the token the client holds.

## Check that it is running

```sh
curl -fsS http://localhost:8080/healthz   # prints ok: the process is up
curl -fsS http://localhost:8080/readyz    # prints ready: the database answers and has this build's schema
```

Point a platform health check at `/readyz` and an uptime monitor at `/healthz`. Neither needs a token.

## Suspend or delete an account

Run the admin commands on the host, against the same data directory:

```sh
docker exec ibridge ibridge admin suspend you@icloud.com
docker exec ibridge ibridge admin delete you@icloud.com
```

`suspend` blocks the account's tokens, API keys and sign-in and deletes nothing. `delete` removes the account and every sealed copy of its password. `--data-dir` defaults to `/data`. The command runs in its own process and cannot reach the running server's pooled mail sessions. It does not need to: the server checks the database on every call, so the account's tokens and keys are refused from the next call and no pool is reached. Sessions the server already holds for that account sit idle and close within five minutes. Revoke the app-specific password at Apple as well: deleting the account here does not do that.

## Backups

The server writes a consistent snapshot of the database to `/data/backups/` once a day and keeps the newest 7. Snapshots hold only sealed passwords, so a snapshot cannot sign in to iCloud. Copy `/data/backups/` somewhere off the host if you want more than seven days. To restore, stop the server, replace `ibridge.db` with a snapshot, and start it. `/readyz` fails if the snapshot came from a build with a different schema.

## Fly.io

```sh
fly launch --no-deploy --image ghcr.io/alexandertar/ibridge:<version>
fly volumes create ibridge_data --size 1
fly secrets set IBRIDGE_ALLOWED_APPLE_IDS=you@icloud.com
```

Then edit `fly.toml`:

```toml
[mounts]
  source = "ibridge_data"
  destination = "/data"

[env]
  IBRIDGE_BEHIND_PROXY = "true"

[processes]
  app = "serve --hosted --http 0.0.0.0:8080 --public-url https://<app>.fly.dev --data-dir /data"

[http_service]
  internal_port = 8080
  force_https = true
  processes = ["app"]

  [[http_service.checks]]
    method = "GET"
    path = "/readyz"
    interval = "15s"
    timeout = "5s"
```

Fly runs the image's entrypoint (`ibridge`) and appends the `[processes]` command to it, which is why the `app` line above starts with `serve` and not `ibridge serve`. Replace `<app>` with your app's name. `IBRIDGE_BEHIND_PROXY` makes the server rate-limit each visitor separately; see [Behind a proxy](#behind-a-proxy). Run one machine only, then `fly deploy`. Fly mounts the volume as root, so if the server cannot write `/data`, chown the volume once with `fly ssh console -C "chown -R 65532:65532 /data"`. This section is not tested against a live Fly account.

## Railway

Create a service from the image `ghcr.io/alexandertar/ibridge:<version>`, attach a volume at `/data`, and set these variables:

```
IBRIDGE_ALLOWED_APPLE_IDS=you@icloud.com
IBRIDGE_BEHIND_PROXY=true
PORT=8080
RAILWAY_RUN_UID=0
```

Set the start command to `ibridge serve --hosted --http 0.0.0.0:8080 --public-url https://<your domain> --data-dir /data`, the health check path to `/readyz`, and generate a domain. `RAILWAY_RUN_UID=0` is there because Railway mounts volumes as root. If the container fails with the command repeated (for example `ibridge ibridge serve`), Railway is appending the start command to the image's entrypoint: remove the leading `ibridge` from it, so it starts with `serve`. Step 5 of the runbook below says the same. `docs/deploy-railway.md` has the full runbook the public instance follows, including the account checks.

## Behind a proxy

The server rate-limits sign-in, client lookups and client registration by client address. Behind Fly's or Railway's edge proxy every connection comes from the proxy, so without help all visitors share one budget, and one person's failed sign-ins can lock everyone out for a few minutes.

Set `IBRIDGE_BEHIND_PROXY=true` (or pass `--behind-proxy`) and the server takes the client address from the last `X-Forwarded-For` entry, which the proxy appends. It is off by default, and it must stay off when clients reach the server directly: with it on, a direct client could pick its own address by sending that header. Turn it on only when the proxy is the only way in. Any value other than `true`, `1`, `false` or `0` stops the server starting. Railway's runbook sets it ([deploy-railway.md](deploy-railway.md)).

## Known limits

- **One instance only.** The database is one SQLite file, and the rate limits and session cache live in memory.
- **Passwords in memory.** See [security-model.md](security-model.md).

## Check it with Claude.ai from your laptop

Before you put it on a host, you can try the whole flow through a tunnel. Claude.ai connects from the internet, so it needs a public https address:

```sh
docker run --rm --name ibridge -p 8080:8080 -v ibridge-data:/data \
  -e IBRIDGE_ALLOWED_APPLE_IDS=you@icloud.com \
  ibridge:test serve --hosted --http 0.0.0.0:8080 \
  --public-url https://<tunnel-host> --data-dir /data
```

The tunnel host is only known after cloudflared starts, so start it first, in another terminal:

```sh
cloudflared tunnel --url http://localhost:8080
```

It prints a `https://<random>.trycloudflare.com` address. Stop the container, restart it with that address as `--public-url`, and confirm `curl https://<random>.trycloudflare.com/readyz` prints `ready`. Then, in Claude.ai, add a custom connector with the URL `https://<random>.trycloudflare.com/mcp`, sign in on the page that opens with your iCloud address and an app-specific password, and ask Claude to call `account_status`. Quick tunnels get a new address each time, so repeat the restart whenever cloudflared restarts. Revoke the app-specific password when you finish.

### Protocol version Claude.ai negotiated

Not recorded yet. After the first successful run, write here the MCP protocol version Claude.ai negotiated, the date and the ibridge version. The server does not log request bodies, so read the version from the `protocolVersion` field of the `initialize` exchange as the client shows it, or point an MCP inspector at the tunnel URL.
