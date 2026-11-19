# iBridge site

The product site at https://ibridge.fyi: static files in `public/`, no build step.

## Hosting: GitHub Pages

`.github/workflows/pages.yml` publishes `site/public` on every push to `main` that touches `site/**` (and on manual runs). It runs `node site/scripts/check.mjs` first and deploys only if that passes. `public/CNAME` holds the custom domain `ibridge.fyi`; keep it, or Pages drops the domain on the next deploy. DNS for `ibridge.fyi` stays on Vercel DNS and points at GitHub Pages; the site itself is not on Vercel.

Pages behaviour the site relies on:

- `/privacy` and `/terms` are served from `privacy.html` and `terms.html`. Link to the extension-less paths.
- A trailing slash is not redirected: `/privacy/` and `/terms/` answer 404 (Vercel used to redirect them). Internal links never use one.
- Unknown paths get `404.html` with status 404, at any depth, so `404.html` uses root-absolute asset paths (`/assets/...`).
- Pages cannot send custom headers. The Content-Security-Policy is a `<meta http-equiv="Content-Security-Policy">` tag in every HTML page, placed before any script, link or image, together with `<meta name="referrer" content="strict-origin-when-cross-origin">`. A meta CSP ignores `frame-ancestors` and `report-*`, so the site cannot forbid framing. Keep the policy identical on all four pages. The other headers the old Vercel config sent (HSTS, nosniff, Permissions-Policy, X-Frame-Options, Cache-Control) are no longer set by the site; Pages decides them.
- SVG files carry no CSP (their inline style needs none).

## Checks

```
cd site && npm ci && node scripts/check.mjs
```

The check covers page copy, links, metadata, the meta CSP on every page, `CNAME`, the Pages workflow, and a rendered pass (axe, layout, console and CSP violations) against a local server that mimics Pages (`/privacy` → `privacy.html`, `404.html` for unknown paths). It needs Chrome (`CHROME_PATH` to override).

Design files in `design/` are the source for `public/assets/`; run `node scripts/sync-design.mjs` after changing them.
