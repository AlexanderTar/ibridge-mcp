// Checks for the iBridge marketing site. Run: node site/scripts/check.mjs
// Static checks read site/public; each section reports its own failures.
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const SITE = join(dirname(fileURLToPath(import.meta.url)), "..");
const PUBLIC = join(SITE, "public");
const failures = [];
const fail = (msg) => failures.push(msg);
const assert = (cond, msg) => { if (!cond) fail(msg); };

const read = (p) => (existsSync(p) ? readFileSync(p, "utf8") : "");
const walk = (dir) => !existsSync(dir) ? [] : readdirSync(dir).flatMap((n) => {
  const p = join(dir, n);
  return statSync(p).isDirectory() ? walk(p) : [p];
});

// Visible text: drop script/style/svg, tags become nothing (inline) or a space (block).
const BLOCK = /<\/?(p|div|li|ul|ol|h[1-6]|section|header|footer|nav|main|details|summary|figure|figcaption|br|button|a|time|label)\b[^>]*>/gi;
function visibleText(html) {
  return html
    .replace(/<(script|style|svg)\b[\s\S]*?<\/\1>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<wbr\s*\/?>/gi, "")
    .replace(BLOCK, " ")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&rarr;/g, "→")
    .replace(/\s+/g, " ").trim();
}
// Copy is compared ignoring spacing and quote style; curly quotes are checked separately.
const squash = (s) => s.replace(/[‘’]/g, "'").replace(/[“”]/g, '"').replace(/\s+/g, "");
// Visible prose (not code, which keeps its identifiers as typed) uses curly quotes and apostrophes.
function assertCurly(name, html) {
  const prose = visibleText(html.replace(/<code\b[^>]*>[\s\S]*?<\/code>/gi, " "));
  for (const m of prose.matchAll(/['"]/g)) fail(`${name}: straight quote in visible text near "${prose.slice(Math.max(0, m.index - 15), m.index + 15)}"`);
}

// ---------- Unit 1: page copy, naming, links ----------
const CONNECTOR = "https://mcp.ibridge.fyi/mcp";
const GITHUB = "https://github.com/AlexanderTar/ibridge-mcp";
const ACCOUNT = "https://mcp.ibridge.fyi/account";
// Links to other sites. Privacy and Terms are pages of this site (/privacy, /terms), not links to mcp.ibridge.fyi.
const ALLOWED_EXTERNAL = new Set([
  CONNECTOR, ACCOUNT, GITHUB,
  `${GITHUB}/blob/main/docs/security-model.md`,
  "https://support.apple.com/102654",
]);
const LOCAL_PAGES = ["/privacy", "/terms"];
// A local href names a shipped file, with Vercel's cleanUrls (/privacy serves privacy.html).
const resolvesLocally = (href) => {
  const path = href.split("#")[0].replace(/^\//, "");
  return path === "" || existsSync(join(PUBLIC, path)) || existsSync(join(PUBLIC, `${path}.html`));
};
const REQUIRED_COPY = [
  "How it works", "Pricing", "FAQ", "GitHub", "Connect",
  "Your iCloud, in your AI assistant.",
  "iBridge lets Claude and other AI assistants read and manage your iCloud Mail, Calendar and Contacts.",
  "Run it for free", CONNECTOR,
  "From US$1.99/month. Open source and free to run yourself.",
  "Try asking",
  "What's on my calendar tomorrow?", "Find the invoice Anna sent last week", "Move my 3pm to Friday", "What's Sam's phone number?",
  "What it connects", "Your mail, calendar and contacts. One connector.",
  "Mail", "Search, read, sort and send email.",
  "Calendar", "See what's coming up and plan events.",
  "Contacts", "Look people up and keep details current.",
  "Connect in four steps",
  "Add the connector.", "In Claude, open Settings → Connectors, add a custom connector and paste the address.",
  "Sign in with Apple.", "Choose a plan.", "US$1.99/month or US$19.99/year.",
  "Connect iCloud.", "Enter your iCloud address and an app-specific password.",
  "Using Claude Code?", "claude mcp add --transport http ibridge https://mcp.ibridge.fyi/mcp",
  "Ready to go, or run it yourself.",
  "Nothing to install", "Works in Claude and other assistants", "Cancel any time",
  "Open source", "Free", "Apache-2.0", "Claude Desktop", "Claude Code", "Docker", "View on GitHub",
  "Is iBridge made by Apple?", "No. It's an independent, unofficial service.",
  "Which assistants can use it?", "Claude, GrokBot and any assistant that supports MCP connectors.",
  "Which password do I give it?", "An app-specific password from your Apple Account, never your main one.",
  "How much does it cost?", "US$1.99/month or US$19.99/year. Running it yourself is free.",
  "Can I run it myself?", "Yes. It's open source. Run it in Claude Desktop or Claude Code, or self-host it with Docker.",
  "Privacy", "Terms", "Account",
  "iBridge is an unofficial service. It is not affiliated with or endorsed by Apple. iCloud is a trademark of Apple Inc.",
];
const BANNED = [
  /reminders?/i, /chatgpt/i, /\btax\b/i, /security/i, /read-only/i, /full access/i, /\bhosted\b/i,
  /main apple id password/i, /change or delete/i,
];

function checkPage() {
  const indexPath = join(PUBLIC, "index.html");
  const html = read(indexPath);
  if (!html) return fail("site/public/index.html is missing");
  const text = visibleText(html);
  const flat = squash(text);

  for (const copy of REQUIRED_COPY) assert(flat.includes(squash(copy)), `copy missing: "${copy}"`);
  for (const re of BANNED) assert(!re.test(text), `banned text present: ${re}`);

  // Brand: capital B in visible text, titles and alt text; lowercase only as identifiers.
  const code = [...html.matchAll(/<code\b[^>]*>[\s\S]*?<\/code>/gi)].map((m) => m[0]);
  const prose = visibleText(html.replace(/<code\b[^>]*>[\s\S]*?<\/code>/gi, " "));
  assert(!/\bibridge\b/.test(prose), "lowercase 'ibridge' in visible text outside code");
  const attrText = [...html.matchAll(/\b(?:alt|title|aria-label|content)="([^"]*)"/gi)].map((m) => m[1]).join(" ");
  assert(!/\bibridge\b/.test(attrText.replace(/https?:\/\/\S+/g, "")), "lowercase 'ibridge' in an alt, title, aria-label or meta content");
  assert(/<title>[^<]*iBridge[^<]*<\/title>/.test(html), "page title must name iBridge");
  assert(code.length >= 3, "expected connector box, step box and Claude Code box");

  // Copy buttons: icon buttons with an accessible "Copy" label, one per copy box.
  const boxes = [...html.matchAll(/<(?:div|span)\b[^>]*class="copy-box"[^>]*>[\s\S]*?<\/button>/gi)].map((m) => m[0]);
  assert(boxes.length === 3, `expected 3 copy boxes, found ${boxes.length}`);
  for (const b of boxes) assert(/<button\b[^>]*aria-label="Copy"[^>]*>\s*<svg/.test(b), "copy box button needs aria-label=\"Copy\" and an icon");
  for (const b of boxes) assert(/<(?:div|span)\b[^>]*role="group"/.test(b) && /<(?:div|span)\b[^>]*aria-label="[^"]+"/.test(b), "copy box needs role=\"group\" and an aria-label naming what it copies");
  assertCurly("index", html);
  for (const b of boxes) assert(!/copy-done|>\s*Copied\s*</.test(b), "copy button must show only the tick icon, with no visible 'Copied' word");
  assert(html.includes("assets/copy.js"), "page must load assets/copy.js");

  // Prices exactly.
  assert(!/US\$\s*1\.99(?!\/month|<small>\/month)/.test(html.replace(/<small>\/month<\/small>/g, "/month")), "price US$1.99 not followed by /month");
  assert(!/\$\s?\d/.test(text.replace(/US\$\d/g, "")), "price not written as US$");

  // Links: hrefs are anchors that exist, files that exist, or allow-listed addresses.
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
  const hrefs = [...html.matchAll(/<a\b[^>]*\bhref="([^"]*)"/g)].map((m) => m[1]);
  for (const href of hrefs) {
    if (href.startsWith("#")) assert(ids.has(href.slice(1)), `anchor ${href} has no target`);
    else if (/^https?:/.test(href)) assert(ALLOWED_EXTERNAL.has(href), `unapproved external link ${href}`);
    else if (!href.startsWith("mailto:")) assert(resolvesLocally(href), `local link ${href} does not resolve`);
  }
  for (const want of [ACCOUNT, GITHUB, ...LOCAL_PAGES]) assert(hrefs.includes(want), `link missing: ${want}`);
  // The footer and the FAQ both link to the site's own privacy and terms pages.
  const footer = (html.match(/<footer\b[\s\S]*?<\/footer>/) || [""])[0];
  const faq = (html.match(/<section\b[^>]*id="faq"[\s\S]*?<\/section>/) || [""])[0];
  for (const [name, area] of [["footer", footer], ["FAQ", faq]]) for (const p of LOCAL_PAGES) assert(area.includes(`href="${p}"`), `${name} must link to ${p}`);
  // Round 2: links to another site open in a new tab with rel="noopener noreferrer"; in-page and same-site links do not.
  for (const [tag, href] of [...html.matchAll(/<a\b[^>]*\bhref="([^"]*)"[^>]*>/g)].map((m) => [m[0], m[1]])) {
    const external = /^https?:/.test(href);
    assert(external === /\btarget="_blank"/.test(tag), `${href}: target="_blank" belongs on links to other sites only`);
    assert(external === /\brel="noopener noreferrer"/.test(tag), `${href}: rel="noopener noreferrer" belongs on links to other sites only`);
  }
  const connectHrefs = [...html.matchAll(/<a\b[^>]*class="[^"]*btn[^"]*"[^>]*href="([^"]*)"[^>]*>\s*Connect\s*</g)].map((m) => m[1]);
  assert(connectHrefs.length >= 1 && connectHrefs.every((h) => h === "#how"), "Connect buttons must go to #how");

  // No external requests from any shipped file (html, css, js, svg), apart from the allow-list and the SVG namespace.
  for (const file of walk(PUBLIC).filter((f) => /\.(html|css|js|mjs|svg|json)$/.test(f))) {
    const src = read(file).replace(/https?:\/\/www\.w3\.org\/\d+\/svg/g, "").replace(/https?:\/\/www\.w3\.org\/1999\/xlink/g, "");
    for (const [url] of src.matchAll(/https?:\/\/[^\s"'<>)\\]+/g)) {
      const clean = url.replace(/[.,]+$/, "");
      // Absolute URLs of this site (canonical, og:image) are metadata, not requests; they must name a shipped file.
      if (clean.startsWith("https://ibridge.fyi/")) {
        const path = clean.slice("https://ibridge.fyi/".length);
        assert(resolvesLocally(path || "index.html"), `${relative(SITE, file)}: ${clean} names no shipped file`);
      } else assert(ALLOWED_EXTERNAL.has(clean), `${relative(SITE, file)}: external URL ${clean}`);
    }
    assert(!/@import|url\(\s*["']?\/\//.test(src), `${relative(SITE, file)}: @import or protocol-relative url`);
  }
  for (const m of html.matchAll(/<(?:script|link(?![^>]*rel="canonical")|img|iframe)\b[^>]*\b(?:src|href)="([^"]*)"/g)) {
    assert(!/^(?:https?:)?\/\//.test(m[1]) || ALLOWED_EXTERNAL.has(m[1]), `external resource ${m[1]}`);
  }
  for (const m of html.matchAll(/<(?:script|img|link)\b[^>]*\b(?:src|href)="(?!https?:|#|mailto:)([^"]*)"/g)) {
    assert(existsSync(join(PUBLIC, m[1].replace(/^\//, ""))), `missing file ${m[1]}`);
  }

  // Design tokens and components are the shipped ones, byte for byte.
  for (const f of ["tokens.css", "components.css", "copy.js", "tick.svg"]) {
    assert(read(join(PUBLIC, "assets", f)) === read(join(SITE, "design", f)) && read(join(SITE, "design", f)) !== "",
      `public/assets/${f} drifted from site/design/${f} (run node site/scripts/sync-design.mjs)`);
  }
}

checkPage();

// ---------- Round 2: /privacy and /terms are pages of this site ----------
// Text is the hosted iBridge instance's policy with billing and Sign in with Apple on (crates/ibridge-hosted/templates).
const CONTACT = "taraymovich@gmail.com";
const LEGAL = {
  privacy: ["Privacy policy", "iBridge is unofficial and not affiliated with Apple", "What we store", "Revoke the password at Apple", "How long we keep things", "Who else is involved", "Your choices and contact",
    "If you sign in with Apple", "Your plan: your Stripe customer and subscription ids", "Google, through Firebase Authentication",
    "Stripe is the seller of record", "end your subscription at Stripe", "We do not store the content of your mail, calendar or contacts", CONTACT],
  terms: ["Terms of use", "iBridge is an unofficial service", "It is not affiliated with Apple or endorsed by Apple", "Your account and Apple's terms",
    "What you are responsible for", "Subscription and payment", "US$1.99/month or US$19.99/year", "renews automatically", "Cancelling",
    "end of the period you have paid for", "Stripe, which is the seller of record", "A failed payment", "Fair use", "No warranty",
    "Suspension and deletion", "Changes and contact", CONTACT],
};
const LEGAL_BANNED = [/reminders?/i, /chatgpt/i, /sealed/i, /read-only/i, /read only/i, /unless you chose/i, /\{\{|\{%/, /operator of this service has not published/i,
  // User 2026-11-18: no risk or decryption sections, no domain names in the legal text.
  /risk remains/i, /cannot decrypt your password from storage/i, /whoever controls/i, /moments when we can still see/i,
  /mcp\.ibridge\.fyi/i, /appleid\.apple\.com/i, /googleapis\.com/i, /api\.stripe\.com/i];

function checkLegal() {
  for (const [name, required] of Object.entries(LEGAL)) {
    const file = join(PUBLIC, `${name}.html`);
    const html = read(file);
    if (!html) { fail(`site/public/${name}.html is missing`); continue; }
    const text = visibleText(html);
    const flat = squash(text);
    for (const copy of required) assert(flat.includes(squash(copy)), `${name}: copy missing: "${copy}"`);
    assertCurly(name, html);
    for (const re of LEGAL_BANNED) assert(!re.test(text), `${name}: banned text present: ${re}`);
    assert(!/\bibridge\b/.test(visibleText(html.replace(/<code\b[^>]*>[\s\S]*?<\/code>/gi, " "))), `${name}: lowercase 'ibridge' in visible text outside code`);
    assert(new RegExp(`<title>[^<]*iBridge[^<]*</title>`).test(html), `${name}: title must name iBridge`);
    assert(/<h1\b/.test(html) && html.includes("assets/components.css") && html.includes("assets/tokens.css"), `${name}: needs an h1 and the design system styles`);
    assert(!/<style\b|\sstyle="/i.test(html), `${name}: no inline styles (the CSP allows only 'self')`);
    assert(new RegExp(`href="mailto:${CONTACT}"`).test(html), `${name}: contact must be a mailto link`);
    assert(/<footer\b[\s\S]*href="\/privacy"[\s\S]*href="\/terms"/.test(html), `${name}: footer must link to /privacy and /terms`);
    const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
    for (const [tag, href] of [...html.matchAll(/<a\b[^>]*\bhref="([^"]*)"[^>]*>/g)].map((m) => [m[0], m[1]])) {
      const external = /^https?:/.test(href);
      if (external) assert(ALLOWED_EXTERNAL.has(href), `${name}: unapproved external link ${href}`);
      else if (href.startsWith("#")) assert(ids.has(href.slice(1)), `${name}: anchor ${href} has no target`);
      else if (!href.startsWith("mailto:")) assert(resolvesLocally(href), `${name}: local link ${href} does not resolve`);
      assert(external === /\btarget="_blank"/.test(tag) && external === /\brel="noopener noreferrer"/.test(tag), `${name}: ${href} must open in a new tab with rel="noopener noreferrer" only when it leaves the site`);
    }
  }
}

checkLegal();

// ---------- Unit 2: icons and metadata ----------
const SITE_URL = "https://ibridge.fyi";
function pngSize(file) {
  const b = existsSync(file) ? readFileSync(file) : Buffer.alloc(0);
  const ok = b.length > 24 && b.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  return ok ? [b.readUInt32BE(16), b.readUInt32BE(20)] : null;
}
function checkIcons() {
  const html = read(join(PUBLIC, "index.html"));
  const fav = read(join(PUBLIC, "favicon.svg"));
  assert(fav.includes("<svg") && /prefers-color-scheme:\s*dark/.test(fav), "favicon.svg must exist and switch colours with prefers-color-scheme");
  for (const [name, w, h] of [["apple-touch-icon.png", 180, 180], ["icon-512.png", 512, 512], ["og.png", 1200, 630]]) {
    const size = pngSize(join(PUBLIC, name));
    assert(size && size[0] === w && size[1] === h, `${name} must be a ${w}x${h} PNG (found ${size ? size.join("x") : "nothing"})`);
  }
  const tag = (re) => (html.match(re) || [])[1] || "";
  const meta = (attr, name) => tag(new RegExp(`<meta\\b[^>]*\\b${attr}="${name}"[^>]*\\bcontent="([^"]*)"`)) || tag(new RegExp(`<meta\\b[^>]*\\bcontent="([^"]*)"[^>]*\\b${attr}="${name}"`));
  assert(/<link\b[^>]*rel="icon"[^>]*href="favicon\.svg"[^>]*type="image\/svg\+xml"/.test(html), "head must link favicon.svg");
  assert(/<link\b[^>]*rel="apple-touch-icon"[^>]*href="apple-touch-icon\.png"/.test(html), "head must link apple-touch-icon.png");
  assert(/<link\b[^>]*rel="manifest"[^>]*href="site\.webmanifest"/.test(html), "head must link site.webmanifest");
  const manifest = read(join(PUBLIC, "site.webmanifest"));
  assert(manifest.includes('"name": "iBridge"') && manifest.includes("icon-512.png"), "site.webmanifest must name iBridge and list icon-512.png");
  assert(tag(/<link\b[^>]*rel="canonical"[^>]*href="([^"]*)"/) === `${SITE_URL}/`, "canonical link must be https://ibridge.fyi/");
  assert(tag(/<title>([^<]*)<\/title>/) === "iBridge · Connect iCloud to your AI assistant", "title must be 'iBridge · Connect iCloud to your AI assistant'");
  const desc = meta("name", "description");
  assert(desc === "iBridge lets Claude and other AI assistants read and manage your iCloud Mail, Calendar and Contacts.", "meta description must match the approved hero line");
  assert(meta("property", "og:title") === "iBridge · Connect iCloud to your AI assistant", "og:title");
  assert(desc !== "" && meta("property", "og:description") === desc, "og:description must equal the description");
  assert(meta("property", "og:type") === "website", "og:type must be website");
  assert(meta("property", "og:url") === `${SITE_URL}/`, "og:url");
  assert(meta("property", "og:site_name") === "iBridge", "og:site_name must be iBridge");
  assert(meta("property", "og:image") === `${SITE_URL}/og.png`, "og:image must be https://ibridge.fyi/og.png");
  assert(meta("property", "og:image:width") === "1200" && meta("property", "og:image:height") === "630", "og:image width/height");
  assert(/iBridge/.test(meta("property", "og:image:alt")), "og:image:alt must name iBridge");
  assert(meta("name", "twitter:card") === "summary_large_image", "twitter:card must be summary_large_image");
  assert(meta("name", "twitter:title") !== "" && meta("name", "twitter:title") === meta("property", "og:title"), "twitter:title");
  assert(desc !== "" && meta("name", "twitter:description") === desc, "twitter:description");
  assert(meta("name", "twitter:image") === `${SITE_URL}/og.png`, "twitter:image");
  assert(existsSync(join(SITE, "scripts", "export-icons.mjs")), "scripts/export-icons.mjs (the committed icon export) is missing");
}

checkIcons();

// ---------- Unit 3: Vercel config, 404, rendered checks ----------
function readVercelConfig() {
  try { return JSON.parse(read(join(SITE, "vercel.json"))); } catch { return null; }
}
// The headers Vercel sends for a path: every rule whose source matches (a source is a path-to-regexp pattern; ours are plain regex groups).
const headersFor = (config, path) => Object.fromEntries((config?.headers ?? [])
  .filter((r) => new RegExp(`^${r.source}$`).test(path))
  .flatMap((r) => r.headers.map((h) => [h.key.toLowerCase(), h.value])));

function checkVercelConfig(config) {
  if (!config) return fail("site/vercel.json is missing or not valid JSON");
  assert(config.cleanUrls === true, "vercel.json: cleanUrls must be true");
  assert(config.outputDirectory === "public", "vercel.json: outputDirectory must be public");
  const all = headersFor(config, "/");
  assert(config.installCommand === "" && config.buildCommand === "", "vercel.json: installCommand and buildCommand must be empty strings (a static site; null would auto-detect and run npm install)");
  for (const path of ["/favicon.svg", "/img/mark-light.svg", "/img/tile-dark.svg"]) {
    assert(!("content-security-policy" in headersFor(config, path)), `vercel.json: no CSP on ${path} (its inline style needs one Firefox can render)`);
    assert(headersFor(config, path)["x-content-type-options"] === "nosniff", `vercel.json: ${path} still needs the other security headers`);
  }
  for (const path of ["/privacy", "/terms", "/nope", "/assets/page.css"]) assert("content-security-policy" in headersFor(config, path), `vercel.json: CSP must be sent on ${path}`);
  assert(!/interest-cohort/.test(all["permissions-policy"] ?? ""), "Permissions-Policy: drop interest-cohort (retired FLoC directive)");
  const csp = all["content-security-policy"] ?? "";
  assert(csp.includes("default-src 'self'"), "CSP must start from default-src 'self'");
  assert(!/unsafe-inline|unsafe-eval|https?:|\*/.test(csp), "CSP must allow only 'self' (no unsafe-*, hosts or wildcards)");
  for (const d of ["script-src 'self'", "style-src 'self'", "img-src 'self'", "object-src 'none'", "base-uri 'self'", "frame-ancestors 'none'", "form-action 'self'"]) {
    assert(csp.includes(d), `CSP missing ${d}`);
  }
  const maxAge = Number(/max-age=(\d+)/.exec(all["strict-transport-security"] ?? "")?.[1] ?? 0);
  assert(maxAge >= 31536000, "HSTS needs a max-age of at least one year");
  assert(all["x-content-type-options"] === "nosniff", "X-Content-Type-Options must be nosniff");
  assert(/^(strict-origin|strict-origin-when-cross-origin|no-referrer|same-origin)$/.test(all["referrer-policy"] ?? ""), "Referrer-Policy must be a strict value");
  assert(Boolean(all["permissions-policy"]), "Permissions-Policy must be set");
  const cached = config.headers?.find((r) => r.headers.some((h) => h.key.toLowerCase() === "cache-control"));
  assert(Boolean(cached), "vercel.json needs a Cache-Control rule for assets and images");
}

const notFoundPage = () => read(join(PUBLIC, "404.html")) || "Not found";
const TYPES = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml", ".png": "image/png", ".webmanifest": "application/manifest+json" };
// Serves site/public the way Vercel will: the vercel.json security headers on every response, 404.html for unknown paths.
function serve(config) {
  const server = createServer((req, res) => {
    const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
    let file = join(PUBLIC, path === "/" ? "index.html" : path);
    if (!extname(file) && existsSync(`${file}.html`)) file += ".html"; // cleanUrls
    if (!file.startsWith(PUBLIC) || !existsSync(file) || statSync(file).isDirectory()) file = null;
    for (const [k, v] of Object.entries(headersFor(config, path))) res.setHeader(k, v);
    res.statusCode = file ? 200 : 404;
    res.setHeader("content-type", TYPES[extname(file ?? "x.html")] ?? "application/octet-stream");
    res.end(file ? readFileSync(file) : notFoundPage());
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => ok(server)));
}

async function checkRendered(config) {
  let puppeteer;
  let axeSource;
  try {
    puppeteer = (await import("puppeteer-core")).default;
    axeSource = readFileSync(join(SITE, "node_modules", "axe-core", "axe.min.js"), "utf8");
  } catch { return fail("puppeteer-core and axe-core are not installed (run: npm ci --prefix site)"); }
  const chrome = [process.env.CHROME_PATH, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/usr/bin/google-chrome", "/usr/bin/chromium"].find((p) => p && existsSync(p));
  if (!chrome) return fail("no Chrome found (set CHROME_PATH)");
  const server = await serve(config);
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await puppeteer.launch({ executablePath: chrome, headless: true, args: ["--no-sandbox"] });
  const served = async (path) => (await fetch(origin + path)).headers;
  assert(!(await served("/favicon.svg")).has("content-security-policy"), "favicon.svg must be served without a CSP (its inline style is blocked by style-src 'self', and Firefox then renders it black)");
  assert((await served("/")).has("content-security-policy"), "the home page must be served with a CSP");
  await checkOgTile(browser, origin);
  const viewports = [
    { width: 1440, height: 900, deviceScaleFactor: 1 },
    { width: 390, height: 844, deviceScaleFactor: 2, isMobile: true, hasTouch: true }, // device emulation: headless Chrome's window can't go this narrow
  ];
  try {
    for (const [pagePath, label] of [["/", "home"], ["/privacy", "privacy"], ["/terms", "terms"], ["/does-not-exist", "404"]]) {
      for (const scheme of ["light", "dark"]) {
        for (const viewport of viewports) {
          const where = `${label} ${scheme} ${viewport.width}px`;
          const page = await browser.newPage();
          const problems = [];
          page.on("request", (r) => { if (!r.url().startsWith(origin) && !r.url().startsWith("data:")) problems.push(`external request ${r.url()}`); });
          page.on("response", (r) => { if (r.status() >= 400 && r.url() !== origin + pagePath) problems.push(`${r.status()} for ${r.url()}`); });
          page.on("console", (m) => { if (m.type() === "error" && m.location().url !== origin + pagePath) problems.push(`console error: ${m.text()}`); });
          page.on("pageerror", (e) => problems.push(`page error: ${e.message}`));
          await page.setViewport(viewport);
          await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: scheme }]);
          const response = await page.goto(origin + pagePath, { waitUntil: "networkidle0" });
          assert(response.status() === (label === "404" ? 404 : 200), `${where}: status ${response.status()}`);
          const widths = await page.evaluate(() => ({ doc: document.documentElement.scrollWidth, inner: window.innerWidth }));
          assert(widths.doc <= widths.inner, `${where}: horizontal scroll (scrollWidth ${widths.doc} > ${widths.inner})`);
          await page.evaluate(axeSource);
          const result = await page.evaluate(() => axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] } }));
          for (const v of result.violations) fail(`${where}: axe ${v.id} (${v.nodes.length}): ${v.nodes[0].html.slice(0, 100)}`);
          for (const p of problems) fail(`${where}: ${p}`);
          if (label === "home" && viewport.width === 1440 && scheme === "light") await checkCopyButtons(page, browser, origin);
          await page.close();
        }
      }
    }
  } finally { await browser.close(); server.close(); }
}

// The tile border on the Open Graph card is a hairline like the other icon sizes, not scaled up with the tile.
async function checkOgTile(browser, origin) {
  const page = await browser.newPage();
  await page.goto(`${origin}/404`);
  const thickness = await page.evaluate(async (url) => {
    const img = new Image();
    img.src = url;
    await img.decode();
    const c = Object.assign(document.createElement("canvas"), { width: img.width, height: img.height });
    const g = c.getContext("2d");
    g.drawImage(img, 0, 0);
    // Along the tile's middle (y=280), count the pixels of the border colour (#D5E3E6) left of the tile's fill.
    let n = 0;
    for (let x = 190; x < 260; x++) {
      const [r, gr, b] = g.getImageData(x, 280, 1, 1).data;
      if (Math.abs(r - 0xd5) < 14 && Math.abs(gr - 0xe3) < 14 && Math.abs(b - 0xe6) < 14) n++;
    }
    return n;
  }, `${origin}/og.png`);
  assert(thickness >= 1 && thickness <= 3, `og.png: the tile border is ${thickness}px thick; it should be a 1 to 3px hairline like the other icons, not scaled with the tile`);
  await page.close();
}

async function checkCopyButtons(page, browser, origin) {
  await browser.defaultBrowserContext().overridePermissions(origin, ["clipboard-read", "clipboard-write", "clipboard-sanitized-write"]);
  const count = await page.$$eval(".copy-box button", (bs) => bs.length);
  assert(count === 3, `expected 3 copy buttons, found ${count}`);
  const want = await page.$$eval(".copy-box code", (els) => els.map((e) => e.textContent.trim()));
  for (let i = 0; i < count; i++) {
    const read = (n) => page.evaluate((k) => {
      const b = document.querySelectorAll(".copy-box button")[k];
      const size = (el) => { const r = el.getBoundingClientRect(); return [r.width, r.height]; };
      const live = b.parentElement.querySelector("[role=status]");
      return {
        copied: "copied" in b.dataset,
        text: b.innerText.trim(),
        icons: [...b.querySelectorAll("svg")].filter((s) => getComputedStyle(s).display !== "none").map((s) => s.getAttribute("class")),
        sizes: [size(b), size(b.parentElement), size(b.parentElement.querySelector("code"))],
        live: live.textContent,
        liveHidden: live.classList.contains("visually-hidden"),
      };
    }, n);
    const before = await read(i);
    await (await page.$$(".copy-box button"))[i].click();
    await page.waitForFunction((n) => "copied" in document.querySelectorAll(".copy-box button")[n].dataset, { timeout: 1500 }, i).catch(() => {});
    const state = await read(i);
    const clipboard = await page.evaluate(() => navigator.clipboard.readText());
    assert(state.copied && state.icons.join() === "icon-done" && state.text === "", `copy button ${i + 1}: copied state must show only the tick icon and no text (shows ${JSON.stringify(state.icons)} / "${state.text}")`);
    assert(state.liveHidden && state.live === "Copied", `copy button ${i + 1}: the visually hidden live region must say "Copied" (says "${state.live}")`);
    assert(clipboard === want[i], `copy button ${i + 1}: clipboard holds "${clipboard}"`);
    assert(JSON.stringify(before.sizes) === JSON.stringify(state.sizes), `copy button ${i + 1}: layout shifted when copied (${JSON.stringify(before.sizes)} -> ${JSON.stringify(state.sizes)})`);
  }
  // A second click while the tick shows restarts the 2 s window: the first click's timer must not clear it early.
  const first = (await page.$$(".copy-box button"))[0];
  await first.click();
  await new Promise((r) => setTimeout(r, 1200));
  await first.click();
  await new Promise((r) => setTimeout(r, 1200)); // 2.4 s after the first click, 1.2 s after the second
  assert(await page.$eval(".copy-box button", (b) => "copied" in b.dataset), "copy.js must clear the previous timer: a second click was cut short by the first click's timeout");
  await new Promise((r) => setTimeout(r, 2200));
  assert(await page.$$eval(".copy-box button", (bs) => bs.every((b) => !("copied" in b.dataset))), "copy confirmation must clear after a moment");
}

const config = readVercelConfig();
checkVercelConfig(config);
const notFound = read(join(PUBLIC, "404.html"));
assert(/<h1\b/.test(notFound) && /href="\/"/.test(notFound), "404.html must exist with a heading and a link home");
assertCurly("404", notFound);
await checkRendered(config);

if (failures.length) {
  console.error(`check: ${failures.length} failure(s)`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log("check: ok");
