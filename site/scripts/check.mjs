// Checks for the iBridge marketing site. Run: node site/scripts/check.mjs
// Static checks read site/public; each section reports its own failures.
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
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
const squash = (s) => s.replace(/\s+/g, "");

// ---------- Unit 1: page copy, naming, links ----------
const CONNECTOR = "https://mcp.ibridge.fyi/mcp";
const ALLOWED_EXTERNAL = new Set([
  CONNECTOR,
  "https://mcp.ibridge.fyi/privacy",
  "https://mcp.ibridge.fyi/terms",
  "https://mcp.ibridge.fyi/account",
  "https://github.com/AlexanderTar/icloud-mcp",
]);
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
  assert(html.includes("assets/copy.js"), "page must load assets/copy.js");

  // Prices exactly.
  assert(!/US\$\s*1\.99(?!\/month|<small>\/month)/.test(html.replace(/<small>\/month<\/small>/g, "/month")), "price US$1.99 not followed by /month");
  assert(!/\$\s?\d/.test(text.replace(/US\$\d/g, "")), "price not written as US$");

  // Links: hrefs are anchors that exist, files that exist, or allow-listed addresses.
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
  const hrefs = [...html.matchAll(/\bhref="([^"]*)"/g)].map((m) => m[1]);
  for (const href of hrefs) {
    if (href.startsWith("#")) assert(ids.has(href.slice(1)), `anchor ${href} has no target`);
    else if (/^https?:/.test(href)) assert(ALLOWED_EXTERNAL.has(href), `unapproved external link ${href}`);
    else assert(existsSync(join(PUBLIC, href.split("#")[0].replace(/^\//, ""))), `local link ${href} does not resolve`);
  }
  for (const want of ALLOWED_EXTERNAL) if (want !== CONNECTOR) assert(hrefs.includes(want), `link missing: ${want}`);
  const connectHrefs = [...html.matchAll(/<a\b[^>]*class="[^"]*btn[^"]*"[^>]*href="([^"]*)"[^>]*>\s*Connect\s*</g)].map((m) => m[1]);
  assert(connectHrefs.length >= 1 && connectHrefs.every((h) => h === "#how"), "Connect buttons must go to #how");

  // No external requests from any shipped file (html, css, js, svg), apart from the allow-list and the SVG namespace.
  for (const file of walk(PUBLIC).filter((f) => /\.(html|css|js|mjs|svg|json)$/.test(f))) {
    const src = read(file).replace(/https?:\/\/www\.w3\.org\/\d+\/svg/g, "").replace(/https?:\/\/www\.w3\.org\/1999\/xlink/g, "");
    for (const [url] of src.matchAll(/https?:\/\/[^\s"'<>)\\]+/g)) {
      const clean = url.replace(/[.,]+$/, "");
      assert(ALLOWED_EXTERNAL.has(clean), `${relative(SITE, file)}: external URL ${clean}`);
    }
    assert(!/@import|url\(\s*["']?\/\//.test(src), `${relative(SITE, file)}: @import or protocol-relative url`);
  }
  for (const m of html.matchAll(/<(?:script|link|img|iframe)\b[^>]*\b(?:src|href)="([^"]*)"/g)) {
    assert(!/^(?:https?:)?\/\//.test(m[1]) || ALLOWED_EXTERNAL.has(m[1]), `external resource ${m[1]}`);
  }
  for (const m of html.matchAll(/<(?:script|img|link)\b[^>]*\b(?:src|href)="(?!https?:|#|mailto:)([^"]*)"/g)) {
    assert(existsSync(join(PUBLIC, m[1].replace(/^\//, ""))), `missing file ${m[1]}`);
  }

  // Design tokens and components are the shipped ones, byte for byte.
  for (const f of ["tokens.css", "components.css", "copy.js"]) {
    assert(read(join(PUBLIC, "assets", f)) === read(join(SITE, "design", f)) && read(join(SITE, "design", f)) !== "",
      `public/assets/${f} drifted from site/design/${f} (run node site/scripts/sync-design.mjs)`);
  }
}

checkPage();

if (failures.length) {
  console.error(`check: ${failures.length} failure(s)`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log("check: ok");
