// README cover options for iBridge. Writes one SVG per option and theme, plus a 2x PNG of each.
// Run on macOS (text uses system Helvetica Neue and Menlo): node site/design/readme-cover/build.mjs
// Needs rsvg-convert (brew install librsvg). Colours are the tokens in ../tokens.css.
import { writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const DIR = dirname(fileURLToPath(import.meta.url));
const W = 1280, H = 400;

// tokens.css, light and dark
const light = {
  bg: "#FFFFFF", sky: "#EAF5F5", surface: "#FFFFFF", sunken: "#F0F4F6", border: "#DCE3E8", borderStrong: "#C3CED6",
  text: "#0F2538", text2: "#46576A", text3: "#5B6B7B", link: "#0A6C72", brand: "#0B7A80", onBrand: "#FFFFFF",
  tint: "#E3F2F2", accent: "#E0532B", tileTop: "#FFFFFF", tileBottom: "#E7F3F3", tileStroke: "#D5E3E6",
};
const dark = {
  bg: "#0B1118", sky: "#0F2129", surface: "#131D27", sunken: "#0A1017", border: "#233140", borderStrong: "#33475A",
  text: "#EAF2F5", text2: "#A9B9C6", text3: "#8A9CAB", link: "#6CD0D3", brand: "#5CC8CC", onBrand: "#062528",
  tint: "#12303A", accent: "#FF7F57", tileTop: "#17344C", tileBottom: "#0B1826", tileStroke: "#24445E",
};
const INK = "#0F2538", TEAL = "#0B7A80", CORAL = "#E0532B";

const SANS = "Helvetica Neue, Helvetica, Arial, sans-serif";
const MONO = "Menlo, ui-monospace, Consolas, monospace";
const TAGLINE = "Your iCloud, in your AI assistant.";
const SERVICES = "Mail · Calendar · Contacts";

// Icon B (Cloud Arch), from ../icons/b-cloud-arch-*.svg, in its 64-unit space.
const CLOUD = "M18 40 A8 8 0 1 1 19 24.05 A12 12 0 0 1 42.87 22.26 A9 9 0 1 1 45 40 Z M22.5 40 V36 A9.5 9.5 0 0 1 41.5 36 V40 Z";
const markInner = (cloud, deck) =>
  `<path fill="${cloud}" fill-rule="evenodd" transform="translate(0 4)" d="${CLOUD}"/><path d="M8 52 H56" stroke="${deck}" stroke-width="4.5" stroke-linecap="round"/>`;
// Bare mark, drawn in a size x size box.
const mark = (x, y, size, cloud, deck) =>
  `<svg x="${x}" y="${y}" width="${size}" height="${size}" viewBox="6 8 52 52">${markInner(cloud, deck)}</svg>`;
// App tile; the border is a 1.5 px hairline at the drawn size.
const tile = (x, y, size, t, id) => {
  const hair = (1.5 / (size / 64)).toFixed(2);
  return `<svg x="${x}" y="${y}" width="${size}" height="${size}" viewBox="0 0 64 64">
    <defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${t.tileTop}"/><stop offset="1" stop-color="${t.tileBottom}"/></linearGradient></defs>
    <rect x="0.5" y="0.5" width="63" height="63" rx="14.2" fill="url(#${id})" stroke="${t.tileStroke}" stroke-width="${hair}"/>
    <g transform="translate(8.96 8.96) scale(0.8862) translate(-6 -8)">${markInner(t.brand, t.accent)}</g></svg>`;
};

// DS feature icons (24-unit stroke icons from the Daylight direction): Mail, Calendar, Contacts.
const GLYPH = {
  mail: `<rect x="3" y="5" width="18" height="14" rx="3"/><path d="M4 7.5l8 5.5 8-5.5"/>`,
  calendar: `<rect x="3.5" y="5" width="17" height="15" rx="3"/><path d="M3.5 10h17M8 3v4M16 3v4"/>`,
  contacts: `<circle cx="12" cy="9" r="3.5"/><path d="M5 20c1.2-3.6 4-5 7-5s5.8 1.4 7 5"/>`,
};
const glyph = (name, x, y, size, color) =>
  `<svg x="${x}" y="${y}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">${GLYPH[name]}</svg>`;

// Rounded banner frame: clip + background + hairline border on top of the content.
const frame = (id, fill, border, body, { radius = 24, defs = "" } = {}) => `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
  <defs>${defs}<clipPath id="${id}-clip"><rect width="${W}" height="${H}" rx="${radius}"/></clipPath></defs>
  <g clip-path="url(#${id}-clip)">
    <rect width="${W}" height="${H}" fill="${fill}"/>
${body}
  </g>
  ${border ? `<rect x="1" y="1" width="${W - 2}" height="${H - 2}" rx="${radius - 1}" fill="none" stroke="${border}" stroke-width="2"/>` : ""}
</svg>
`;

// ---------- 1 · Wordmark: the og.png card as a wide banner (light + dark) ----------
function wordmark(t, scheme) {
  const id = `wm-${scheme}`;
  const defs = `<linearGradient id="${id}-sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${t.sky}"/><stop offset="1" stop-color="${t.bg}"/></linearGradient>`;
  const body = `
    <rect width="${W}" height="${H}" fill="url(#${id}-sky)"/>
    <rect x="0" y="376" width="${W}" height="24" fill="${t.brand}"/>
    <rect x="0" y="370" width="${W}" height="6" fill="${t.accent}"/>
    ${tile(232, 85, 200, t, `${id}-tile`)}
    <g font-family="${SANS}">
      <text x="484" y="180" font-size="104" font-weight="700" letter-spacing="-3" fill="${t.text}">iBridge</text>
      <text x="487" y="240" font-size="38" fill="${t.text2}">${TAGLINE}</text>
      <text x="487" y="292" font-size="28" font-weight="600" fill="${t.link}">${SERVICES}</text>
    </g>`;
  return frame(id, t.bg, t.border, body, { defs });
}

// ---------- 2 · Product moment: tagline left, assistant chat right (light + dark) ----------
function chat(t, scheme) {
  const id = `ch-${scheme}`;
  const defs = `<linearGradient id="${id}-sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${t.sky}"/><stop offset="1" stop-color="${t.bg}"/></linearGradient>
    <filter id="${id}-shadow" x="-20%" y="-20%" width="140%" height="160%"><feDropShadow dx="0" dy="16" stdDeviation="18" flood-color="${scheme === "light" ? INK : "#000000"}" flood-opacity="${scheme === "light" ? 0.14 : 0.5}"/></filter>`;
  // window: x 680..1216, top 52, runs off the bottom edge
  const wx = 680, wy = 52, ww = 536;
  const event = (y, title, time) => `
      <rect x="${wx + 46}" y="${y - 22}" width="5" height="32" rx="2.5" fill="${t.accent}"/>
      <text x="${wx + 64}" y="${y}" font-size="21" fill="${t.text}">${title}</text>
      <text x="${wx + 410}" y="${y}" font-size="19" fill="${t.text3}" text-anchor="end">${time}</text>`;
  const body = `
    <rect width="${W}" height="${H}" fill="url(#${id}-sky)"/>
    <g font-family="${SANS}">
      ${mark(72, 62, 44, t.brand, t.accent)}
      <text x="126" y="98" font-size="34" font-weight="700" letter-spacing="-0.8" fill="${t.text}">iBridge</text>
      <text x="72" y="196" font-size="58" font-weight="700" letter-spacing="-1.8" fill="${t.text}">Your iCloud,</text>
      <text x="72" y="262" font-size="58" font-weight="700" letter-spacing="-1.8" fill="${t.text}">in your AI assistant.</text>
      <text x="74" y="324" font-size="27" font-weight="600" fill="${t.link}">${SERVICES}</text>
    </g>
    <g font-family="${SANS}" filter="url(#${id}-shadow)">
      <rect x="${wx}" y="${wy}" width="${ww}" height="420" rx="20" fill="${t.surface}" stroke="${t.border}" stroke-width="1.5"/>
    </g>
    <g font-family="${SANS}">
      <path d="M${wx + 0.75} ${wy + 52} V${wy + 20} a19.25 19.25 0 0 1 19.25 -19.25 H${wx + ww - 20} a19.25 19.25 0 0 1 19.25 19.25 V${wy + 52} Z" fill="${scheme === "light" ? "#F5F7F8" : "#0F1720"}"/>
      <path d="M${wx} ${wy + 52} H${wx + ww}" stroke="${t.border}" stroke-width="1.5"/>
      <circle cx="${wx + 26}" cy="${wy + 26}" r="6" fill="${t.borderStrong}"/><circle cx="${wx + 46}" cy="${wy + 26}" r="6" fill="${t.borderStrong}"/><circle cx="${wx + 66}" cy="${wy + 26}" r="6" fill="${t.borderStrong}"/>
      <text x="${wx + 86}" y="${wy + 33}" font-size="18" font-weight="500" fill="${t.text3}">Your assistant</text>
      <!-- user bubble: DS .bubble-user, 18 px radius with a 6 px bottom-right corner (components.css) -->
      <path d="M${wx + 154} ${wy + 78} H${wx + 492} a18 18 0 0 1 18 18 V${wy + 126} a6 6 0 0 1 -6 6 H${wx + 154} a18 18 0 0 1 -18 -18 V${wy + 96} a18 18 0 0 1 18 -18 Z" fill="${t.brand}"/>
      <text x="${wx + 488}" y="${wy + 113}" font-size="21" font-weight="500" fill="${t.onBrand}" text-anchor="end">What's on my calendar tomorrow?</text>
      <!-- assistant bubble -->
      <rect x="${wx + 24}" y="${wy + 152}" width="414" height="214" rx="20" fill="${t.sunken}" stroke="${t.border}" stroke-width="1.5"/>
      <rect x="${wx + 40}" y="${wy + 170}" width="186" height="32" rx="16" fill="${t.tint}"/>
      ${mark(wx + 48, wy + 176, 20, t.brand, t.accent)}
      <text x="${wx + 74}" y="${wy + 192}" font-size="17" font-weight="600" fill="${t.link}">iBridge · Calendar</text>
      ${event(wy + 240, "Team planning", "09:30")}
      ${event(wy + 288, "Lunch with Sam", "12:30")}
      ${event(wy + 336, "Dentist", "14:00")}
    </g>`;
  return frame(id, t.bg, t.border, body, { defs });
}

// ---------- 3 · Bridge: Cloud Arch stretched into a bridge, one dusk image for both themes ----------
function bridge() {
  const id = "br";
  const C = { text: "#EAF2F5", text2: "#B4C3CF", teal: "#5CC8CC", link: "#6CD0D3", coral: "#FF7F57", tint: "#12303A", tintStroke: "#24445E" };
  const defs = `<linearGradient id="${id}-dusk" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#17344C"/><stop offset="1" stop-color="#0B1826"/></linearGradient>`;
  const deckY = 262;
  // arch under the deck, between the two abutments; spandrel posts follow the arch
  const ax0 = 698, ax1 = 1068, crown = deckY + 22, foot = 420;
  const archY = (x) => { const u = (x - ax0) / (ax1 - ax0); return foot - (foot - crown) * (1 - (2 * u - 1) ** 2); };
  let posts = "";
  for (let x = ax0 + 38; x < ax1 - 20; x += 38) {
    const y = archY(x);
    if (y - deckY > 8) posts += `<path d="M${x} ${deckY + 4} V${y.toFixed(1)}" stroke="${C.teal}" stroke-opacity="0.45" stroke-width="3"/>`;
  }
  const pill = (name, x) => `
      <rect x="${x}" y="${deckY - 66}" width="58" height="58" rx="14" fill="${C.tint}" stroke="${C.tintStroke}" stroke-width="1.5"/>
      ${glyph(name, x + 13, deckY - 53, 32, C.link)}
      <path d="M${x - 46} ${deckY - 26} h30 M${x - 38} ${deckY - 44} h22" stroke="${C.teal}" stroke-opacity="0.35" stroke-width="3" stroke-linecap="round"/>`;
  const body = `
    <rect width="${W}" height="${H}" fill="url(#${id}-dusk)"/>
    <g font-family="${SANS}">
      <text x="72" y="168" font-size="88" font-weight="700" letter-spacing="-2.5" fill="${C.text}">iBridge</text>
      <text x="74" y="224" font-size="32" fill="${C.text2}">Your iCloud,</text>
      <text x="74" y="264" font-size="32" fill="${C.text2}">in your AI assistant.</text>
      <text x="74" y="322" font-size="24" font-weight="600" fill="${C.link}">${SERVICES}</text>
    </g>
    <!-- arch and posts -->
    <path d="M${ax0} ${foot} Q${(ax0 + ax1) / 2} ${2 * crown - foot} ${ax1} ${foot}" fill="none" stroke="${C.teal}" stroke-width="8" stroke-linecap="round"/>
    ${posts}
    <!-- abutments -->
    <rect x="540" y="${deckY + 4}" width="158" height="${H}" fill="${C.teal}" fill-opacity="0.16"/>
    <rect x="1068" y="${deckY + 4}" width="152" height="${H}" fill="${C.teal}" fill-opacity="0.16"/>
    <!-- deck -->
    <path d="M528 ${deckY} H1228" stroke="${C.coral}" stroke-width="7" stroke-linecap="round"/>
    <!-- iCloud side: the Cloud Arch cloud, sitting on the deck -->
    <path fill="${C.teal}" fill-rule="evenodd" transform="translate(${540 - 10 * 3.6} ${deckY - 3 - 44 * 3.6}) scale(3.6) translate(0 4)" d="${CLOUD}"/>
    <g font-family="${SANS}" font-size="20" font-weight="600" fill="${C.text2}">
      <text x="619" y="${deckY + 46}" text-anchor="middle">Your iCloud</text>
      <text x="1144" y="${deckY + 46}" text-anchor="middle">Your assistant</text>
    </g>
    <!-- Mail, Calendar, Contacts crossing the deck -->
    ${pill("mail", 762)}${pill("calendar", 868)}${pill("contacts", 974)}
    <!-- assistant side: a chat bubble -->
    <path d="M1090 ${deckY - 156} h108 a22 22 0 0 1 22 22 v70 a22 22 0 0 1 -22 22 h-62 l-26 22 v-22 h-20 a22 22 0 0 1 -22 -22 v-70 a22 22 0 0 1 22 -22 Z" fill="#EAF2F5"/>
    <circle cx="1118" cy="${deckY - 99}" r="8" fill="${TEAL}"/><circle cx="1144" cy="${deckY - 99}" r="8" fill="${TEAL}"/><circle cx="1170" cy="${deckY - 99}" r="8" fill="${TEAL}"/>`;
  return frame(id, "#0B1826", "#24445E", body, { defs });
}

// ---------- 4 · Connector: headline + the connector URL on brand teal, one image for both themes ----------
function connector() {
  const id = "cn";
  const defs = `<linearGradient id="${id}-teal" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0B7A80"/><stop offset="1" stop-color="#086268"/></linearGradient>`;
  // big faint Cloud Arch marks bleeding off the bottom corners, clear of the headline (which ends near x 1070)
  const big = 560, right = 480;
  const body = `
    <rect width="${W}" height="${H}" fill="url(#${id}-teal)"/>
    <svg x="${W - right * 0.45}" y="${H - right * 0.42}" width="${right}" height="${right}" viewBox="6 8 52 52" opacity="0.10">${markInner("#FFFFFF", "#FFFFFF")}</svg>
    <svg x="${-big * 0.42}" y="${H - big * 0.42}" width="${big * 0.8}" height="${big * 0.8}" viewBox="6 8 52 52" opacity="0.06">${markInner("#FFFFFF", "#FFFFFF")}</svg>
    <g font-family="${SANS}" text-anchor="middle">
      ${mark(W / 2 - 92, 44, 46, "#FFFFFF", "#FFB49B")}
      <text x="${W / 2 + 28}" y="81" font-size="36" font-weight="700" letter-spacing="-0.8" fill="#FFFFFF">iBridge</text>
      <text x="${W / 2}" y="178" font-size="60" font-weight="700" letter-spacing="-1.8" fill="#FFFFFF">${TAGLINE}</text>
      <text x="${W / 2}" y="232" font-size="28" font-weight="500" fill="#FFFFFF">${SERVICES}</text>
    </g>
    <!-- connector URL box -->
    <rect x="${W / 2 - 300}" y="276" width="600" height="68" rx="34" fill="#FFFFFF"/>
    <rect x="${W / 2 - 292}" y="284" width="148" height="52" rx="26" fill="#E3F2F2"/>
    <g font-family="${SANS}" font-size="20" font-weight="600" fill="#0A6C72" text-anchor="middle"><text x="${W / 2 - 218}" y="317">Connector</text></g>
    <text x="${W / 2 + 76}" y="319" font-family="${MONO}" font-size="25" fill="${INK}" text-anchor="middle">https://mcp.ibridge.fyi/mcp</text>
    <rect x="0" y="392" width="${W}" height="8" fill="${CORAL}"/>`;
  return frame(id, TEAL, null, body, { defs });
}

const outputs = {
  "1-wordmark-light": wordmark(light, "light"),
  "1-wordmark-dark": wordmark(dark, "dark"),
  "2-chat-light": chat(light, "light"),
  "2-chat-dark": chat(dark, "dark"),
  "3-bridge": bridge(),
  "4-connector": connector(),
};
for (const [name, svg] of Object.entries(outputs)) {
  // A missing token interpolates as "undefined" (or a bad sum as "NaN"); fail instead of drawing black text.
  const bad = svg.match(/.{0,40}\b(undefined|NaN)\b.{0,20}/);
  if (bad) throw new Error(`${name}: "${bad[1]}" in output near: ${bad[0]}`);
  const svgPath = join(DIR, `${name}.svg`);
  writeFileSync(svgPath, svg);
  execFileSync("rsvg-convert", ["--zoom", "2", "--output", join(DIR, `${name}@2x.png`), svgPath]);
}
console.log(`wrote ${Object.keys(outputs).length} svg + png pairs to ${DIR}`);
