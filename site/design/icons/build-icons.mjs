// Generates every icon option as SVG files plus the comparison page.
// Run: node site/design/icons/build-icons.mjs
// Each option is drawn once on a 64×64 grid; colours come from the palette
// below, which mirrors the brand tokens in ../tokens.css.
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

const palette = {
  light: { ink: "#0F2538", teal: "#0B7A80", coral: "#E0532B", bg: "#FFFFFF" },
  dark: { ink: "#EAF2F5", teal: "#5CC8CC", coral: "#FF7F57", bg: "#0E1520" },
};

// Cloud built from three circles (r 8 / 12 / 9) on a flat base at y = 40.
// Bounds: x 10–54, y 12–40. `open` leaves the base edge out.
const CLOUD_OPEN = "M18 40 A8 8 0 1 1 19 24.05 A12 12 0 0 1 42.87 22.26 A9 9 0 1 1 45 40";
const CLOUD = `${CLOUD_OPEN} Z`;

const options = [
  {
    id: "a-cloud-deck",
    name: "A · Cloud Deck",
    concept: "A cloud outline riding on a bridge deck, carried by a single arch below. Line art; the deck is the accent.",
    box: [2, 2, 60, 60],
    draw: (c) => `
  <g fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-width="5">
    <path d="${CLOUD_OPEN}" transform="translate(0 -4)" stroke="${c.teal}"/>
    <path d="M10 57 Q32 17 54 57" stroke="${c.ink}"/>
    <path d="M5 36 H59" stroke="${c.coral}"/>
  </g>`,
    // 16 px: filled cloud, thicker arch and deck, so the cloud no longer fades.
    small: {
      box: [2, 4, 60, 60],
      draw: (c) => `
  <path d="${CLOUD}" fill="${c.teal}" transform="translate(-6.4 -9.6) scale(1.2)"/>
  <g fill="none" stroke-linecap="round" stroke-linejoin="round">
    <path d="M11 61 Q32 23 53 61" stroke="${c.ink}" stroke-width="7"/>
    <path d="M4 42 H60" stroke="${c.coral}" stroke-width="7"/>
  </g>`,
    },
  },
  {
    id: "b-cloud-arch",
    name: "B · Cloud Arch",
    concept: "A solid cloud with an arch cut from its base, so the cloud itself stands like a bridge.",
    box: [6, 8, 52, 52],
    draw: (c) => `
  <path fill="${c.teal}" fill-rule="evenodd" transform="translate(0 4)" d="${CLOUD} M22.5 40 V36 A9.5 9.5 0 0 1 41.5 36 V40 Z"/>
  <path d="M8 52 H56" stroke="${c.coral}" stroke-width="4.5" stroke-linecap="round"/>`,
  },
  {
    id: "c-viaduct",
    name: "C · Viaduct",
    concept: "Three bridge arches on piers, the middle one raised, so their tops trace a cloud. One line plus a water line.",
    box: [2, 8, 60, 60],
    draw: (c) => `
  <g fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-width="5">
    <path d="M7 50 V40 A6.5 6.5 0 0 1 20 40 V32 A12 12 0 0 1 44 32 V40 A6.5 6.5 0 0 1 57 40 V50 M20 40 V50 M44 40 V50" stroke="${c.teal}"/>
    <path d="M4 56 H60" stroke="${c.coral}"/>
  </g>`,
  },
  {
    id: "d-i-pylon",
    name: "D · i-Pylon",
    concept: "A lowercase i: the stem is a bridge tower, the dot is a cloud, the cables and deck hang from it.",
    box: [2, 2, 60, 60],
    draw: (c) => `
  <g fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-width="4.5">
    <path d="M26 30 Q16 47 6 49 M38 30 Q48 47 58 49 M6 50 H58" stroke="${c.coral}"/>
  </g>
  <rect x="26" y="26" width="12" height="32" rx="6" fill="${c.ink}"/>
  <path d="${CLOUD}" fill="${c.teal}" transform="translate(18.4 1.5) scale(0.42)"/>`,
  },
  {
    id: "e-suspension",
    name: "E · Suspension",
    concept: "A two-tower suspension bridge reaching up into a small cloud. The most literal, illustrative option.",
    box: [0, 0, 64, 64],
    draw: (c) => `
  <path d="${CLOUD}" fill="${c.teal}" transform="translate(18.6 3) scale(0.42)"/>
  <g fill="none" stroke-linecap="round" stroke-linejoin="round">
    <path d="M4 44 Q12 28 18 20 Q32 56 46 20 Q52 28 60 44" stroke="${c.coral}" stroke-width="4"/>
    <path d="M18 18 V54 M46 18 V54" stroke="${c.ink}" stroke-width="5"/>
    <path d="M3 46 H61" stroke="${c.ink}" stroke-width="4.5"/>
  </g>`,
    // 16 px: drop the side spans, keep two towers, one main cable and a bigger cloud.
    small: {
      box: [0, 0, 64, 64],
      draw: (c) => `
  <path d="${CLOUD}" fill="${c.teal}" transform="translate(9.5 -6) scale(0.7)"/>
  <g fill="none" stroke-linecap="round" stroke-linejoin="round">
    <path d="M14 28 Q32 58 50 28" stroke="${c.coral}" stroke-width="6"/>
    <path d="M14 26 V60 M50 26 V60" stroke="${c.ink}" stroke-width="7"/>
    <path d="M4 50 H60" stroke="${c.ink}" stroke-width="6"/>
  </g>`,
    },
  },
  {
    id: "f-two-shores",
    name: "F · Two Shores",
    concept: "Two clouds joined by one arch span: ibridge connects your iCloud data and your assistant.",
    box: [2, 5, 60, 60],
    draw: (c) => `
  <path d="M15 42 Q32 6 49 42" fill="none" stroke="${c.coral}" stroke-width="5" stroke-linecap="round"/>
  <path d="${CLOUD}" fill="${c.teal}" transform="translate(-1.5 26) scale(0.5)"/>
  <path d="${CLOUD}" fill="${c.ink}" transform="translate(33.5 26) scale(0.5)"/>`,
    // 16 px: bigger clouds and a taller, thicker span, filling the square.
    small: {
      box: [0, 0, 64, 64],
      draw: (c) => `
  <path d="M13 50 Q32 -14 51 50" fill="none" stroke="${c.coral}" stroke-width="7" stroke-linecap="round"/>
  <path d="${CLOUD}" fill="${c.teal}" transform="translate(-6 31) scale(0.7)"/>
  <path d="${CLOUD}" fill="${c.ink}" transform="translate(26 31) scale(0.7)"/>`,
    },
  },
];

const svg = (inner, extra = "", box = [0, 0, 64, 64]) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${box.join(" ")}" width="64" height="64">${extra}${inner}\n</svg>\n`;

// App tile: rounded square (22.5 % radius), mark scaled to 72 % and centred.
const tile = (o, mode) => {
  const c = palette[mode];
  const [from, to, edge] =
    mode === "light" ? ["#FFFFFF", "#E7F3F3", "#D5E3E6"] : ["#17344C", "#0B1826", "#24445E"];
  const defs = `
  <defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${from}"/><stop offset="1" stop-color="${to}"/></linearGradient></defs>
  <rect x="0.5" y="0.5" width="63" height="63" rx="14.2" fill="url(#g)" stroke="${edge}" stroke-width="1.5" vector-effect="non-scaling-stroke"/>`;
  const [bx, by, bw] = o.box;
  const k = 46.08 / bw;
  return svg(`<g transform="translate(8.96 8.96) scale(${k.toFixed(4)}) translate(${-bx} ${-by})">${o.draw(c)}</g>`, defs);
};

// Favicon: the bare mark, switching colours with the browser theme.
const small = (o) => o.small ?? { box: o.box, draw: o.draw };

const favicon = (o) => {
  const L = palette.light;
  const D = palette.dark;
  const { box, draw } = small(o);
  let inner = draw({ ink: "var(--ink)", teal: "var(--teal)", coral: "var(--coral)" });
  const style = `
  <style>:root{--ink:${L.ink};--teal:${L.teal};--coral:${L.coral}}@media (prefers-color-scheme:dark){:root{--ink:${D.ink};--teal:${D.teal};--coral:${D.coral}}}</style>`;
  // SVG presentation attributes don't resolve var(); move colours into style attributes.
  inner = inner.replace(/(fill|stroke)="var\((--[a-z]+)\)"/g, 'style="$1:var($2)"');
  return svg(inner, style, box);
};

for (const o of options) {
  for (const mode of ["light", "dark"]) {
    writeFileSync(join(here, `${o.id}-mark-${mode}.svg`), svg(o.draw(palette[mode]), "", o.box));
    writeFileSync(join(here, `${o.id}-tile-${mode}.svg`), tile(o, mode));
    const sm = small(o);
    writeFileSync(join(here, `${o.id}-small-${mode}.svg`), svg(sm.draw(palette[mode]), "", sm.box));
  }
  writeFileSync(join(here, `${o.id}-favicon.svg`), favicon(o));
}

// ---------- comparison page ----------
const panel = (o, mode) => `
      <div class="panel ${mode}">
        <div class="label">${mode === "light" ? "Light" : "Dark"}</div>
        <div class="row">
          <figure><img src="${o.id}-small-${mode}.svg" width="16" height="16" alt=""><figcaption>16</figcaption></figure>
          <figure><canvas class="px" data-src="${o.id}-small-${mode}.svg" width="16" height="16"></canvas><figcaption>16 ×4</figcaption></figure>
          <figure><img src="${o.id}-mark-${mode}.svg" width="32" height="32" alt=""><figcaption>32</figcaption></figure>
          <figure><img src="${o.id}-tile-${mode}.svg" width="180" height="180" alt=""><figcaption>180 tile</figcaption></figure>
          <figure class="lockup"><img src="${o.id}-mark-${mode}.svg" width="40" height="40" alt=""><span>ibridge</span><figcaption>lockup</figcaption></figure>
        </div>
        <div class="tab"><img src="${o.id}-small-${mode}.svg" width="16" height="16" alt=""><span>ibridge · Connect iCloud to your AI assistant</span></div>
      </div>`;

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ibridge icon options</title>
<style>
  :root { color-scheme: light; --text:#0F2538; --muted:#4A5B6B; --line:#DCE3E8; }
  * { box-sizing: border-box; }
  body { margin:0; background:#F6F8F9; color:var(--text); font:15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  header { padding:40px 48px 8px; }
  h1 { font-size:32px; letter-spacing:-0.02em; margin:0 0 6px; }
  header p { color:var(--muted); margin:0; max-width:760px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fill, minmax(min(100%, 640px), 1fr)); gap:24px; padding:24px 48px; }
  section { background:#fff; border:1px solid var(--line); border-radius:20px; padding:24px; }
  h2 { font-size:20px; margin:0 0 4px; letter-spacing:-0.01em; }
  section > p { color:var(--muted); margin:0 0 16px; }
  .panel { border-radius:14px; padding:16px; margin-top:12px; }
  .panel.light { background:#FFFFFF; border:1px solid var(--line); }
  .panel.dark { background:#0E1520; color:#EAF2F5; }
  .label { font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:.06em; opacity:.7; margin-bottom:8px; }
  .row { display:flex; align-items:flex-end; gap:20px; flex-wrap:wrap; }
  figure { margin:0; display:flex; flex-direction:column; align-items:center; gap:6px; }
  figcaption { font-size:11px; opacity:.65; }
  .px { image-rendering:pixelated; width:64px; height:64px; }
  .lockup { flex-direction:row; flex-wrap:wrap; justify-content:center; align-items:center; gap:8px; }
  .lockup span { font-size:30px; font-weight:650; letter-spacing:-0.03em; }
  .lockup figcaption { width:100%; text-align:center; }
  .tab { margin-top:14px; display:inline-flex; align-items:center; gap:8px; font-size:12px; padding:6px 12px; border-radius:8px 8px 0 0; }
  .light .tab { background:#EEF1F3; }
  .dark .tab { background:#1B2633; }
  .big { padding:8px 48px 48px; }
  .big h2 { margin:24px 0 12px; }
  .bigrow { display:flex; gap:24px; flex-wrap:wrap; }
  .bigrow > div { border-radius:24px; padding:24px; }
  .bigrow > div { flex:0 1 auto; max-width:100%; }
  .bigrow img { display:block; width:512px; max-width:100%; height:auto; }
</style>
</head>
<body>
<header>
  <h1>ibridge icon options</h1>
  <p>Six bridge-and-cloud marks. Each is shown as the bare mark at 16 and 32&nbsp;px (A, E and F use a simplified variant at 16&nbsp;px, the same one their favicon uses), the 16&nbsp;px render magnified ×4 to judge its pixels, the 180&nbsp;px touch tile, a wordmark lockup and a browser-tab mock, on light and dark. 512&nbsp;px tiles are further down. Teal, coral and ink are the brand colours; no option uses Apple's white-cloud-on-blue look.</p>
</header>
<div class="grid">
${options
  .map(
    (o) => `  <section id="${o.id}">
    <h2>${o.name}</h2>
    <p>${o.concept}${o.small ? " <b>Has a simplified 16&nbsp;px variant</b> (<code>-small-*.svg</code>, also used by the favicon)." : ""}</p>${panel(o, "light")}${panel(o, "dark")}
  </section>`,
  )
  .join("\n")}
</div>
<div class="big">
${options
  .map(
    (o) => `  <h2 id="${o.id}-512">${o.name} at 512&nbsp;px</h2>
  <div class="bigrow">
    <div style="background:#fff;border:1px solid #DCE3E8"><img src="${o.id}-tile-light.svg" width="512" height="512" alt="${o.name}, light tile"></div>
    <div style="background:#0E1520"><img src="${o.id}-tile-dark.svg" width="512" height="512" alt="${o.name}, dark tile"></div>
  </div>`,
  )
  .join("\n")}
</div>
<script>
  // Rasterise each mark at a true 16×16, then show it magnified so its pixels can be judged.
  for (const cv of document.querySelectorAll("canvas.px")) {
    const img = new Image();
    img.onload = () => cv.getContext("2d").drawImage(img, 0, 0, 16, 16);
    img.src = cv.dataset.src;
  }
</script>
</body>
</html>
`;
writeFileSync(join(here, "index.html"), page);
console.log(`wrote ${options.length} options`);
