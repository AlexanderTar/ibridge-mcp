// Exports icon B (Cloud Arch) from site/design/icons into site/public:
// favicon.svg (theme-aware), apple-touch-icon.png (180x180), icon-512.png and og.png (1200x630).
// Rasteriser: @resvg/resvg-js, pinned in package.json. Run: npm ci --prefix site && node site/scripts/export-icons.mjs
// og.png draws text with a system sans font, so rerun it on macOS to regenerate; the committed PNG is what ships.
import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Resvg } from "@resvg/resvg-js";

const SITE = join(dirname(fileURLToPath(import.meta.url)), "..");
const icons = (f) => join(SITE, "design", "icons", f);
const out = (f) => join(SITE, "public", f);
const png = (svg, width, options = {}) => new Resvg(svg, { fitTo: { mode: "width", value: width }, ...options }).render().asPng();

copyFileSync(icons("b-cloud-arch-favicon.svg"), out("favicon.svg"));

const tile = readFileSync(icons("b-cloud-arch-tile-light.svg"), "utf8");
// iOS rounds the touch icon itself and paints transparent corners black, so ship it square and full-bleed.
const square = tile.replace('rx="14.2"', 'rx="0"').replace(/ stroke="#D5E3E6" stroke-width="1.5" vector-effect="non-scaling-stroke"/, "");
if (square === tile) throw new Error("tile svg changed: update the square-corner rewrite");
writeFileSync(out("apple-touch-icon.png"), png(square, 180));
writeFileSync(out("icon-512.png"), png(tile, 512));

// Open Graph card: the tile, the name and one line, on the hero's pale teal wash.
// The tile's border is a 1.5px hairline (non-scaling). resvg scales it inside the nested 260px svg (4.06x, about 6px),
// so give it the width that renders as 1.5px: 1.5 / (260 / 64).
const hairline = (1.5 / (260 / 64)).toFixed(2);
const tileInner = tile.slice(tile.indexOf("<defs>"), tile.lastIndexOf("</svg>"))
  .replace(' stroke-width="1.5" vector-effect="non-scaling-stroke"', ` stroke-width="${hairline}"`);
if (!tileInner.includes(`stroke-width="${hairline}"`)) throw new Error("tile svg changed: update the og border rewrite");
const og = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs><linearGradient id="sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#EAF5F5"/><stop offset="1" stop-color="#FFFFFF"/></linearGradient></defs>
  <rect width="1200" height="630" fill="url(#sky)"/>
  <rect x="0" y="606" width="1200" height="24" fill="#0B7A80"/>
  <rect x="0" y="600" width="1200" height="6" fill="#E0532B"/>
  <g transform="translate(120 0)">
  <svg x="96" y="150" width="260" height="260" viewBox="0 0 64 64">${tileInner}</svg>
  <g font-family="Helvetica Neue, Helvetica, Arial, sans-serif" fill="#0F2538">
    <text x="412" y="252" font-size="112" font-weight="700" letter-spacing="-3">iBridge</text>
    <text x="414" y="326" font-size="42" fill="#46576A">Connect iCloud to your</text>
    <text x="414" y="378" font-size="42" fill="#46576A">AI assistant</text>
    <text x="414" y="448" font-size="30" font-weight="600" fill="#0B7A80">Mail · Calendar · Contacts</text>
  </g>
  </g>
</svg>`;
writeFileSync(out("og.png"), png(og, 1200, { font: { loadSystemFonts: true, defaultFontFamily: "Helvetica Neue" } }));
