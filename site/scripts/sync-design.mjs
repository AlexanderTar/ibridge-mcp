// Copies the design tokens, components, copy script and the chosen icon (B · Cloud Arch)
// from site/design into site/public, so the shipped page uses them unchanged.
// Run: node site/scripts/sync-design.mjs
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SITE = join(dirname(fileURLToPath(import.meta.url)), "..");
const copy = (from, to) => {
  mkdirSync(dirname(join(SITE, to)), { recursive: true });
  copyFileSync(join(SITE, from), join(SITE, to));
};

for (const f of ["tokens.css", "components.css", "copy.js", "tick.svg"]) copy(`design/${f}`, `public/assets/${f}`);
for (const variant of ["mark", "tile"]) {
  for (const theme of ["light", "dark"]) copy(`design/icons/b-cloud-arch-${variant}-${theme}.svg`, `public/img/${variant}-${theme}.svg`);
}
