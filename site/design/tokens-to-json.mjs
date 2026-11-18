// Writes tokens.json from tokens.css so the two never drift.
// Run: node site/design/tokens-to-json.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const css = readFileSync(join(here, "tokens.css"), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");

const block = (selector) => {
  const start = css.indexOf(selector);
  const open = css.indexOf("{", start);
  const close = css.indexOf("}", open);
  return Object.fromEntries(
    [...css.slice(open + 1, close).matchAll(/--([\w-]+):\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]),
  );
};

const light = block(":root {");
const dark = block(':root[data-theme="dark"]');
const group = (prefix) => Object.fromEntries(Object.entries(light).filter(([k]) => k.startsWith(prefix)));

const json = {
  $description: "ibridge design tokens. Generated from tokens.css by tokens-to-json.mjs; edit tokens.css, not this file.",
  brand: group("brand-"),
  color: { light: group("color-"), dark },
  font: group("font-"),
  text: { ...group("text-"), ...group("leading-"), ...group("tracking-"), ...group("weight-") },
  space: { ...group("space-"), "section-y": light["section-y"], gutter: light.gutter, container: light.container, "container-narrow": light["container-narrow"] },
  radius: group("radius-"),
  shadow: { light: group("shadow-"), dark: Object.fromEntries(Object.entries(dark).filter(([k]) => k.startsWith("shadow-"))) },
  motion: { ...group("ease-"), ...group("duration-") },
  z: group("z-"),
};
for (const k of Object.keys(json.color.dark)) if (k.startsWith("shadow-")) delete json.color.dark[k];

writeFileSync(join(here, "tokens.json"), JSON.stringify(json, null, 2) + "\n");
console.log("wrote tokens.json");
