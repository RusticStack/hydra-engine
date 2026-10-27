// Turns the animated architecture SVG into GIF frames, because GitHub shows README SVGs without
// their animation. Inlines the SVG, pauses its SMIL clock and seeks to each frame's time, so every
// frame is exact. Needs playwright-core and a Chrome; then encode with gifski:
//
//   python make_diagram.py out
//   node diagram_to_gif.mjs out/architecture-dark.svg frames-dark 15 11 1.5
//   gifski --fps 15 --quality 90 --width 1440 -o architecture-dark.gif frames-dark/f*.png
//
// (the same for light). CHROME_PATH selects the browser.
import { chromium } from "playwright-core";
import { readFileSync, mkdirSync } from "node:fs";
const [svgPath, outDir, fps, seconds, scale] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });
const svg = readFileSync(svgPath, "utf8");
const b = await chromium.launch({ executablePath: process.env.CHROME_PATH });
const p = await b.newPage({ viewport: { width: 960, height: 400 }, deviceScaleFactor: Number(scale) });
await p.setContent(`<html><body style="margin:0;background:transparent">${svg}</body></html>`);
await p.evaluate(() => document.querySelector("svg").pauseAnimations());
const n = Math.round(Number(fps) * Number(seconds));
for (let i = 0; i < n; i++) {
  await p.evaluate((t) => document.querySelector("svg").setCurrentTime(t), i / Number(fps));
  await p.screenshot({ path: `${outDir}/f${String(i).padStart(4, "0")}.png`, omitBackground: true, clip: { x: 0, y: 0, width: 960, height: 400 } });
}
await b.close();
console.log(n, "frames");
