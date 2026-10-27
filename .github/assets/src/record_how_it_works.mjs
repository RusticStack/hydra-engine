// Records the README's how-it-works.gif from the website's own "How it works" component
// (https://www.hydrare.dev/embed/how-it-works, the README variant), so the two never differ.
// A fake clock drives the page's animation: after a warm-up it captures exactly one period of the
// request script (6.96 s), so the GIF loops seamlessly. Needs playwright-core and a Chrome:
//
//   node record_how_it_works.mjs frames 15 6960 27840 [url]
//   gifski --fps 15 --quality 92 -o ../how-it-works.gif frames/f*.png
//
// CHROME_PATH selects the browser.
import { chromium } from "playwright-core";
import { mkdirSync } from "node:fs";
const [outDir, fps, periodMs, warmMs, url = "https://www.hydrare.dev/embed/how-it-works"] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });
const b = await chromium.launch({ executablePath: process.env.CHROME_PATH });
const p = await b.newPage({ viewport: { width: 1640, height: 420 }, deviceScaleFactor: 1 });
await p.clock.install({ time: 0 });
await p.goto(url, { waitUntil: "networkidle" });
// Let the art load and paint, then warm the script up past its first cycles.
for (let i = 0; i < 20; i++) { await p.clock.runFor(100); await p.waitForTimeout(50); }
await p.clock.runFor(Number(warmMs));
const n = Math.round((Number(fps) * Number(periodMs)) / 1000);
let done = 0;
for (let i = 0; i < n; i++) {
  const target = Math.round(((i + 1) * Number(periodMs)) / n);
  await p.locator("#frame").screenshot({ path: `${outDir}/f${String(i).padStart(4, "0")}.png` });
  await p.clock.runFor(target - done);
  done = target;
}
await b.close();
console.log(n, "frames");
