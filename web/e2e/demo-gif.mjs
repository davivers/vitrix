// README demo GIF: drives the real UI in Edge and encodes frames with gifenc (no ffmpeg).
//   node e2e/demo-gif.mjs [BASE_URL] [OUT.gif]
// Start a server first on a fresh repo:  vitrix init D && cd D && git init && git add -A && git commit -m init && vitrix serve --port 8133
// Default output: ../docs/images/demo.gif (960 px wide (1280x760 viewport at 0.75 scale: the two-column layout), one shared 128-colour palette, identical frames merged).
import { chromium } from "@playwright/test";
import gifenc from "gifenc"; // CommonJS build
const { GIFEncoder, applyPalette, quantize } = gifenc;
import { PNG } from "pngjs";
import { mkdirSync, writeFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const base = (process.argv[2] ?? "http://127.0.0.1:8133").replace(/\/$/, "");
const out = path.resolve(process.argv[3] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "docs", "images", "demo.gif"));
const VW = 1280, VH = 760, SCALE = 0.75, W = VW * SCALE, H = VH * SCALE, EVERY_MS = 150, MAX_BYTES = 5 * 1024 * 1024;

const browser = await chromium.launch({ channel: "msedge", headless: true });
const page = await (await browser.newContext({ viewport: { width: VW, height: VH }, deviceScaleFactor: SCALE, colorScheme: "light" })).newPage();

const frames = []; // { t, png }
let recording = false;
const t0 = Date.now();
const grab = (async () => {
  while (recording !== null) {
    if (recording) {
      try { frames.push({ t: Date.now() - t0, png: await page.screenshot({ type: "png" }) }); } catch { /* page navigating */ }
    }
    await new Promise((r) => setTimeout(r, EVERY_MS));
  }
})();
const PACE = 1.9; // slow the story down so a reader can follow (total ~25 s)
const pause = (ms) => page.waitForTimeout(ms * PACE);
// Sticky cards can cover a control near the viewport edge: centre it first, then click.
const press = async (locator) => { await locator.evaluate((e) => e.scrollIntoView({ block: "center" })); await locator.click(); };

try {
  await page.goto(`${base}/editor/windows/powershell_encoded.yml`);
  await page.locator(".cm-content").first().waitFor();
  recording = true;
  await pause(1200);

  // 1. Type a small change
  await page.locator(".cm-content").first().click();
  await page.keyboard.press("Control+End");
  await page.keyboard.press("Enter");
  await page.keyboard.type("# tuned for the SOC: encoded command is rarely legitimate", { delay: 70 });
  await pause(900);

  // 2. Tests tab passes
  await press(page.getByRole("tab", { name: "Tests" }));
  await pause(2200);

  // 3. Replay run
  await press(page.getByRole("tab", { name: "Replay" }));
  await pause(600);
  await press(page.getByRole("button", { name: "Run replay" }));
  await page.getByRole("table", { name: "Draft replay per dataset" }).waitFor();
  await pause(2200);

  // 4. Gate approved
  await press(page.getByRole("tab", { name: "Quality gate" }));
  await page.getByText("Approved", { exact: true }).first().waitFor();
  await pause(2600);
} finally {
  recording = null;
  await grab;
  await browser.close();
}

// ---- encode ----
if (process.env.DEMO_GIF_DUMP) { // debugging aid: write every 8th raw frame as PNG
  mkdirSync(process.env.DEMO_GIF_DUMP, { recursive: true });
  frames.forEach((f, i) => i % 8 === 0 && writeFileSync(path.join(process.env.DEMO_GIF_DUMP, `frame-${String(i).padStart(3, "0")}.png`), f.png));
}
const decoded = frames.map((f) => ({ t: f.t, rgba: PNG.sync.read(f.png).data }));
if (decoded.length < 5) throw new Error(`only ${decoded.length} frames captured`);
const merged = []; // identical consecutive frames are merged (longer delay)
for (const f of decoded) {
  const last = merged.at(-1);
  if (last && Buffer.compare(Buffer.from(last.rgba.buffer, last.rgba.byteOffset, last.rgba.length), Buffer.from(f.rgba.buffer, f.rgba.byteOffset, f.rgba.length)) === 0) continue;
  merged.push(f);
}
// shared palette from ~12 evenly spaced frames
const step = Math.max(1, Math.floor(merged.length / 12));
const sample = merged.filter((_, i) => i % step === 0).map((f) => f.rgba);
const cat = new Uint8Array(sample.reduce((n, s) => n + s.length, 0));
let off = 0;
for (const s of sample) { cat.set(s, off); off += s.length; }
const palette = quantize(cat, 128);

const gif = GIFEncoder();
merged.forEach((f, i) => {
  const next = merged[i + 1]?.t ?? f.t + 1500;
  const delay = Math.min(Math.max(next - f.t, 100), 2500);
  gif.writeFrame(applyPalette(f.rgba, palette), W, H, { palette: i === 0 ? palette : undefined, delay, repeat: 0 });
});
gif.finish();
mkdirSync(path.dirname(out), { recursive: true });
writeFileSync(out, gif.bytes());
const size = statSync(out).size;
console.log(`${out}: ${((decoded.at(-1).t - decoded[0].t) / 1000).toFixed(1)} s, ${merged.length} frames (of ${decoded.length}), ${(size / 1024 / 1024).toFixed(2)} MB`);
if (size > MAX_BYTES) { console.error("GIF is over 5 MB: shorten the pauses or lower the palette"); process.exit(1); }
