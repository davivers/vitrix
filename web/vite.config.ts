import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Normal build goes into the Python package; `vitrix serve` serves that folder at "/".
// VITE_DEMO=1 builds the static read-only demo (ADR 0003) into build/demo, served under /<repo>/ on GitHub Pages.
const demo = process.env.VITE_DEMO === "1";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: demo ? (process.env.VITRIX_DEMO_BASE ?? "/vitrix/") : "/",
  publicDir: demo ? "demo/public" : "public",
  build: { outDir: demo ? "../build/demo" : "../src/vitrix/ui", emptyOutDir: true },
  server: { proxy: { "/api": "http://127.0.0.1:8000" } },
});
