import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// O build vai para dentro do pacote Python; `vitrix serve` serve essa pasta em "/".
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: "../src/vitrix/ui", emptyOutDir: true },
  server: { proxy: { "/api": "http://127.0.0.1:8000" } },
});
