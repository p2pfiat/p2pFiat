import { defineConfig } from "vite";

export default defineConfig({
  // Relative base so the static bundle works cleanly on https://p2pfiat.github.io/,
  // https://p2pfiat.github.io/p2pFiat/, custom domains, and localhost alike.
  base: "./",
});
