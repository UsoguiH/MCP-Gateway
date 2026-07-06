import { defineConfig } from "vite";
import path from "path";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The built dashboard is served by the FastAPI gateway from ../ui at the /ui/
// base (index.html is returned at "/"; hashed assets live under /ui/assets/).
export default defineConfig({
  base: "/ui/",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  build: {
    outDir: path.resolve(__dirname, "../ui"),
    emptyOutDir: true,
    assetsDir: "assets",
  },
});
