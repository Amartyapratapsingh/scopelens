import { defineConfig } from "vite";
import { localWorkspace } from "./dev/local-workspace.ts";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The API is proxied rather than called cross-origin, so the browser treats the
// session cookie as first-party and no CORS configuration is needed.
export default defineConfig({
  plugins: [react(), tailwindcss(), localWorkspace()],
  server: {
    host: "127.0.0.1",
    strictPort: true,
    port: 5173,
    proxy: {
      "/api": {
        target: `http://127.0.0.1:${process.env.SCOPELENS_API_PORT ?? "8090"}`,
        changeOrigin: false,
      },
      "/healthz": `http://127.0.0.1:${process.env.SCOPELENS_API_PORT ?? "8090"}`,
      "/readyz": `http://127.0.0.1:${process.env.SCOPELENS_API_PORT ?? "8090"}`,
    },
  },
});
