import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import tailwindcss from "@tailwindcss/vite";

// Dev server proxies API calls to the local audit-api (uvicorn :8100) so the
// SPA can use cookie/bearer auth without CORS setup.
export default defineConfig({
  plugins: [vue(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/v1": "http://127.0.0.1:8100",
      "/internal": "http://127.0.0.1:8100",
      "/healthz": "http://127.0.0.1:8100",
    },
  },
});
