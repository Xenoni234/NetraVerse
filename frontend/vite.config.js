import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { defineConfig } from "vite";

// Serve the unmodified Stitch exports at the product routes in development.
// Production copies the same documents to matching route directories in build.
const routeDocuments = {
  "/home": "src/pages/Home/index.html",
  "/simulate": "src/pages/Simulate/index.html",
  "/forecast": "src/pages/Forecast/index.html",
  "/attack": "src/pages/AttackTrajectory/index.html",
  "/investigate": "src/pages/Investigate/index.html",
  "/network": "src/pages/Network/index.html",
  "/validate": "src/pages/Validate/index.html",
  "/model": "src/pages/Model/index.html",
  "/live": "src/pages/Live/index.html",
  "/topology": "src/pages/Topology/index.html"
};

// The API runs on the sensor (Tailscale 100.72.80.52:8000). Proxying /api through
// the dev server lets pages call it same-origin (no CORS / private-network blocks).
const API_TARGET = process.env.NV_API_TARGET || "http://100.72.80.52:8000";

export default defineConfig({
  // Regex key so the proxy matches /api/... but NOT the frontend's own /api.js.
  server: { proxy: { "^/api/": { target: API_TARGET, changeOrigin: true } } },
  plugins: [{
    name: "stitch-route-documents",
    configureServer(server) {
      server.middlewares.use(async (request, response, next) => {
        const pathname = new URL(request.url, "http://localhost").pathname.replace(/\/$/, "") || "/home";
        const documentPath = routeDocuments[pathname];
        if (!documentPath) return next();
        try {
          response.statusCode = 200;
          response.setHeader("Content-Type", "text/html; charset=utf-8");
          response.end(await readFile(resolve(documentPath), "utf8"));
        } catch (error) {
          next(error);
        }
      });
    }
  }]
});
