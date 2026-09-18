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
  "/live": "src/pages/Live/index.html"
};

export default defineConfig({
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
