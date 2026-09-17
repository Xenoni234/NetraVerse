import { cp, mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const pages = {
  home: "Home",
  simulate: "Simulate",
  forecast: "Forecast",
  attack: "AttackTrajectory",
  investigate: "Investigate",
  network: "Network",
  validate: "Validate",
  model: "Model"
};

await Promise.all(Object.entries(pages).map(async ([route, source]) => {
  const destination = resolve("dist", route);
  await mkdir(destination, { recursive: true });
  await cp(resolve("src/pages", source, "index.html"), resolve(destination, "index.html"));
}));
