import { pages } from "./data/demo-data.js";
const validRoutes = new Set(Object.keys(pages));

function routeFromLocation() {
  const route = window.location.pathname.split("/").filter(Boolean)[0] || "home";
  return validRoutes.has(route) ? route : "home";
}

function openPage() {
  const route = routeFromLocation();
  const page = pages[route];
  document.title = `${page.title} · NetraVerse`;
  window.location.replace(`/${route}`);
}
openPage();
