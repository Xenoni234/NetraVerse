/*
 * NetraVerse shell wiring (shared across all 8 routes).
 * - loads the shared design system (app-shell.css)
 * - marks the active sidebar item from the real URL
 * - ticks a live IST clock in the header (no fabricated timestamp)
 * The page content itself is rendered by api.js from the live backend.
 */
(() => {
  const shellStyles = document.createElement("link");
  shellStyles.rel = "stylesheet";
  shellStyles.href = "/app-shell.css";
  document.head.appendChild(shellStyles);

  const routes = ["home", "simulate", "forecast", "attack", "investigate", "network", "validate", "model", "live"];
  const titles = { home: "Home", simulate: "Simulate", forecast: "Forecast", attack: "ATT&CK",
    investigate: "Investigate", network: "Network", validate: "Validate", model: "Model", live: "Live" };

  const current = (() => {
    const seg = window.location.pathname.split("/").filter(Boolean)[0];
    return routes.includes(seg) ? seg : "home";
  })();
  document.body.dataset.route = current;
  document.title = `${titles[current]} · NetraVerse`;

  // Active sidebar item, derived from the URL (app-shell.css styles [aria-current]).
  document.querySelectorAll("aside nav a").forEach((link) => {
    const seg = (link.getAttribute("href") || "").split("/").filter(Boolean)[0];
    if (seg === current) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });

  // Live IST clock in the header context bar (Asia/Kolkata, no fabricated timestamp).
  const clock = document.getElementById("nv-ctx-clock");
  if (clock) {
    const tick = () => {
      clock.textContent = new Date().toLocaleTimeString("en-GB", {
        timeZone: "Asia/Kolkata", hour12: false,
      }) + " IST";
    };
    tick(); setInterval(tick, 1000);
  }
})();
