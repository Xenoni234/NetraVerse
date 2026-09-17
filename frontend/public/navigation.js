(() => {
  const shellStyles = document.createElement("link");
  shellStyles.rel = "stylesheet";
  shellStyles.href = "/app-shell.css";
  document.head.appendChild(shellStyles);

  const pages = Object.fromEntries([
    "home", "simulate", "forecast", "attack", "investigate", "network", "validate", "model"
  ].map((route) => [route, `/${route}`]));
  const routeAliases = { "att-ck": "attack" };
  const routeFor = (route) => routeAliases[route] || route;
  const current = currentRoute();
  document.body.dataset.route = current;
  const linkTo = (control, route) => {
    control.href = pages[route];
    control.removeAttribute("target");
  };

  // Some Stitch exports omit data-path attributes. The first eight sidebar
  // links are consistently the eight product screens, so normalize them here.
  const sidebarRoutes = ["home", "simulate", "forecast", "attack", "investigate", "network", "validate", "model"];
  document.querySelectorAll("aside nav").forEach((nav) => {
    const links = [...nav.querySelectorAll("a")].slice(0, 8);
    const activeTemplate = links.find((link) => link.hasAttribute("aria-current"))?.className;
    const inactiveTemplate = links.find((link) => !link.hasAttribute("aria-current"))?.className;
    links.forEach((link, index) => {
      link.dataset.path = sidebarRoutes[index];
      const active = link.dataset.path === current;
      link.toggleAttribute("aria-current", active);
      if (active && activeTemplate) link.className = activeTemplate;
      if (!active && inactiveTemplate) link.className = inactiveTemplate;
    });
  });
  document.querySelectorAll("a[data-path]").forEach((link) => linkTo(link, routeFor(link.dataset.path)));

  const routeByLabel = [
    [/run simulation|back to simulation/i, "simulate"],
    [/explore forecast|view forecast|back to forecast/i, "forecast"],
    [/back to att|attack trajectory/i, "attack"],
    [/investigate supporting evidence/i, "investigate"],
    [/network evidence/i, "network"],
    [/back to validation/i, "validate"]
  ];
  document.querySelectorAll("a, button").forEach((control) => {
    const match = routeByLabel.find(([pattern]) => pattern.test(control.textContent));
    if (!match) return;
    if (control.tagName === "A") linkTo(control, match[1]);
    else {
      control.type = control.type || "button";
      control.addEventListener("click", () => { window.location.assign(pages[match[1]]); });
    }
  });

  // Keep route behavior real even where an export used placeholder hashes.
  document.querySelectorAll('a[href="#"]').forEach((link) => {
    const match = routeByLabel.find(([pattern]) => pattern.test(link.textContent));
    if (match) linkTo(link, match[1]);
    else link.removeAttribute("href");
  });

  // The user-facing product name is NetraVerse; retain the Stitch page content.
  document.querySelectorAll("body *").forEach((element) => {
    if (element.children.length === 0 && element.textContent.trim() === "NAF-CONSOLE") element.textContent = "NetraVerse";
    if (element.children.length === 0) {
      element.textContent = element.textContent
        .replaceAll("Â·", "·")
        .replaceAll("â†’", "→")
        .replaceAll("â‰¥", "≥")
        .replaceAll("â€“", "–")
        .replaceAll("â€”", "—");
    }
  });

  const titles = {
    home: "Home", simulate: "Simulate", forecast: "Forecast", attack: "ATT&CK",
    investigate: "Investigate", network: "Network", validate: "Validate", model: "Model"
  };
  document.title = `${titles[currentRoute()] || "Network Attack Forecasting"} · NetraVerse`;

  function currentRoute() {
    const route = window.location.pathname.split("/").filter(Boolean)[0];
    return pages[route] ? route : Object.entries(pages).find(([, href]) => href === window.location.pathname)?.[0] || "home";
  }

  // Replace any hardcoded header clock ("2024-10-24 14:32:10 UTC", "SYNC: 14:22:08 UTC",
  // "10:30:00 UTC") with the real current time, ticking live. No fabricated timestamps.
  (function liveClock() {
    const clockRe = /(SYNC:\s*)?\d{2,4}[-:]\d{2}([-:]\d{2})?([ T]\d{2}:\d{2}:\d{2})?\s*UTC/;
    const targets = [];
    document.querySelectorAll("span,div,time").forEach((el) => {
      if (el.children.length === 0 && clockRe.test(el.textContent.trim())) {
        targets.push({ el, prefix: /^SYNC:/.test(el.textContent.trim()) ? "SYNC: " : "" });
      }
    });
    if (!targets.length) return;
    const tick = () => {
      const s = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
      targets.forEach((t) => { t.el.textContent = t.prefix + s; });
    };
    tick(); setInterval(tick, 1000);
  })();
})();
