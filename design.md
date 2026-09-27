# Design Guidelines — NetraVerse

Governing principle: the dashboard should look like a tool a SOC analyst already trusts (Grafana / Datadog / Splunk-adjacent) — **not** like an AI-hackathon landing page. No neon, no purple, no glassmorphism, no glow.

---

## 1. What to avoid (explicitly banned)

- Neon colors of any kind (electric blue, neon green, hot pink).
- Purple/violet as a primary or accent color — the single most common "this is an AI demo" tell.
- Glassmorphism: frosted-glass panels, background blur, translucent cards with light borders.
- Glow/drop-shadow effects on buttons, cards, or text.
- Decorative gradients (gradient text, gradient buttons, gradient backgrounds used purely for visual flair).
- Overly rounded corners (pill-shaped buttons, 20px+ border radius on cards).
- Excessive animation/motion — no bouncing, pulsing, or particle effects.
- Stock "AI" iconography — glowing brains, circuit-board textures, robot mascots.

## 2. Color Palette

**Base (choose one mode, keep it consistent):**
- Light mode: off-white background (`#F7F7F5` / `#FAFAF9`), not pure white.
- Dark mode (recommended for a "security console" feel): graphite/slate background (`#14161A` / `#1B1E23`), not pure black.

**Structural colors:**
- Primary text: near-black (`#1A1A1A`) on light, or off-white (`#E6E6E6`) on dark.
- Secondary text/labels: mid-gray (`#6B7280`).
- Panel/card background: one step off the base (`#FFFFFF` on light / `#20242B` on dark), flat — no blur, minimal or no border-radius (2–4px max), thin 1px border (`#E5E7EB` light / `#2C313A` dark).

**Accent (pick ONE primary accent, used sparingly):**
- Amber/gold (`#C98A2C`–`#D9A441` range) or teal (`#2A7F7E`–`#3B9C9B` range) — either reads as "instrumentation," neither reads as "AI demo."
- Use the accent only for: active states, the primary CTA, and chart highlight lines. Do not tint entire panels with it.

**Semantic/status colors (for topology and alerts — kept desaturated, not neon):**
- Normal/benign: neutral gray (`#8A9098`).
- Elevated risk / attacker node: muted red-orange (`#C0472C`).
- Victim/targeted node: muted amber (`#C98A2C`).
- Safe/mitigated (post-action): muted green (`#4B8A5E`).

Keep all status colors desaturated (add gray) rather than saturated/bright — this alone is most of what separates "professional dashboard" from "AI demo."

## 3. Typography

- UI text / labels / body: a clean grotesk — **Inter** or **IBM Plex Sans**.
- Numeric/data displays (probabilities, IPs, ports, timestamps): a monospace font — **IBM Plex Mono** or **JetBrains Mono** — this is what makes it read as an analyst tool rather than a marketing page.
- Avoid decorative or rounded display fonts entirely.
- Font weights: mostly regular/medium; reserve bold for alerts and key numbers only.

## 4. Layout Principles

- Grid-based, information-dense but not cluttered — think "monitoring console," not "landing page with whitespace."
- Left or top nav bar for mode switching (CSV Upload / PCAP Upload / Live Monitor) — flat, no icons-only nav without labels.
- Main canvas split: topology graph + probability timeline as co-primary views (side-by-side or stacked, not one buried in a tab).
- Decision panel (Accept/Modify/Reject) appears as a docked panel or modal that doesn't obscure the timeline — the user should still see the curve while deciding.
- Consistent 8px spacing grid; align charts and cards to it.

## 5. Component-Specific Guidance

**Probability Timeline (Plotly line chart)**
- Single accent-colored line for the probability curve; MITRE stage transitions marked with small flat labels/ticks along the x-axis, not colored background bands.
- Alert threshold shown as a thin dashed neutral-gray horizontal line, not a glowing red zone.
- Forecast region (not-yet-reached time) can be shown slightly lower-opacity or dashed to distinguish "predicted" from "observed."

**Topology / Host Graph (Plotly network graph or a custom SVG)**
- Nodes: simple circles, flat fill, thin border. Size can encode traffic volume modestly — avoid huge disparities that make it look like a bubble-chart infographic.
- Edges: thin lines, thickness can encode flow volume; avoid animated "flowing dots" effects — a static or subtly-updating line is enough.
- Attacker node: muted red-orange fill + label. Victim node: muted amber fill + label. Normal hosts: neutral gray.
- Labels: IP address in monospace, small, always visible (not only on hover) for key nodes.

**Decision Panel (Accept / Modify / Reject)**
- Three flat buttons, equal visual weight except the recommended action can have a subtle accent-colored border (not a filled glowing button).
- Show the recommended action + one-line rationale (from the rule-engine) above the buttons; Ollama's fuller narration can sit below as secondary/expandable text, clearly a "details" affordance rather than the headline.
- "Modify" opens a small flat dropdown/list of alternative actions from the rule-engine — not a free-text field.

**Counterfactual Before/After**
- Simple two-bar or two-line comparison (before probability vs. projected after probability), labeled plainly with numbers, not a flashy delta animation.

## 6. Motion

- Only functional motion: the probability curve extending as the simulation plays, and topology updating as new flows appear.
- No transition animations for their own sake (no fade-bounce on panel open, no confetti on "risk reduced").

## 7. Streamlit-Specific Notes

- Override Streamlit's default theme via `dashboard/styles/theme.css` / `.streamlit/config.toml` — set `base`, `backgroundColor`, `secondaryBackgroundColor`, `textColor`, and `font` explicitly; do not ship Streamlit's default blue-accent look.
- Hide Streamlit's default hamburger menu / "Made with Streamlit" footer for a cleaner, less "prototype" feel during judging.
- Use `st.columns` for the topology/timeline side-by-side layout rather than tabs, so both are visible at once during the live decision moments.

## 8. One-Line Test

Before finalizing any screen, ask: *"If I removed the AI-specific labels, would this look like a screenshot from a real SOC vendor's product page (Splunk, Darktrace, Grafana)?"* If the honest answer is no, it's too decorative — pull back the color, glow, or motion until it is.
