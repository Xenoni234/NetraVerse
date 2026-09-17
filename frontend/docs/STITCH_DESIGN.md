---
name: Predictive Tactical Intelligence
colors:
  surface: '#faf8ff'
  surface-dim: '#d2d9f4'
  surface-bright: '#faf8ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f2f3ff'
  surface-container: '#eaedff'
  surface-container-high: '#e2e7ff'
  surface-container-highest: '#dae2fd'
  on-surface: '#131b2e'
  on-surface-variant: '#3f4850'
  inverse-surface: '#283044'
  inverse-on-surface: '#eef0ff'
  outline: '#707881'
  outline-variant: '#bfc7d2'
  surface-tint: '#006398'
  primary: '#006194'
  on-primary: '#ffffff'
  primary-container: '#007bb9'
  on-primary-container: '#fdfcff'
  inverse-primary: '#93ccff'
  secondary: '#006a61'
  on-secondary: '#ffffff'
  secondary-container: '#86f2e4'
  on-secondary-container: '#006f66'
  tertiary: '#8d4b00'
  on-tertiary: '#ffffff'
  tertiary-container: '#b15f00'
  on-tertiary-container: '#fffbff'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#cce5ff'
  primary-fixed-dim: '#93ccff'
  on-primary-fixed: '#001d31'
  on-primary-fixed-variant: '#004b73'
  secondary-fixed: '#89f5e7'
  secondary-fixed-dim: '#6bd8cb'
  on-secondary-fixed: '#00201d'
  on-secondary-fixed-variant: '#005049'
  tertiary-fixed: '#ffdcc3'
  tertiary-fixed-dim: '#ffb77d'
  on-tertiary-fixed: '#2f1500'
  on-tertiary-fixed-variant: '#6e3900'
  background: '#faf8ff'
  on-background: '#131b2e'
  surface-variant: '#dae2fd'
typography:
  headline-xl:
    fontFamily: IBM Plex Sans
    fontSize: 2rem
    fontWeight: '600'
    lineHeight: 2.5rem
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: IBM Plex Sans
    fontSize: 1.5rem
    fontWeight: '600'
    lineHeight: 2rem
    letterSpacing: -0.015em
  headline-md:
    fontFamily: IBM Plex Sans
    fontSize: 1.25rem
    fontWeight: '600'
    lineHeight: 1.75rem
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: IBM Plex Sans
    fontSize: 1.125rem
    fontWeight: '500'
    lineHeight: 1.5rem
    letterSpacing: 0em
  body-lg:
    fontFamily: IBM Plex Sans
    fontSize: 1rem
    fontWeight: '400'
    lineHeight: 1.5rem
    letterSpacing: 0em
  body-md:
    fontFamily: IBM Plex Sans
    fontSize: 0.875rem
    fontWeight: '400'
    lineHeight: 1.25rem
    letterSpacing: 0.005em
  body-sm:
    fontFamily: IBM Plex Sans
    fontSize: 0.75rem
    fontWeight: '400'
    lineHeight: 1rem
    letterSpacing: 0.01em
  label-md:
    fontFamily: IBM Plex Sans
    fontSize: 0.8125rem
    fontWeight: '500'
    lineHeight: 1.125rem
    letterSpacing: 0.01em
  label-sm:
    fontFamily: IBM Plex Sans
    fontSize: 0.6875rem
    fontWeight: '600'
    lineHeight: 0.875rem
    letterSpacing: 0.04em
  code-lg:
    fontFamily: JetBrains Mono
    fontSize: 0.9375rem
    fontWeight: '500'
    lineHeight: 1.375rem
    letterSpacing: -0.01em
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 0.8125rem
    fontWeight: '400'
    lineHeight: 1.125rem
    letterSpacing: 0em
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 0.6875rem
    fontWeight: '400'
    lineHeight: 0.875rem
    letterSpacing: 0.01em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  margin: 1.5rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1.25rem
  space-xl: 2rem
---

## Brand & Style

This design system serves high-stakes operational cyber intelligence, predictive defense telemetry, and institutional threat forecasting. The interface must communicate unyielding precision, institutional authority, and scientific calm. 

The aesthetic is grounded in a rigorous, high-density analytical style. It completely rejects decorative gradients, blurred glassmorphism, luminous neon highlights, and casual ornamentation. Surfaces are light, planar, and disciplined, prioritizing optical legibility, structured scannability, and cognitive clarity during prolonged operational shifts. 

The emotional tone is objective, clinical, and reassuringly stable. Visual weight is communicated strictly through structural hairline boundaries, meticulous typography, and intentional semantic color application. Every layout artifact is functional; every token exists to support threat analysis, timeline projection, and systematic network attribution.

## Colors

The palette employs a restrained, light-mode clinical hierarchy designed for high visual endurance under institutional monitoring conditions.

### Canvas & Surface Hierarchy
- **Base Canvas (`#f8fafc`)**: Neutral slate wash providing an eye-resting substrate across full-screen dashboards.
- **Surface Panels (`#ffffff`)**: Pure optical white cards and analytical matrices, delineated by crisp neutral hairline rules (`#e2e8f0`).
- **Sub-surfaces (`#f1f5f9`)**: Subtle structural fills for table headers, inactive controls, and technical readout containers.

### Typography Shades
- **Primary Ink (`#0f172a`)**: Deep charcoal slate for critical metrics, primary labels, and data points.
- **Secondary Ink (`#475569`)**: Balanced mid-tone slate for supporting contextual labels, headers, and metadata.
- **Tertiary / Muted (`#64748b`)**: Low-distraction tone reserved strictly for units, table borders, inactive pagination, and breadcrumbs.

### Analytical & Telemetry Accents
- **Primary Accent (`#0284c7`)**: Analytical blue for predictive curves, forecast trajectories, baseline data selections, and focal focus targets.
- **Secondary Accent (`#0d9488`)**: Deep teal for confirmed historical baselines, telemetry status, and validated telemetry channels.

### Semantic Triage & Risk States
- **Benign / Nominal (`#16a34a`)**: Controlled emerald green for normal protocol flow, verified nodes, and nominal network baseline behavior.
- **Elevated Risk / Advisory (`#d97706`)**: Grounded amber for confidence variance, anomalous port access, and elevated vector potential.
- **Critical / High Threat (`#dc2626`)**: Restrained crimson red strictly reserved for high-probability threat execution, attack vectors, and active compromise indicators.
- Semantic fills must rely on a 10% tinted surface (`#fef2f2`, `#fffbeb`, `#f0fdf4`) paired with an authoritative 1px solid semantic border, entirely eschewing saturated flood fills or glowing outer blurs.

## Typography

The type system is strictly split by role to ensure zero ambiguity between human-readable administrative text and raw machine telemetry:

- **Interface & Analytical Headings**: `IBM Plex Sans` delivers an engineered, no-nonsense humanist clarity. Numbers within Plex Sans must feature tabular figures (`tnum`) in complex comparison grids.
- **Machine State, Telemetry, and Mathematical Variables**: `JetBrains Mono` or equivalent tabular monospaced structures handle IP addresses, CIDR blocks, port ranges, hex offsets, cryptographic hashes, UNIX timestamps, and state equations ($S_t$, $\Delta t$, $P(A|B)$).
- **Letter Spacing**: Headings feature subtle tracking contraction (`-0.02em` to `-0.01em`) to tighten horizontal line-scan efficiency. Micro-labels and system tags utilize positive tracking (`+0.04em`) and uppercase styling for instantaneous identification across dense multi-monitor spreads.

## Layout & Spacing

This layout architecture prioritizes high data density and modular multi-pane monitoring. 

### Grid Philosophy
- **Fluid Structural Grid**: The application framework operates on a 12-column or 24-column layout matrix across full widescreen operations dashboards (1920px+). Content panes stretch edge-to-edge within a global 24px outer margin.
- **Docked Multi-Split Viewports**: Data flows through tiled analytical quadrants. Split-panes use an immutable 1px border separation (`#e2e8f0`) rather than wide gutters, maximizing usable telemetry surface.
- **Component Padding Scale**: Compact baseline increments. `space-xs` (4px) for metric offsets, `space-sm` (8px) for tabular cell padding and chip internals, `space-md` (12px) for control cluster gaps, and `space-lg` (20px) for inner card enclosures.

### Responsive Breakpoints
- **Desktop Primary (1440px - 2560px)**: Persistent collapsible technical navigation rails (width: 240px or 64px collapsed), dual-timeline projection canvases, side-by-side node triage.
- **Standard Workstation (1024px - 1439px)**: Split-pane transforms to stacked 12-column cards; sub-metrics switch from horizontal stat strips to tabular rows.
- **Compact / Field Viewport (<1024px)**: Single column reflow with scroll-locked lateral data matrices for tabular metrics.

## Elevation & Depth

Visual hierarchy in this design system is established entirely through planar separation and low-contrast hairline outlines. 

- **Surface Levels**: Zero drop shadows are permitted on standard operational states. Elevation is signaled purely by surface color changes: Level 0 Canvas (`#f8fafc`) $\to$ Level 1 Panel (`#ffffff`) $\to$ Level 2 Active Header/Inset Well (`#f1f5f9`).
- **Hairline Outlines**: Every functional element, container, split panel, and analytical card is anchored by a 1px solid border (`#e2e8f0`). When a card or input achieves focus or triage priority, the border transitions cleanly to the primary analytical blue (`#0284c7`) without blur or ring offset expansions.
- **Floating Modals and Overlays**: When spatial overlay is mandatory (e.g., node drill-down flyouts or raw packet inspectors), use a clinical, ultra-restrained shadow: `0 1px 3px 0 rgba(15, 23, 42, 0.08), 0 1px 2px -1px rgba(15, 23, 42, 0.04)`. Ambient diffusion must never exceed 8px radius.

## Shapes

The design system adheres to a sharp, structural, low-radius geometric language (Option 1: Soft).

- **Corner Geometry**: The standard base border radius across buttons, data inputs, operational badges, and cards is strictly `0.25rem` (4px). Containers exceeding 400px may scale up to `0.375rem` (6px) maximum.
- **Functional Form Factor**: Rounding elements to circles or pill shapes is prohibited except for small binary live status indicators (a 6px solid dot). High radiuses dilute the scientific, institutional posture of the tool.

## Components

### Buttons & Trigger Controls
- **Primary Operational Action**: Solid `#0284c7` background, pure `#ffffff` text, 4px corner radius, 1px border (`#0369a1`). Hover state darkens slightly to `#0369a1`. Active state: `#075985`. No transition latency or glowing effects.
- **Secondary Action**: Solid `#ffffff` background, `#0f172a` text, 1px hairline border (`#cbd5e1`). Hover state transitions to `#f8fafc`.
- **Destructive Action (Mitigation/Isolate)**: Crisp white background, `#dc2626` text, 1px border (`#fca5a5`). Hover shifts background to `#fef2f2`.

### Inputs & Filters
- **Text & IP Search Fields**: Pure white background (`#ffffff`), 1px border (`#cbd5e1`), mono typography for network criteria, 32px height standard for high information density. Focus state shifts border directly to `#0284c7` with zero box-shadow spread.
- **Selection Dropdowns**: Fixed height, hairline rule, tabular numbers enabled, explicit text labels rather than abstract iconography.

### Status Badges & Telemetry Chips
- Badges never use rounded-pill layouts. They are compact rectangles (height: 20px) with 2px corner radiuses and monospaced uppercase labels (`label-sm`).
- **Nominal State**: `#f0fdf4` fill, `#16a34a` text, 1px `#bbf7d0` perimeter border.
- **Elevated State**: `#fffbeb` fill, `#b45309` text, 1px `#fde68a` perimeter border.
- **High Risk State**: `#fef2f2` fill, `#dc2626` text, 1px `#fecaca` perimeter border.

### Analytical Cards & Forecasting Panels
- Cards feature an invariant `#ffffff` background and 1px `#e2e8f0` structural enclosure.
- Panel headers are separated by an explicit 1px bottom divider, housing the section title (`headline-sm`), monospaced time range or projection horizon ($\Delta t = +4\text{h}$), and state controls.

### Tabular Telemetry Matrices
- Row heights are compacted to 36px.
- Table headers use `#f8fafc` background with uppercase 11px IBM Plex Sans text (`#475569`).
- Borders are continuous 1px `#e2e8f0` horizontal dividers. Alternating zebra row striping is disallowed; hover highlighting utilizes a crisp `#f1f5f9` fill across the target row.
- Numerical, IP, timestamp, and score columns are rigorously right-aligned using `JetBrains Mono`.

### Specialized Domain Components
- **Mathematical State Indicators ($S_t$)**: Inline badges showing current probabilistic state, featuring math notation alongside confidence intervals (e.g., `S_t [0.892 CI: 95%]`).
- **Forecasting Timeline Scrubbers**: Flat 1px rail with precise vertical tick marks indicating historical boundary versus forecast window, strictly differentiated by solid line versus dashed line styles.