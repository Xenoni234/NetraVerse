#!/usr/bin/env python3
"""Plot the NetraVerse SIH system architecture.

The diagram intentionally mirrors the implemented demo paths:

    labelled CSV / replay ─┐
                           ├─> shared windowing and SIH inference ─> API/UI
    server interface ──────┘
             └─ tcpdump -> CICFlowMeter -> rolling flow CSVs

Examples
--------
python scripts/plot_system_architecture.py
python scripts/plot_system_architecture.py --output docs/architecture/system.svg
"""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle


# Calm, presentation-friendly colours that also remain readable when printed.
NAVY = "#16324F"
BLUE = "#2F80B7"
TEAL = "#1B998B"
GREEN = "#4E9F70"
AMBER = "#C58A25"
PURPLE = "#8064A2"
RED = "#B84A4A"
INK = "#243447"
MUTED = "#66788A"
LIGHT_BLUE = "#EAF4FB"
LIGHT_TEAL = "#EAF8F5"
LIGHT_AMBER = "#FFF7E6"
LIGHT_PURPLE = "#F4EFF9"
LIGHT_GREY = "#F5F7FA"
WHITE = "#FFFFFF"


def add_box(
    ax,
    xy: tuple[float, float],
    width: float,
    height: float,
    title: str,
    body: str,
    *,
    face: str = WHITE,
    edge: str = NAVY,
    title_color: str = NAVY,
    body_color: str = INK,
    title_size: float = 10.0,
    body_size: float = 8.4,
    radius: float = 0.018,
) -> tuple[float, float, float, float]:
    """Add a rounded architecture node and return its bounds."""
    x, y = xy
    patch = FancyBboxPatch(
        (x, y),
        width,
        height,
        boxstyle=f"round,pad=0.012,rounding_size={radius}",
        linewidth=1.25,
        edgecolor=edge,
        facecolor=face,
        transform=ax.transAxes,
        clip_on=False,
    )
    ax.add_patch(patch)
    ax.text(
        x + 0.018,
        y + height - 0.034,
        title,
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=title_size,
        fontweight="bold",
        color=title_color,
    )
    ax.text(
        x + 0.018,
        y + height - 0.073,
        body,
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=body_size,
        color=body_color,
        linespacing=1.35,
    )
    return x, y, width, height


def center(bounds: tuple[float, float, float, float]) -> tuple[float, float]:
    x, y, width, height = bounds
    return x + width / 2, y + height / 2


def connect(
    ax,
    start: tuple[float, float],
    end: tuple[float, float],
    *,
    color: str = BLUE,
    style: str = "-",
    width: float = 1.5,
    label: str | None = None,
    label_offset: tuple[float, float] = (0.0, 0.0),
) -> None:
    arrow = FancyArrowPatch(
        start,
        end,
        arrowstyle="-|>",
        mutation_scale=12,
        linewidth=width,
        linestyle=style,
        color=color,
        connectionstyle="arc3,rad=0.0",
        transform=ax.transAxes,
        clip_on=False,
    )
    ax.add_patch(arrow)
    if label:
        x = (start[0] + end[0]) / 2 + label_offset[0]
        y = (start[1] + end[1]) / 2 + label_offset[1]
        ax.text(
            x,
            y,
            label,
            transform=ax.transAxes,
            ha="center",
            va="center",
            fontsize=7.2,
            color=MUTED,
            bbox={"facecolor": WHITE, "edgecolor": "none", "pad": 1.5},
        )


def add_section_label(ax, x: float, y: float, text: str, color: str) -> None:
    ax.text(
        x,
        y,
        text.upper(),
        transform=ax.transAxes,
        fontsize=8.2,
        fontweight="bold",
        color=color,
        ha="left",
        va="center",
        bbox={"facecolor": WHITE, "edgecolor": color, "linewidth": 0.8, "pad": 4},
    )


def build_figure() -> plt.Figure:
    fig, ax = plt.subplots(figsize=(16, 9), dpi=150)
    fig.patch.set_facecolor(WHITE)
    ax.set_facecolor(WHITE)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # Header.
    ax.text(
        0.04,
        0.955,
        "NETRAVERSE",
        transform=ax.transAxes,
        fontsize=11,
        fontweight="bold",
        color=BLUE,
        va="top",
        ha="left",
        fontfamily="DejaVu Sans",
    )
    ax.text(
        0.04,
        0.918,
        "AI-powered early forecasting of network attack progression",
        transform=ax.transAxes,
        fontsize=19,
        fontweight="bold",
        color=NAVY,
        va="top",
        ha="left",
    )
    ax.text(
        0.04,
        0.875,
        "One shared inference contract for labelled replay, uploads, and authorized live server monitoring",
        transform=ax.transAxes,
        fontsize=9.5,
        color=MUTED,
        va="top",
        ha="left",
    )
    ax.plot([0.04, 0.96], [0.845, 0.845], color="#D7E1EA", linewidth=1.0, transform=ax.transAxes)

    # Branch labels.
    add_section_label(ax, 0.055, 0.79, "A  labelled replay / upload", BLUE)
    add_section_label(ax, 0.055, 0.485, "B  authorized live capture", TEAL)
    add_section_label(ax, 0.405, 0.79, "shared temporal inference", PURPLE)
    add_section_label(ax, 0.735, 0.79, "analyst-facing outputs", RED)

    # Replay branch.
    replay_csv = add_box(
        ax,
        (0.055, 0.665),
        0.145,
        0.095,
        "Labelled CSV / replay",
        "Uploaded capture\nexisting dataset replay\ntrusted labels or intervals",
        face=LIGHT_BLUE,
        edge=BLUE,
    )
    replay_ingest = add_box(
        ax,
        (0.235, 0.665),
        0.145,
        0.095,
        "Replay ingestion",
        "schema mapping\nhost selection\ntimestamp ordering",
        face=LIGHT_BLUE,
        edge=BLUE,
    )

    # Live branch.
    server_iface = add_box(
        ax,
        (0.055, 0.355),
        0.145,
        0.095,
        "Owned server interface",
        "wlp0s20f3 / authorized\nnetwork telemetry\n30-second capture cadence",
        face=LIGHT_TEAL,
        edge=TEAL,
    )
    capture = add_box(
        ax,
        (0.235, 0.355),
        0.145,
        0.095,
        "Capture agent",
        "tcpdump PCAP chunks\nagent/capture.sh\nrolling flow directory",
        face=LIGHT_TEAL,
        edge=TEAL,
    )

    flowmeter = add_box(
        ax,
        (0.415, 0.355),
        0.145,
        0.095,
        "CICFlowMeter",
        "Java 8 + jnetpcap\nPCAP → flow CSV\nCIC-compatible features",
        face=LIGHT_AMBER,
        edge=AMBER,
        title_color="#805B00",
    )

    # Shared inference spine.
    windowing = add_box(
        ax,
        (0.415, 0.665),
        0.145,
        0.095,
        "Window builder",
        "30-second feature windows\nnormalization + host grouping\n10-window history",
        face=LIGHT_PURPLE,
        edge=PURPLE,
    )
    live_forecast = add_box(
        ax,
        (0.595, 0.355),
        0.145,
        0.095,
        "Live flow feed",
        "rolling *_Flow.csv files\nscripts/live_forecast.py\nserver calibration",
        face=LIGHT_TEAL,
        edge=TEAL,
    )
    checkpoint = add_box(
        ax,
        (0.595, 0.665),
        0.145,
        0.095,
        "SIH demo checkpoint",
        "temporal world model\nwm_sih_demo / wm_server\nCPU-compatible inference",
        face=LIGHT_PURPLE,
        edge=PURPLE,
    )

    outputs = add_box(
        ax,
        (0.775, 0.55),
        0.17,
        0.21,
        "Forecast outputs",
        "risk: +60s / +90s / +120s\nATT&CK stage forecast\nattention focus + uncertainty\nalert state + lead time",
        face="#FFF0F0",
        edge=RED,
        title_color=RED,
    )
    dashboard = add_box(
        ax,
        (0.775, 0.235),
        0.17,
        0.15,
        "API + dashboard",
        "replay graph / live page\nhoverable temporal nodes\nstage-linked decision support",
        face=LIGHT_GREY,
        edge=NAVY,
    )

    # Data edges.
    connect(ax, (replay_csv[0] + replay_csv[2], center(replay_csv)[1]), (replay_ingest[0], center(replay_ingest)[1]), color=BLUE)
    connect(ax, (replay_ingest[0] + replay_ingest[2], center(replay_ingest)[1]), (windowing[0], center(windowing)[1]), color=BLUE)
    connect(ax, (server_iface[0] + server_iface[2], center(server_iface)[1]), (capture[0], center(capture)[1]), color=TEAL)
    connect(ax, (capture[0] + capture[2], center(capture)[1]), (flowmeter[0], center(flowmeter)[1]), color=TEAL)
    connect(ax, (flowmeter[0] + flowmeter[2], center(flowmeter)[1]), (live_forecast[0], center(live_forecast)[1]), color=TEAL)
    connect(ax, (live_forecast[0] + live_forecast[2], center(live_forecast)[1]), (windowing[0] + windowing[2] * 0.5, windowing[1]), color=TEAL, label="same window contract", label_offset=(0.0, -0.025))
    connect(ax, (windowing[0] + windowing[2], center(windowing)[1]), (checkpoint[0], center(checkpoint)[1]), color=PURPLE)
    connect(ax, (checkpoint[0] + checkpoint[2], center(checkpoint)[1]), (outputs[0], center(outputs)[1]), color=RED, label="forecast", label_offset=(0.0, 0.018))
    connect(ax, (outputs[0] + outputs[2] * 0.5, outputs[1]), (dashboard[0] + dashboard[2] * 0.5, dashboard[1] + dashboard[3]), color=RED, label="API response", label_offset=(0.025, 0.0))

    # Causal replay and live polling are control paths, not data paths.
    connect(ax, (replay_ingest[0] + replay_ingest[2] * 0.5, replay_ingest[1]), (dashboard[0], dashboard[1] + dashboard[3] * 0.58), color=BLUE, style="--", width=1.1, label="causal replay state", label_offset=(-0.015, 0.02))
    connect(ax, (live_forecast[0] + live_forecast[2] * 0.5, live_forecast[1]), (dashboard[0], dashboard[1] + dashboard[3] * 0.34), color=TEAL, style="--", width=1.1, label="poll every 30s", label_offset=(0.0, -0.018))

    # Bottom explanatory strip.
    strip = Rectangle(
        (0.055, 0.075),
        0.89,
        0.085,
        transform=ax.transAxes,
        facecolor="#F8FAFC",
        edgecolor="#D7E1EA",
        linewidth=0.8,
    )
    ax.add_patch(strip)
    ax.text(
        0.075,
        0.128,
        "What the system demonstrates",
        transform=ax.transAxes,
        fontsize=8.5,
        fontweight="bold",
        color=NAVY,
        va="center",
        ha="left",
    )
    ax.text(
        0.075,
        0.098,
        "The two input modes produce the same temporal representation, so the same SIH checkpoint can forecast replayed captures and authorized live server behavior.",
        transform=ax.transAxes,
        fontsize=8.1,
        color=INK,
        va="center",
        ha="left",
    )
    ax.text(
        0.94,
        0.052,
        "Solid arrows = data flow    Dashed arrows = control/UI updates",
        transform=ax.transAxes,
        fontsize=7.2,
        color=MUTED,
        va="center",
        ha="right",
    )
    return fig


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/architecture/netraverse_system_architecture.png"),
        help="PNG, SVG, or PDF output path (default: %(default)s)",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Open the diagram interactively after saving it",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig = build_figure()
    fig.savefig(args.output, dpi=220, bbox_inches="tight", facecolor=WHITE)
    print(f"Saved architecture diagram to {args.output}")
    if args.show:
        plt.show()
    else:
        plt.close(fig)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
