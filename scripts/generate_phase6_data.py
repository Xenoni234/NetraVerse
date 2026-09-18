"""Generate safe, deterministic Phase 6 canonical episodes.

This creates state/flow artifacts only. It never executes or replays attacks.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.data.synthetic import EpisodeSpec, STAGE_BY_SCENARIO, generate_dataset, write_bundle


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("data/interim/phase6_synthetic"))
    parser.add_argument("--episodes-per-scenario", type=int, default=4)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--entities", type=int, default=2)
    parser.add_argument("--warmup-windows", type=int, default=40)
    parser.add_argument("--preparation-windows", type=int, default=10)
    parser.add_argument("--attack-windows", type=int, default=24)
    parser.add_argument("--recovery-windows", type=int, default=30)
    args = parser.parse_args(argv)
    if args.episodes_per_scenario < 1 or args.entities < 1:
        parser.error("episodes-per-scenario and entities must be positive")
    specs = [EpisodeSpec(scenario=scenario, seed=args.seed + i,
                         entity_count=args.entities, warmup_windows=args.warmup_windows,
                         preparation_windows=args.preparation_windows,
                         attack_windows=args.attack_windows, recovery_windows=args.recovery_windows)
             for i, scenario in enumerate(STAGE_BY_SCENARIO)
             for _ in range(args.episodes_per_scenario)]
    # Offset repeated scenarios deterministically so episodes do not duplicate.
    specs = [EpisodeSpec(**{**spec.__dict__, "seed": args.seed + i})
             for i, spec in enumerate(specs)]
    frame = generate_dataset(specs)
    paths = write_bundle(frame, args.output, specs)
    print(f"[phase6] generated {len(frame):,} windows from {len(specs)} episodes")
    for name, path in paths.items():
        print(f"[phase6] {name}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
