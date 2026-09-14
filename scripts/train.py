"""CLI training entry point.

Usage::

    python scripts/train.py --config configs/dev.yaml
    python scripts/train.py --config configs/train.yaml
    python scripts/train.py --config configs/train.yaml training.lr=3e-4 model.hidden_size=128
    python scripts/train.py --config configs/dev.yaml --overfit-one-batch

Trailing ``key=value`` arguments are OmegaConf dotlist overrides, so any config
key can be changed without editing the YAML — and the exact command line is then
a complete record of what was run.

What it does
------------
1. Load and merge the config (YAML + CLI overrides), then print the resolved one.
2. Seed everything.
3. Build or load the windowed feature cache.
4. Split per the LOCKED policy and **assert no leakage** before training.
5. Fit the scaler on train only.
6. Train with :func:`src.training.train_loop.train`.
7. Save a self-sufficient checkpoint, plus the resolved config next to it.

Always run ``--overfit-one-batch`` before a long job. If the model cannot drive a
single batch to near-zero loss, the bug is in the model, not the data, and an
hour of training will not find it.

TODO
----
* [ ] Implement ``parse_args`` (config path, overrides, flags).
* [ ] Implement ``load_config`` — OmegaConf merge, resolve, validate.
* [ ] Implement ``build_dataloaders`` (cache -> split -> scale -> Dataset).
* [ ] Implement ``main`` end to end.
* [ ] Print the resolved config and the split summary before training starts.
* [ ] Save the resolved config next to the checkpoint for provenance.
* [ ] Fail fast with a clear message when the feature cache is missing, and name
      the ``extract_features.py`` command that would build it.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Mapping, Sequence


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments.

    Returns a namespace with ``config`` (Path), ``overrides`` (dotlist strings),
    ``resume`` (Path | None), ``overfit_one_batch`` (bool) and ``dry_run`` (bool).
    """
    raise NotImplementedError("TODO: argparse with a trailing nargs='*' for overrides")


def load_config(config_path: Path, overrides: Sequence[str] = ()) -> Mapping[str, Any]:
    """Load a YAML config and apply dotlist overrides.

    Validates that the LOCKED blocks (``windowing``, ``labelling``) match the
    values in DESIGN.md, and warns loudly if they do not — a silently altered
    window length invalidates every comparison against previous runs.
    """
    raise NotImplementedError("TODO: OmegaConf.load + merge(from_dotlist) + LOCKED validation")


def build_dataloaders(config: Mapping[str, Any]) -> tuple[Any, Any, dict[str, Any]]:
    """Build train and val loaders plus the train-fit scaler state.

    Returns:
        ``(train_loader, val_loader, scaler_state)``.

    Raises:
        FileNotFoundError: when the feature cache is missing, with the exact
            ``extract_features.py`` command that would create it.
    """
    raise NotImplementedError("TODO: load cache, split, assert_no_leakage, fit scaler, wrap")


def main(argv: Sequence[str] | None = None) -> int:
    """Run a training job. Returns a process exit code."""
    raise NotImplementedError("TODO: parse, load config, build data, train, checkpoint")


if __name__ == "__main__":
    raise SystemExit(main())
