"""Offline model registry with atomic promotion and rollback."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


class ModelRegistry:
    """Filesystem registry for candidate/current/previous checkpoints."""

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    @property
    def current(self) -> Path:
        return self.root / "current.ckpt"

    @property
    def previous(self) -> Path:
        return self.root / "previous.ckpt"

    def promote(self, checkpoint: Path | str, *, metrics: dict | None = None) -> Path:
        source = Path(checkpoint)
        if not source.is_file():
            raise FileNotFoundError(source)
        staged = self.root / "candidate.ckpt"
        shutil.copy2(source, staged)
        if self.current.exists():
            shutil.copy2(self.current, self.previous)
        staged.replace(self.current)
        record = {"promoted_at": datetime.now(timezone.utc).isoformat(),
                  "checkpoint": str(source), "metrics": metrics or {}}
        (self.root / "promotion.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
        return self.current

    def rollback(self) -> Path:
        if not self.previous.exists():
            raise FileNotFoundError("No previous checkpoint is available for rollback")
        self.previous.replace(self.current)
        return self.current


__all__ = ["ModelRegistry"]
