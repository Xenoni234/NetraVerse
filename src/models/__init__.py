"""Model zoo: two baselines that must be beaten, plus the world model itself.

``baseline_persistence``  "the next window looks like this one" — the null model
``baseline_lr``           logistic regression on the flattened L x F history
``lstm_encoder_decoder``  the world model: LSTM encoder -> decoder -> three heads
``heads``                 state / risk / stage output heads
``losses``                the combined multitask objective

Device policy (applies to every model here): construct on CPU, move with
``.to(device)``, and pick the device via :func:`src.models.get_device` which
returns CUDA when available and CPU otherwise. Nothing in this package may
assume a GPU exists.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # keep the import cheap for non-torch consumers
    import torch

__all__ = [
    "baseline_persistence",
    "baseline_lr",
    "lstm_encoder_decoder",
    "heads",
    "losses",
    "get_device",
]


def get_device(preference: str = "auto") -> "torch.device":
    """Resolve the config's ``device`` key into a concrete ``torch.device``.

    Args:
        preference: ``"auto"`` (CUDA if available, else CPU), ``"cpu"``, or
            ``"cuda"``. An explicit ``"cuda"`` on a machine without CUDA logs a
            warning and falls back to CPU rather than raising — the demo must
            never die on a judge's laptop.

    TODO
    ----
    * [ ] Implement, including the ``torch.backends.mps`` case for Apple laptops.
    * [ ] Log the resolved device once at startup.
    """
    import logging

    import torch

    log = logging.getLogger(__name__)
    pref = (preference or "auto").lower()
    if pref == "cpu":
        return torch.device("cpu")
    if pref == "cuda":
        if torch.cuda.is_available():
            return torch.device("cuda")
        log.warning("device='cuda' requested but CUDA is unavailable; falling back to CPU")
        return torch.device("cpu")
    # auto
    if torch.cuda.is_available():
        return torch.device("cuda")
    if getattr(torch.backends, "mps", None) is not None and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")
