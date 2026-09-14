"""Training layer: the loop, the scheduled-sampling schedule, and checkpointing.

``train_loop``          epoch loop, validation, early stopping, logging
``scheduled_sampling``  the teacher-forcing -> free-running ramp
``checkpointing``       save/load of weights *and* the scaler state

One rule worth stating up front: a checkpoint must be **self-sufficient**. It
carries the model config, the fitted scaler state, the class weights and the
selected decision threshold, so that ``scripts/evaluate.py`` and the demo can
reproduce a prediction exactly without re-reading the training config. Anything
less has, historically, been the source of "it scored 0.8 in training and 0.4 in
the demo".
"""

from __future__ import annotations

__all__ = ["train_loop", "scheduled_sampling", "checkpointing"]
