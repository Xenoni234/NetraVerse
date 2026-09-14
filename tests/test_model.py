"""Tests for the world model: shapes, device portability, and learning capacity.

These tests do not check that the model is *accurate* — that is the eval
harness's job. They check that it is *correct*: right shapes, no future leakage
inside the decoder, identical behaviour on CPU and GPU, dropout that actually
toggles, and enough capacity to overfit a single batch.

The overfit-one-batch test is the most valuable one here. A model that cannot
drive one batch's loss to near zero has a real bug — wrong loss reduction,
detached gradients, a frozen parameter — and no amount of training will fix it.
Catching that in ten seconds instead of two hours is the entire point.

Every test must pass on CPU. GPU tests are skipped when CUDA is absent.

TODO
----
* [ ] Implement the fixtures (tiny config, random batch).
* [ ] Implement the shape tests for every head and horizon.
* [ ] Implement the CPU/GPU parity test.
* [ ] Implement the teacher-forcing / free-running behaviour tests.
* [ ] Implement the MC-dropout toggle test.
* [ ] Implement overfit-one-batch. Do this one first.
* [ ] Implement the checkpoint round-trip test.
* [ ] Add a gradient-flow test: every trainable parameter gets a non-None grad.
"""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch", reason="PyTorch is required for model tests")


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def tiny_config():
    """A deliberately small model config, so tests run in seconds on CPU."""
    raise NotImplementedError("TODO: WorldModelConfig(hidden_size=16, num_layers=1, ...)")


@pytest.fixture
def batch():
    """A random batch matching the LOCKED shapes: B=4, L=10, F=32, K=(1,2,4)."""
    raise NotImplementedError("TODO: seeded random x, y_state, y_risk, y_stage")


# --------------------------------------------------------------------------- #
# Shapes
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: model not implemented")
def test_forward_output_shapes(tiny_config, batch) -> None:
    """Forward returns state, risk and stage tensors of the documented shapes."""
    raise NotImplementedError("TODO: assert (B,K,F) / (B,K) / (B,K,n_stages)")


@pytest.mark.skip(reason="scaffold: model not implemented")
def test_select_horizons_indexes_correctly(tiny_config, batch) -> None:
    """``select_horizons`` maps horizon ``k`` to decoder step ``k-1``.

    An off-by-one here would report k=2 numbers under the k=1 heading — plausible
    and completely wrong.
    """
    raise NotImplementedError("TODO: compare sliced outputs against manual indexing")


@pytest.mark.skip(reason="scaffold: model not implemented")
def test_rollout_length(tiny_config, batch) -> None:
    """``rollout(n_steps=k)`` returns exactly ``k`` steps."""
    raise NotImplementedError("TODO: assert the step dimension for several k")


@pytest.mark.skip(reason="scaffold: model not implemented")
def test_input_size_matches_locked_schema(tiny_config) -> None:
    """The model's input width equals ``unified_schema.N_FEATURES``."""
    raise NotImplementedError("TODO: assert config.input_size == N_FEATURES")


# --------------------------------------------------------------------------- #
# Device portability
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: model not implemented")
def test_runs_on_cpu(tiny_config, batch) -> None:
    """The model works on CPU. Non-negotiable: the demo may have no GPU."""
    raise NotImplementedError("TODO: build on cpu, forward, assert finite outputs")


@pytest.mark.skip(reason="scaffold: model not implemented")
def test_get_device_falls_back_to_cpu() -> None:
    """``get_device('cuda')`` on a CUDA-less machine warns and returns CPU."""
    raise NotImplementedError("TODO: assert the fallback rather than an exception")


@pytest.mark.skipif(not torch.cuda.is_available(), reason="CUDA not available")
@pytest.mark.skip(reason="scaffold: model not implemented")
def test_cpu_gpu_parity(tiny_config, batch) -> None:
    """CPU and GPU produce the same outputs within float tolerance."""
    raise NotImplementedError("TODO: same seed and weights on both, allclose with atol=1e-4")


# --------------------------------------------------------------------------- #
# Behaviour
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: model not implemented")
def test_teacher_forcing_changes_output(tiny_config, batch) -> None:
    """Teacher forcing at ratio 0 vs 1 produces different predictions.

    If they are identical, the scheduled-sampling plumbing is not wired in and
    the ramp is decorative.
    """
    raise NotImplementedError("TODO: forward at both ratios, assert not allclose")


@pytest.mark.skip(reason="scaffold: model not implemented")
def test_eval_mode_ignores_targets(tiny_config, batch) -> None:
    """In ``eval()``, passing targets changes nothing — no accidental leakage."""
    raise NotImplementedError("TODO: eval forward with and without targets, assert equal")


@pytest.mark.skip(reason="scaffold: model not implemented")
def test_history_only_affects_prediction(tiny_config, batch) -> None:
    """Changing a target does not change a free-running prediction.

    The model-level counterpart of the windowing leakage tests.
    """
    raise NotImplementedError("TODO: perturb targets, rollout, assert identical output")


@pytest.mark.skip(reason="scaffold: model not implemented")
def test_mc_dropout_toggles(tiny_config, batch) -> None:
    """``enable_mc_dropout`` makes repeated eval passes differ; plain eval does not."""
    raise NotImplementedError("TODO: two passes each way, assert varies only with MC enabled")


# --------------------------------------------------------------------------- #
# Learning capacity
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: model not implemented")
def test_overfit_one_batch(tiny_config, batch) -> None:
    """The model drives a single batch's loss to near zero.

    The highest-value test in this file. Failure means a real bug — wrong loss
    reduction, detached gradients, a frozen parameter — not a tuning problem.
    """
    raise NotImplementedError("TODO: 200 steps on one batch, assert final loss < 0.01")


@pytest.mark.skip(reason="scaffold: model not implemented")
def test_all_parameters_receive_gradients(tiny_config, batch) -> None:
    """Every trainable parameter has a non-None, non-zero gradient after backward.

    Catches a head that is never used and a layer accidentally detached.
    """
    raise NotImplementedError("TODO: backward once, iterate named_parameters, assert grads")


@pytest.mark.skip(reason="scaffold: losses not implemented")
def test_loss_is_finite_on_first_batch(tiny_config, batch) -> None:
    """The combined loss is finite on the very first batch.

    A NaN here nearly always means an unscaled or NaN feature reached the model.
    """
    raise NotImplementedError("TODO: compute MultiTaskLoss, assert torch.isfinite")


@pytest.mark.skip(reason="scaffold: losses not implemented")
def test_loss_weights_are_applied(tiny_config, batch) -> None:
    """Changing a loss weight changes the total by the expected proportion."""
    raise NotImplementedError("TODO: compute at two weight settings, check the arithmetic")


# --------------------------------------------------------------------------- #
# Checkpointing
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: checkpointing not implemented")
def test_checkpoint_round_trip(tmp_path, tiny_config, batch) -> None:
    """Save then load reproduces identical predictions."""
    raise NotImplementedError("TODO: save, load, forward both, assert allclose")


@pytest.mark.skip(reason="scaffold: checkpointing not implemented")
def test_checkpoint_carries_scaler_and_threshold(tmp_path, tiny_config) -> None:
    """The payload includes the scaler state and the chosen threshold.

    Without these, the demo silently preprocesses differently from training —
    historically the source of "0.8 in training, 0.4 in the demo".
    """
    raise NotImplementedError("TODO: save with both, load, assert present and equal")


@pytest.mark.skip(reason="scaffold: checkpointing not implemented")
def test_schema_version_mismatch_is_rejected(tmp_path, tiny_config) -> None:
    """Loading a checkpoint with a different schema version raises."""
    raise NotImplementedError("TODO: tamper with schema_version, assert it refuses to load")


@pytest.mark.skip(reason="scaffold: checkpointing not implemented")
def test_gpu_checkpoint_loads_on_cpu(tmp_path, tiny_config) -> None:
    """A GPU-saved checkpoint opens on a CPU-only machine.

    Simulate by saving with CUDA tensors where available; otherwise assert the
    loader passes ``map_location="cpu"``.
    """
    raise NotImplementedError("TODO: verify map_location handling")
