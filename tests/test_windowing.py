"""Tests for window construction, labelling and — above all — leakage.

**This is the most important test file in the project.** Every other kind of bug
makes the numbers worse. A leakage bug makes them *better*, which means nobody
goes looking for it, and the whole result is worthless.

The three leaks worth losing sleep over:

1. **Temporal leakage** — a feature at window `t` reading data from `t' > t`.
2. **Split leakage** — a test sample's 10-window history overlapping a training
   window (this is why the 14-window gap buffer exists).
3. **Label leakage** — `dist_to_attack` or a baseline computed across an entity
   or campaign boundary.

All tests run on synthetic windows with known, hand-checkable answers. Synthetic
data is the point: with real data you cannot tell a leak from a good model.

TODO
----
* [ ] Implement the synthetic window fixtures.
* [ ] Implement the window-parameter tests (LOCKED values).
* [ ] Implement the sequence-shape tests.
* [ ] Implement the boundary tests (no crossing entity or campaign).
* [ ] Implement the labelling tests, especially ``dist_to_attack``.
* [ ] Implement the leakage tests. Do these first if time is short.
* [ ] Add a property-based test (hypothesis) over random window counts.
"""

from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def synthetic_windows():
    """Hand-built windows with a known attack at a known time.

    Two entities across two campaigns, 40 windows each at a 10 s stride, with an
    attack starting at window 25 for entity A only. Every expected label in this
    file can be worked out by hand from that description.
    """
    raise NotImplementedError("TODO: construct a small, fully predictable frame")


@pytest.fixture
def ramping_windows():
    """One entity whose byte rate ramps linearly, for derivative tests."""
    raise NotImplementedError("TODO: linear ramp with a known constant derivative")


# --------------------------------------------------------------------------- #
# Window parameters — LOCKED
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: windowing not implemented")
def test_locked_window_parameters() -> None:
    """The LOCKED constants are what DESIGN.md section 3 says they are.

    Guards against a well-meaning tuning commit silently invalidating every
    previously reported number.
    """
    raise NotImplementedError("TODO: assert 30 / 10 / 10 / (1,2,4) / 14")


@pytest.mark.skip(reason="scaffold: windowing not implemented")
def test_window_span_and_stride(synthetic_windows) -> None:
    """Windows span 30 s and start every 10 s, so they overlap 3-deep."""
    raise NotImplementedError("TODO: assert window_end - window_start and the start diffs")


# --------------------------------------------------------------------------- #
# Sequence construction
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: windowing not implemented")
def test_sequence_shapes(synthetic_windows) -> None:
    """``build_sequences`` returns the documented shapes."""
    raise NotImplementedError("TODO: assert (N,10,32) / (N,3,32) / (N,3) / (N,3)")


@pytest.mark.skip(reason="scaffold: windowing not implemented")
def test_short_entities_are_dropped(synthetic_windows) -> None:
    """Entities with fewer than 14 windows produce no samples — never padding.

    Padding a short sequence teaches the model that zeros are a valid network
    state, which is both false and useful-looking.
    """
    raise NotImplementedError("TODO: add a 5-window entity, assert it contributes nothing")


@pytest.mark.skip(reason="scaffold: windowing not implemented")
def test_history_precedes_target(synthetic_windows) -> None:
    """Every history window is strictly earlier than every target window."""
    raise NotImplementedError("TODO: assert max(history time) < min(target time) per sample")


# --------------------------------------------------------------------------- #
# Boundaries
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: windowing not implemented")
def test_sequences_never_cross_entity_boundary(synthetic_windows) -> None:
    """A single sample's windows all belong to one entity."""
    raise NotImplementedError("TODO: assert one distinct entity_id per sample")


@pytest.mark.skip(reason="scaffold: windowing not implemented")
def test_sequences_never_cross_campaign_boundary(synthetic_windows) -> None:
    """A single sample's windows all belong to one campaign."""
    raise NotImplementedError("TODO: assert one distinct campaign_id per sample")


@pytest.mark.skip(reason="scaffold: windowing not implemented")
def test_derivatives_reset_at_group_start(ramping_windows) -> None:
    """The first window of each (entity, campaign) has a zero derivative.

    Guards the classic bug: ``diff()`` over the whole frame instead of per group.
    """
    raise NotImplementedError("TODO: assert first-row derivative == NO_HISTORY_VALUE")


# --------------------------------------------------------------------------- #
# Labelling
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: labeller not implemented")
def test_distance_to_attack_counts_strides(synthetic_windows) -> None:
    """``dist_to_attack`` is 0 inside an attack and counts up going backwards."""
    raise NotImplementedError("TODO: check the exact values around window 25")


@pytest.mark.skip(reason="scaffold: labeller not implemented")
def test_distance_is_minus_one_when_no_future_attack(synthetic_windows) -> None:
    """An entity with no attack gets ``NO_FUTURE_ATTACK`` throughout."""
    raise NotImplementedError("TODO: assert entity B is all -1")


@pytest.mark.skip(reason="scaffold: labeller not implemented")
def test_pre_attack_flag_window(synthetic_windows) -> None:
    """``is_pre_attack`` is set for exactly the 6 windows before an attack."""
    raise NotImplementedError("TODO: assert the flag spans windows 19..24 inclusive")


@pytest.mark.skip(reason="scaffold: labeller not implemented")
def test_distance_does_not_cross_campaign(synthetic_windows) -> None:
    """An attack in campaign 2 does not affect distances in campaign 1."""
    raise NotImplementedError("TODO: assert campaign 1 distances are unaffected")


# --------------------------------------------------------------------------- #
# Leakage — the tests that matter most
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: splits not implemented")
def test_no_temporal_leakage_in_features(synthetic_windows) -> None:
    """Perturbing a future window does not change any past window's features.

    The direct test for rule 4 of the LOCKED feature schema: modify window 30,
    recompute, and assert windows 0-29 are byte-identical.
    """
    raise NotImplementedError("TODO: perturb a future row, recompute, compare earlier rows")


@pytest.mark.skip(reason="scaffold: splits not implemented")
def test_no_overlap_between_splits(synthetic_windows) -> None:
    """No ``(entity_id, window_start)`` appears in two splits."""
    raise NotImplementedError("TODO: intersect the split index sets, assert empty")


@pytest.mark.skip(reason="scaffold: splits not implemented")
def test_gap_buffer_prevents_history_overlap(synthetic_windows) -> None:
    """No test sample's 10-window history reaches into a training window.

    The subtlest leak in the pipeline, and the reason for the 14-window buffer.
    """
    raise NotImplementedError("TODO: reconstruct test histories, assert no train overlap")


@pytest.mark.skip(reason="scaffold: splits not implemented")
def test_held_out_family_absent_from_train_and_val(synthetic_windows) -> None:
    """The held-out attack family appears only in test."""
    raise NotImplementedError("TODO: assert the family is missing from train and val")


@pytest.mark.skip(reason="scaffold: splits not implemented")
def test_train_precedes_test_within_campaign(synthetic_windows) -> None:
    """Every train window precedes every test window of the same campaign."""
    raise NotImplementedError("TODO: per campaign, assert max(train time) < min(test time)")


@pytest.mark.skip(reason="scaffold: splits not implemented")
def test_assert_no_leakage_catches_a_deliberate_leak(synthetic_windows) -> None:
    """``assert_no_leakage`` raises on a split we deliberately corrupt.

    A leakage check that has never been seen to fire is not a check.
    """
    raise NotImplementedError("TODO: move a test row into train, assert AssertionError")


# --------------------------------------------------------------------------- #
# Scaling
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: windowing not implemented")
def test_scaler_is_fit_on_train_only(synthetic_windows) -> None:
    """Scaler statistics computed on train are unchanged by val/test content."""
    raise NotImplementedError("TODO: alter test rows, refit on train, assert identical state")


@pytest.mark.skip(reason="scaffold: windowing not implemented")
def test_scaled_features_are_finite(synthetic_windows) -> None:
    """Scaling never emits NaN or inf, even with a zero-variance feature."""
    raise NotImplementedError("TODO: include a constant column, assert all finite")
