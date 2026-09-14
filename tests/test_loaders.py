"""Tests for dataset loading and unified-schema conformance.

What these tests are for: the loaders sit at the boundary between four messy
public datasets and everything else. A loader that silently drops a column,
mis-parses a timestamp, or returns a naive datetime will not fail — it will
produce a slightly wrong model, quietly, and nobody will notice until the
numbers make no sense.

Every test here runs on small **synthetic fixtures**, not on the real datasets:
tests must pass on a teammate's laptop with an empty ``data/`` directory. Tests
that need real data are marked ``@pytest.mark.requires_data`` and skipped when
it is absent.

TODO
----
* [ ] Implement the synthetic fixtures (a handful of rows per dataset format).
* [ ] Implement the schema-conformance tests.
* [ ] Implement the timestamp tests — timezone handling is the top bug source.
* [ ] Add the ``requires_data`` marker to ``pyproject.toml`` and a skip helper.
* [ ] Add a round-trip parquet test (write then read must be identical).
* [ ] Add a test that every dataset's labels map to a known attack family.
"""

from __future__ import annotations

from pathlib import Path

import pytest


# --------------------------------------------------------------------------- #
# Fixtures — synthetic mini-datasets, one per source format
# --------------------------------------------------------------------------- #


@pytest.fixture
def cicids_csv(tmp_path: Path) -> Path:
    """A tiny CIC-IDS2017-format CSV, including the dataset's real quirks.

    Must reproduce: leading spaces in column names, an ``Infinity`` cell in a
    rate column, a blank cell, and a mix of BENIGN and attack labels.
    """
    raise NotImplementedError("TODO: write a small CSV with the CIC quirks baked in")


@pytest.fixture
def unsw_csv(tmp_path: Path) -> Path:
    """A headerless UNSW-NB15-format CSV plus its separate feature-name file."""
    raise NotImplementedError("TODO: write both files, with epoch Stime/Ltime")


@pytest.fixture
def ctu13_binetflow(tmp_path: Path) -> Path:
    """A tiny CTU-13 ``.binetflow`` with Background, Normal and Botnet rows."""
    raise NotImplementedError("TODO: write a small binetflow with free-text labels")


# --------------------------------------------------------------------------- #
# Schema conformance
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: loader not implemented")
def test_cicids_loader_returns_expected_columns(cicids_csv: Path) -> None:
    """The CIC loader emits every column the unified mapping expects."""
    raise NotImplementedError("TODO: load, assert the source columns are present")


@pytest.mark.skip(reason="scaffold: loader not implemented")
def test_to_unified_produces_locked_schema(cicids_csv: Path) -> None:
    """``to_unified`` output passes ``validate_unified`` exactly."""
    raise NotImplementedError("TODO: load -> to_unified -> validate_unified")


@pytest.mark.skip(reason="scaffold: loader not implemented")
def test_missing_required_column_raises(tmp_path: Path) -> None:
    """A CSV missing a required column fails loudly, naming the column."""
    raise NotImplementedError("TODO: assert ValueError mentioning the missing column")


# --------------------------------------------------------------------------- #
# Timestamps — the most common silent failure
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: loader not implemented")
def test_timestamps_are_timezone_aware_utc(cicids_csv: Path) -> None:
    """Every loader returns tz-aware UTC timestamps.

    A naive timestamp survives every downstream operation and silently shifts
    every window boundary by the local UTC offset.
    """
    raise NotImplementedError("TODO: assert dtype is datetime64[ns, UTC]")


@pytest.mark.skip(reason="scaffold: loader not implemented")
def test_timestamps_are_monotonic_within_campaign(cicids_csv: Path) -> None:
    """Rows within a campaign are time-ordered after loading."""
    raise NotImplementedError("TODO: groupby campaign, assert is_monotonic_increasing")


@pytest.mark.skip(reason="scaffold: loader not implemented")
def test_no_null_timestamps(cicids_csv: Path) -> None:
    """A null timestamp is unrecoverable downstream — fail at load time."""
    raise NotImplementedError("TODO: assert no nulls in the timestamp column")


# --------------------------------------------------------------------------- #
# Cleaning
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: loader not implemented")
def test_infinity_cells_become_null(cicids_csv: Path) -> None:
    """CIC's literal ``Infinity`` cells are coerced to null, not to a huge float.

    A surviving inf propagates through scaling and silently produces NaN
    gradients several hours later.
    """
    raise NotImplementedError("TODO: assert the rate column has nulls, not infs")


@pytest.mark.skip(reason="scaffold: loader not implemented")
def test_column_names_are_stripped(cicids_csv: Path) -> None:
    """Leading and trailing spaces are removed from CIC column names."""
    raise NotImplementedError("TODO: assert no column name differs from its strip()")


# --------------------------------------------------------------------------- #
# Labels
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: loader not implemented")
def test_all_labels_map_to_known_family(cicids_csv: Path) -> None:
    """Every source label normalises to a family present in ``FAMILY_TO_STAGE``.

    An unmapped family silently becomes BENIGN, which quietly deletes attacks
    from the training set.
    """
    raise NotImplementedError("TODO: normalise labels, assert unmapped_families is empty")


@pytest.mark.skip(reason="scaffold: loader not implemented")
def test_parquet_round_trip(tmp_path: Path, cicids_csv: Path) -> None:
    """``write_parquet`` then ``read_parquet`` returns an identical frame."""
    raise NotImplementedError("TODO: assert_frame_equal on the round trip")


# --------------------------------------------------------------------------- #
# Real-data tests — skipped unless the datasets are present
# --------------------------------------------------------------------------- #


@pytest.mark.skip(reason="scaffold: loader not implemented")
def test_real_dataset_loads_if_present() -> None:
    """Smoke test against real data when it is available locally.

    Mark with ``requires_data`` and skip via ``paths.verify_raw_layout``.
    """
    raise NotImplementedError("TODO: skip-if-absent, then load a capped number of rows")
