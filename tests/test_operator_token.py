"""Operator-token gate for live enforcement (FR17/R13).

Two modes:
- a sensor secret (NV_OPERATOR_TOKEN) configured -> header must match exactly;
- no secret configured -> any non-empty operator token is accepted, blank/missing is refused.
"""
import pytest
from fastapi import HTTPException

from src.api.routes_live import _check_token


def test_no_secret_requires_nonempty_token(monkeypatch):
    monkeypatch.delenv("NV_OPERATOR_TOKEN", raising=False)
    for bad in (None, "", "   "):
        with pytest.raises(HTTPException) as e:
            _check_token(bad)
        assert e.value.status_code == 403
    _check_token("anything-the-operator-typed")   # non-empty -> accepted


def test_secret_requires_exact_match(monkeypatch):
    monkeypatch.setenv("NV_OPERATOR_TOKEN", "s3cret")
    for bad in (None, "", "wrong"):
        with pytest.raises(HTTPException) as e:
            _check_token(bad)
        assert e.value.status_code == 403
    _check_token("s3cret")                          # exact match -> accepted
