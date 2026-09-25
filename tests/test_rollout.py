"""World model + rollout contract: 300 s horizon, prior-only imagination, deterministic mean path."""
import torch

from src.features.schema import N_FEATURES
from src.models.rollout import Intervention, batch_forecast, rollout
from src.models.world_model import WorldModel
from src.utils.config import world_model_config


def _model():
    torch.manual_seed(0)
    return WorldModel(world_model_config()).eval()


def test_rollout_covers_300s():
    cfg = world_model_config()
    m = _model()
    x = torch.randn(1, cfg["windowing"]["history"], N_FEATURES)
    st = m.encode(x)
    r = rollout(m, st, cfg["windowing"]["horizon"], mc=4)
    assert r.horizon_s[-1] == 300
    assert len(r.probs) == len(r.stages) == 5
    assert all(0 <= p <= 1 for p in r.probs)
    assert all(lo <= hi for lo, hi in zip(r.lo, r.hi))


def test_intervention_uses_supplied_state():
    m = _model()
    x = torch.randn(1, 10, N_FEATURES)
    s1, s2 = m.encode(x), m.encode(torch.zeros(1, 10, N_FEATURES))
    torch.manual_seed(1); a = rollout(m, s1, 5, Intervention("x", s2), mc=2)
    torch.manual_seed(1); b = rollout(m, s2, 5, mc=2)
    assert a.probs == b.probs and a.intervention == "x"


def test_batch_forecast_deterministic():
    m = _model()
    x = torch.randn(3, 15, N_FEATURES)
    a = batch_forecast(m, x, None, 10, 5)
    b = batch_forecast(m, x, None, 10, 5)
    assert a["future"].shape == (3, 5)
    assert (a["future"] == b["future"]).all()


def test_loss_backprop():
    m = WorldModel(world_model_config())
    x = torch.randn(4, 15, N_FEATURES)
    nb = torch.zeros(4, 15, 2 * N_FEATURES + 1)
    ry = torch.zeros(4, 15); ry[0, 12:] = 1
    sy = torch.zeros(4, 15, dtype=torch.long)
    out = m.loss(x, nb, ry, sy, 10, 5, 2.0)
    out["total"].backward()
    assert torch.isfinite(out["total"])
