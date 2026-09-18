import numpy as np
import pandas as pd
import torch

from src.data.synthetic import EpisodeSpec, generate_episode
from src.data.windowing import MODEL_COLUMNS, build_sequences
from src.eval.calibration import fit_calibrator
from src.models.lstm_encoder_decoder import WorldModel, WorldModelConfig
from src.models.self_supervised import (SelfSupervisedConfig, TemporalPretrainer,
                                        masked_temporal_batch, self_supervised_loss)


def test_synthetic_episode_is_reproducible_and_provenanced():
    spec = EpisodeSpec("recon", seed=42, entity_count=1)
    a, b = generate_episode(spec), generate_episode(spec)
    pd.testing.assert_frame_equal(a, b)
    assert set(["episode_id", "scenario", "source_kind", "generator_seed"]).issubset(a.columns)
    assert int(a.attack_onset.sum()) == 1
    assert a.source_kind.eq("synthetic").all()


def test_synthetic_sequence_has_future_targets():
    frame = generate_episode(EpisodeSpec("c2", seed=3, entity_count=1))
    batch = build_sequences(frame)
    assert batch.x.shape[-1] == len(MODEL_COLUMNS)
    assert batch.y_risk.sum() > 0
    assert batch.meta.source_kind.eq("synthetic").all()


def test_self_supervised_loss_is_finite():
    torch.manual_seed(1)
    x = torch.randn(8, 10, 12)
    model = TemporalPretrainer(SelfSupervisedConfig(input_size=12, hidden_size=8, num_layers=1))
    masked, mask = masked_temporal_batch(x, 0.2)
    loss, parts = self_supervised_loss(model(masked), x, mask)
    assert torch.isfinite(loss)
    assert np.isfinite(parts["total"])


def test_pretrained_encoder_loads_into_world_model():
    model = WorldModel(WorldModelConfig(input_size=12, state_size=9, hidden_size=8, num_layers=1))
    pre = TemporalPretrainer(SelfSupervisedConfig(input_size=12, hidden_size=8, num_layers=1))
    model.load_pretrained_encoder(pre.encoder.state_dict())


def test_calibrator_round_trip():
    y = np.array([[0, 0], [1, 0], [1, 1], [0, 1]])
    p = np.array([[.1, .1], [.7, .2], [.8, .9], [.2, .8]])
    calibrator = fit_calibrator(y, p, bins=2)
    restored = type(calibrator).from_dict(calibrator.to_dict())
    np.testing.assert_allclose(calibrator.transform(p), restored.transform(p))
