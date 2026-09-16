import numpy as np
import pandas as pd
import pytest

from src.data import windowing as W
from src.eval.metrics import compute_all_metrics


def windows():
    f = pd.DataFrame(np.tile(np.arange(20)[:, None], (1, len(W.MODEL_COLUMNS))), columns=W.MODEL_COLUMNS)
    f['campaign_id'], f['entity_id'] = 'campaign', 'host'
    f['window_start'] = pd.date_range('2020-01-01', periods=20, freq='30s', tz='UTC')
    f['binary_label'] = (np.arange(20) >= 12).astype(int)
    f['attt_stage'] = f.binary_label
    return f


def test_exact_rollout_and_onset():
    b = W.build_sequences(windows())
    np.testing.assert_array_equal(b.future[0, :, 0], [10,11,12,13])
    np.testing.assert_array_equal(b.y_state[0, :, 0], [10,11,13])
    np.testing.assert_array_equal(b.y_risk[0], [0,0,1])


def test_gap_is_not_a_thirty_second_transition():
    f = windows()
    f.loc[10:, 'window_start'] += pd.Timedelta(hours=1)
    with pytest.raises(ValueError, match='No sequences'):
        W.build_sequences(f)


def test_signed_log_scaler_preserves_masks_and_legacy():
    x = np.array([[[0., -100., 1.]], [[1000000., 100., 0.]]], dtype=np.float32)
    s = W.fit_scaler(x, method='signed_log', mask_tail=1)
    z = W.apply_scaler(x,s)
    assert np.isfinite(z).all()
    np.testing.assert_allclose(z[..., :2].mean(axis=(0,1)),0,atol=1e-6)
    np.testing.assert_array_equal(z[..., -1], x[..., -1])
    legacy = W.fit_scaler(x,method='standard',mask_tail=1)
    np.testing.assert_allclose(W.apply_scaler(x,legacy)[...,:2],(x[...,:2]-legacy['center'])/legacy['scale'])


def test_all_benign_false_alarms_are_counted():
    m = compute_all_metrics([0,0],[1,0],[.8,.2])
    assert m['fpr'] == .5
    assert m['confusion_matrix']['fp'] == 1


def test_sequence_cache_keeps_all_future_steps(tmp_path):
    b = W.build_sequences(windows())
    path = tmp_path / 'sequences.npz'
    W.save_sequences(b,path)
    loaded = W.load_sequences(path)
    np.testing.assert_array_equal(loaded.future,b.future)


def test_mc_dropout_produces_nonzero_uncertainty():
    import torch
    from src.models.lstm_encoder_decoder import WorldModel, WorldModelConfig
    from src.inference.engine import Forecaster
    torch.manual_seed(42)
    x = np.ones((2,10,len(W.MODEL_COLUMNS)), dtype=np.float32)
    model = WorldModel(WorldModelConfig(len(W.MODEL_COLUMNS), len(W.STATE_FEATURE_COLUMNS), hidden_size=8))
    forecaster = Forecaster(model,W.fit_scaler(x),list(W.MODEL_COLUMNS),.5,[1,2,4],torch.device('cpu'))
    result = forecaster.forecast_batch(x,mc_samples=8)
    assert np.any(result['risk_hi'] > result['risk_lo'])


def test_timeline_rejects_gapped_history():
    import torch
    from src.models.lstm_encoder_decoder import WorldModel, WorldModelConfig
    from src.inference.engine import Forecaster
    f = windows().iloc[:10].copy()
    x = f[list(W.MODEL_COLUMNS)].to_numpy(dtype='float32')[None]
    model = WorldModel(WorldModelConfig(len(W.MODEL_COLUMNS), len(W.STATE_FEATURE_COLUMNS), hidden_size=8))
    forecaster = Forecaster(model,W.fit_scaler(x),list(W.MODEL_COLUMNS),.5,[1,2,4],torch.device('cpu'))
    assert len(forecaster.forecast_host_timeline(f)) == 1
    f.loc[5:,'window_start'] += pd.Timedelta(minutes=5)
    assert forecaster.forecast_host_timeline(f).empty


def test_lead_time_uses_window_close_and_matching_horizon():
    from scripts.improve_world_model import warning_lead_times
    f = windows()
    meta = f.iloc[[9]][['campaign_id','entity_id','window_start']]
    labels = f.set_index(['campaign_id','entity_id','window_start']).binary_label
    # Attack begins three windows later: a +30s alert is not a correct forecast.
    wrong = warning_lead_times(meta,np.array([[.9,.1,.1]]),np.array([.5]*3),labels)
    assert wrong['alerted_events'] == 0
    right = warning_lead_times(meta,np.array([[.1,.1,.9]]),np.array([.5]*3),labels)
    assert right['lead_seconds'] == [60.0]
