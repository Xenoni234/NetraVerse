import numpy as np
import pandas as pd
import torch

from src.data.loaders import _parse_cic_working_hours
from src.data import windowing as W
from src.models.lstm_encoder_decoder import WorldModel, WorldModelConfig


def test_working_hours_clock_is_dataset_specific_and_preserves_explicit_time():
    s = pd.Series(['7/7/2017 1:05','7/7/2017 9:35','7/7/2017 12:59',
                   '7/7/2017 1:05 AM','2017-07-07 01:05:00',None])
    t = _parse_cic_working_hours(s)
    assert t.dt.hour.iloc[:5].tolist() == [13,9,12,1,1]
    assert pd.isna(t.iloc[5])


def test_vectorized_behaviour_matches_trailing_reference():
    rng = np.random.default_rng(42)
    n = 85
    df = pd.DataFrame({'campaign_id':['a']*n,'entity_id':['x']*30+['y']*55,
                      'window_start':pd.date_range('2020-01-01',periods=n,freq='30s'),
                      'flows_per_sec':rng.uniform(0,5,n),'dst_port_entropy':rng.uniform(0,3,n)})
    actual = W._add_behavioural_features(df,W.WindowConfig())
    expected = []
    for _,g in df.groupby('entity_id'):
        x = g.flows_per_sec.to_numpy()
        for i in range(len(x)):
            h = x[max(0,i-20):i]
            expected.append(0 if len(h)<3 else np.clip((x[i]-np.median(h))/max(np.ptp(np.percentile(h,[25,75])),h.std(),1e-3),-10,10))
    np.testing.assert_allclose(actual.baseline_deviation,expected,atol=1e-6)
    assert actual.mask_trajectory_velocity.iloc[30] == 0


def test_cumulative_risk_and_residual_dynamics():
    torch.manual_seed(1)
    model = WorldModel(WorldModelConfig(6,4,hidden_size=8,residual_state=True,
                                       temporal_deltas=True,cumulative_risk=True)).eval()
    x = torch.randn(3,10,6)
    out = model(x)
    risk = out['risk_logits'].sigmoid()
    assert torch.all(risk[:,1:] >= risk[:,:-1])
    torch.testing.assert_close(out['state_mean'],x[:,-1:,:4].expand(-1,3,-1))
    out['risk_logits'].sum().backward()
    assert model.decoder.weight_ih_l0.grad.abs().sum() > 0


def test_window_aggregation_preserves_dataset_and_entropy():
    from src.data.unified_schema import FLOW_FEATURE_COLUMNS
    rows = pd.DataFrame({c:np.zeros(4) for c in FLOW_FEATURE_COLUMNS})
    rows['timestamp'] = pd.to_datetime(['2020-01-01']*4,utc=True)
    rows['src_ip'] = 'host'
    rows['dst_ip'] = ['a','b','c','c']
    rows['dst_port'] = [1,2,3,3]
    rows['protocol'] = 6
    rows['campaign_id'] = ['one','one','two','two']
    rows['dataset'] = ['d1','d1','d2','d2']
    rows['binary_label'] = [0,1,0,0]
    rows['attt_stage'] = [0,4,0,0]
    actual = W.build_windows(rows).sort_values('campaign_id')
    assert actual.dataset.tolist() == ['d1','d2']
    assert actual.dst_port_entropy.tolist() == [1.,0.]
    assert actual.attt_stage.tolist() == [4,0]


def test_masked_history_never_invents_future_targets():
    from tests.test_forecast_correctness import windows
    f = windows().drop(index=[3,5])
    b = W.build_sequences(f,W.WindowConfig(history_policy='masked'))
    assert b.feature_names[-1] == 'mask_observed'
    assert (b.x[:,:,-1] == 0).any()
    assert (b.x[:,:,-1].sum(1) >= 3).all()
    assert (b.future[:,:,-1] == 1).all()
    for t in b.meta.window_start:
        for step in range(1,5):
            assert t+pd.Timedelta(seconds=30*step) in set(f.window_start)


def test_timestamp_ties_never_cross_partitions():
    from src.eval.splits import chronological_split, SplitConfig
    f = pd.DataFrame({'campaign_id':['x']*20,'binary_label':[0]*20,
                      'window_start':pd.date_range('2020-01-01',periods=5,freq='30s').repeat(4)})
    parts = chronological_split(f,config=SplitConfig(time_col='window_start'),verbose=False)
    assert parts['train'].window_start.max() < parts['val'].window_start.min()
    assert parts['val'].window_start.max() < parts['test'].window_start.min()


def test_masked_checkpoint_inference_and_horizon_thresholds():
    from tests.test_forecast_correctness import windows
    from src.inference.engine import Forecaster
    f = windows().drop(index=[3,5])
    b = W.build_sequences(f,W.WindowConfig(history_policy='masked'))
    model = WorldModel(WorldModelConfig(b.x.shape[-1],len(W.STATE_FEATURE_COLUMNS),hidden_size=8)).eval()
    fc = Forecaster(model,W.fit_scaler(b.x,mask_tail=4),list(b.feature_names),.1,[1,2,4],torch.device('cpu'),
                    thresholds=[.1,.2,.3],sequence_policy='masked_history_30s')
    timeline = fc.forecast_host_timeline(f)
    direct = fc.forecast_batch(b.x)['risk']
    aligned = timeline.set_index('window_start').loc[b.meta.window_start]
    np.testing.assert_allclose(aligned[['risk_k1','risk_k2','risk_k4']],direct,atol=1e-6)
    assert fc.threshold_for_horizon(4) == .3


def test_sustained_lead_uses_confirmation_close_and_real_time():
    from src.inference.engine import lead_time_seconds
    f = pd.DataFrame({'window_start':pd.date_range('2020-01-01',periods=5,freq='30s'),
                      'risk_k4':[.8,.8,.8,.8,.8],'true_label':[0,0,0,0,1]})
    assert lead_time_seconds(f,horizon_key='risk_k4',threshold=.5,sustain=2)==60
    f = f.iloc[[0,2,4]]
    assert lead_time_seconds(f,horizon_key='risk_k4',threshold=.5,sustain=2) is None
