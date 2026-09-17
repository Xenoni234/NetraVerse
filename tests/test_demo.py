"""Demo boundaries: history, real inputs, conversion errors and attribution alignment."""
from pathlib import Path
import subprocess
import numpy as np
import pandas as pd
import pytest
from demo import helpers as H
from src.data.windowing import MODEL_COLUMNS, apply_scaler
from src.inference.live import CICFLOWMETER_PY_COLUMN_MAP


def frame(n=12):
    data = pd.DataFrame({f: np.arange(n,dtype=float) for f in MODEL_COLUMNS})
    data['window_start'] = pd.date_range('2020-01-01', periods=n, freq='30s', tz='UTC')
    data['campaign_id'], data['entity_id'], data['binary_label'] = 'test', 'host', 0
    return data


def test_gap_and_focus_alignment():
    data = frame()
    history,x = H.history_at(data,data.window_start.iloc[9],list(MODEL_COLUMNS))
    assert len(history)==10
    np.testing.assert_array_equal(x[0,-1],data.iloc[9][list(MODEL_COLUMNS)].to_numpy(float))
    data.loc[6:,'window_start'] += pd.Timedelta(seconds=30)
    assert not len(H.origins(data))
    with pytest.raises(ValueError,match='consecutive'):
        H.history_at(data,data.window_start.iloc[9],list(MODEL_COLUMNS))


def test_benign_reference_never_crosses_hosts_or_attack():
    good=frame();bad=frame();bad['entity_id']='other';bad['binary_label']=1
    bad[list(MODEL_COLUMNS)]=999
    ref=H.benign_references(pd.concat([good,bad]),list(MODEL_COLUMNS))
    assert ref.shape==(3,10,43)
    assert ref.max()<999
    np.testing.assert_array_equal(ref,H.benign_references(pd.concat([bad,good]),list(MODEL_COLUMNS)))
    with pytest.raises(ValueError,match='benign'):
        H.benign_references(bad,list(MODEL_COLUMNS))


def test_alert_confirmation_and_attack_shading():
    data=frame(5);data['risk_k4']=[.9,.9,.1,.9,.9]
    assert H.first_sustained(data,'risk_k4',.5)[0]==data.window_start.iloc[1]+pd.Timedelta(seconds=30)
    data.loc[1:,'window_start']+=pd.Timedelta(seconds=30)
    assert H.first_sustained(data,'risk_k4',.5)[0]==data.window_start.iloc[4]+pd.Timedelta(seconds=30)
    data['binary_label']=[1,1,0,1,1]
    assert len(H.attack_intervals(data))==3


def test_packet_mapping_and_explicit_group():
    for source,target in H.PACKET_MAP.items():
        assert CICFLOWMETER_PY_COLUMN_MAP[source]==target
    assert len(H.PACKET_FEATURES)==9
    assert set(H.PACKET_FEATURES)<=set(MODEL_COLUMNS)
    assert 'fwd_bytes' not in H.PACKET_FEATURES


def test_forecast_log_preserves_missing_history_and_forecast_intervals():
    host=frame()
    timeline=pd.DataFrame({'window_start':host.window_start.iloc[9:].to_list()})
    for k in (1,2,4):
        timeline[f'risk_k{k}']=[.2,.5,.1]
        timeline[f'stage_k{k}']=[0,2,0]
    log=H.forecast_log(host.iloc[::-1],timeline,list(MODEL_COLUMNS),
                       pd.Series(1.,index=MODEL_COLUMNS),{1:.1,2:.3,4:.4},primary=4)
    assert log['Window start (UTC)'].is_monotonic_increasing
    assert len(log)==len(host)
    assert log.loc[:8,'+120 s risk'].isna().all()
    assert (log.loc[:8,'Forecast status']=='Insufficient consecutive history').all()
    assert log.loc[10,'Forecast status']=='Above alert threshold'
    assert log.loc[9,'Forecast status']=='Below alert threshold'
    assert log.loc[10,'+120 s stage']=='INITIAL_ACCESS'
    assert log.loc[9,'Forecast available (UTC)']==host.window_start.iloc[9]+pd.Timedelta(seconds=30)
    assert log.loc[9,'Forecast through (+120 s, UTC)']==host.window_start.iloc[9]+pd.Timedelta(seconds=150)
    assert 'reference' in log.loc[9,'Observed evidence (not SHAP)']
    np.testing.assert_allclose(log['+120 s risk'].dropna(),timeline.risk_k4)
    other=H.forecast_log(host,timeline,list(MODEL_COLUMNS),
                        pd.Series(100.,index=MODEL_COLUMNS),{1:.1,2:.3,4:.4},primary=1)
    assert other.loc[9,'Forecast status']=='Above alert threshold'
    assert other.loc[9,'Forecast through (+30 s, UTC)']==host.window_start.iloc[9]+pd.Timedelta(seconds=60)
    assert other.loc[9,'Observed evidence (not SHAP)']=='No feature notably elevated above the benign gallery reference.'


@pytest.mark.parametrize('payload,suffix',[(b'', '.csv'),(b'garbage','.csv'),(b'a,b\n1,2\n','.csv'),(b'abc','.txt')])
def test_invalid_uploads(payload,suffix):
    with pytest.raises((ValueError,pd.errors.ParserError)):
        H.ingest_upload(payload,suffix)


def test_conversion_failure_and_timeout(monkeypatch,tmp_path):
    monkeypatch.setattr(H,'patch_converter',lambda:False)
    monkeypatch.setattr(H.subprocess,'run',lambda *a,**k:subprocess.CompletedProcess(a,1,'','invalid capture'))
    with pytest.raises(ValueError,match='conversion failed'):
        H.convert_capture(tmp_path/'x',tmp_path/'y')
    def timeout(*a,**k):
        raise subprocess.TimeoutExpired(a,1)
    monkeypatch.setattr(H.subprocess,'run',timeout)
    with pytest.raises(ValueError,match='five-minute'):
        H.convert_capture(tmp_path/'x',tmp_path/'y')


def test_real_converter_packet_values_and_zero_audit(tmp_path):
    pytest.importorskip('cicflowmeter')
    scapy=pytest.importorskip('scapy.all')
    a=scapy.Ether(src='00:00:00:00:00:01',dst='00:00:00:00:00:02')/scapy.IP(src='10.0.0.1',dst='10.0.0.2')/scapy.TCP(sport=1234,dport=80,flags='S')
    b=scapy.Ether(src='00:00:00:00:00:02',dst='00:00:00:00:00:01')/scapy.IP(src='10.0.0.2',dst='10.0.0.1')/scapy.TCP(sport=80,dport=1234,flags='SA')/scapy.Raw(b'test')
    a.time=1700000000;b.time=1700000000.1
    path=tmp_path/'tiny.pcap';scapy.wrpcap(str(path),[a,b])
    windows,audit=H.ingest_upload(path.read_bytes(),'.pcap')
    assert audit['model_columns']==43 and audit['finite']
    assert not audit['missing_source_fields']
    assert all(v['present'] for v in audit['packet_source_mappings'].values())
    assert audit['nonzero_columns']<43
    assert windows.mean_bwd_pkt_len.iloc[0]>0
    assert (windows.binary_label==0).all()  # Placeholders, not verified benign labels.


def test_checkpoint_attention_shap_and_raw_api_agree():
    checkpoint=Path('models/wm_final/best.ckpt')
    paths=list(Path('data/processed').glob('windows_cicids2017_all_+2018_+ctu13_*.parquet'))
    if not checkpoint.exists() or not paths:
        pytest.skip('Local checkpoint and gallery required')
    import torch
    from src.inference.engine import load_forecaster
    from src.explain.shap_wrapper import RiskExplainer
    torch.set_num_threads(2)
    model=load_forecaster(checkpoint,device='cpu')
    separate=load_forecaster(checkpoint,device='cpu')
    gallery=pd.read_parquet(max(paths,key=lambda p:p.stat().st_mtime))
    host=gallery.loc[(gallery.campaign_id=='cicids2017-friday') & (gallery.entity_id=='172.16.0.1')].sort_values('window_start').reset_index(drop=True)
    origin=H.origins(host)[0]
    host=host.iloc[origin-9:origin+1]
    timeline=model.forecast_host_timeline(host)
    _,raw=H.history_at(host,timeline.window_start.iloc[0],model.feature_names)
    expected=model.forecast_batch(raw)
    assert timeline.risk_k4.iloc[0]==pytest.approx(expected['risk'][0,2])
    attention=timeline.attn_k4.iloc[0]
    assert attention.shape==(10,) and np.isfinite(attention).all()
    assert attention.sum()==pytest.approx(1,abs=1e-5)
    reference=H.benign_references(gallery,model.feature_names,size=5)
    explainer=RiskExplainer(separate.model,apply_scaler(reference,model.scaler),feature_names=model.feature_names,horizon=4,device='cpu')
    result=explainer.explain_batch(apply_scaler(raw,model.scaler))[0]
    assert result.values.shape==(10,43)
    assert np.isfinite(result.values).all()
    assert result.prediction==pytest.approx(timeline.risk_k4.iloc[0],abs=1e-6)
    mc=model.forecast_host_timeline(host,mc_samples=20)
    assert (mc.risk_lo_k4<=mc.risk_hi_k4).all()
    np.testing.assert_allclose(mc.attn_k4.iloc[0],attention)
