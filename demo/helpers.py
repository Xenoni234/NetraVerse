"""Offline dashboard utilities. No changes to inference or window semantics."""
from __future__ import annotations

import importlib.metadata
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import numpy as np
import pandas as pd

from src.data.windowing import MODEL_COLUMNS, build_windows
from src.data.unified_schema import FLOW_FEATURE_COLUMNS
from src.inference.live import _detect_map, load_live_flows

PACKET_FEATURES = (
    'mean_fwd_pkt_len', 'mean_bwd_pkt_len', 'pkt_len_var', 'mean_fwd_iat_s',
    'mean_bwd_iat_s', 'mean_init_win_fwd', 'mean_init_win_bwd', 'active_s', 'idle_s',
)
PACKET_MAP = dict(zip(
    ('fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'pkt_len_var', 'fwd_iat_mean',
     'bwd_iat_mean', 'init_fwd_win_byts', 'init_bwd_win_byts', 'active_mean', 'idle_mean'),
    ('fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'pkt_len_var', 'fwd_iat_mean',
     'bwd_iat_mean', 'init_win_fwd', 'init_win_bwd', 'active_mean', 'idle_mean')))


def campaign_label(name):
    families = {'monday': 'benign only', 'tuesday': 'FTP / SSH brute force',
                'wednesday': 'DoS / Heartbleed', 'thursday': 'Web attacks / infiltration',
                'friday': 'Port scan / bot / DDoS'}
    if name.startswith('ctu13-'):
        family = 'botnet scenario' + ('; no attack labels in cached windows' if name == 'ctu13-1' else '')
    elif name.startswith('cicids2018-'):
        family = 'DDoS'
    else:
        family = families.get(name.rsplit('-', 1)[-1], 'recorded traffic')
    return f'{name} | {family}'


def origins(frame, length=10):
    times = pd.to_datetime(frame.window_start, utc=True).astype('datetime64[ns, UTC]').astype('int64').to_numpy()
    if len(times) < length:
        return np.array([], dtype=int)
    breaks = np.r_[0, np.cumsum(np.diff(times) != 30_000_000_000)]
    candidates = np.arange(length - 1, len(times))
    return candidates[breaks[candidates] == breaks[candidates - length + 1]]


def host_catalog(frame, length=10):
    if frame.empty:
        return pd.DataFrame(columns=['host','attacked','windows','forecasts'])
    ordered = frame.sort_values(['entity_id','window_start'])
    times = pd.to_datetime(ordered.window_start,utc=True).astype('datetime64[ns, UTC]').astype('int64').to_numpy()
    breaks = np.r_[True,np.diff(times)!=30_000_000_000] | (ordered.entity_id != ordered.entity_id.shift()).to_numpy()
    positions = np.arange(len(ordered))
    run_start = np.maximum.accumulate(np.where(breaks,positions,0))
    counts = ordered.assign(eligible=positions-run_start>=length-1).groupby('entity_id',sort=True).agg(
        attacked=('binary_label','max'),windows=('window_start','size'),forecasts=('eligible','sum')).reset_index()
    counts = counts.rename(columns={'entity_id':'host'})
    counts['host'] = counts.host.astype(str)
    counts['attacked'] = counts.attacked.astype(bool)
    return counts


def history_at(frame, timestamp, features, length=10):
    group = frame.sort_values('window_start').reset_index(drop=True)
    matches = np.flatnonzero(pd.to_datetime(group.window_start, utc=True) == pd.Timestamp(timestamp))
    if len(matches) != 1 or matches[0] not in origins(group, length):
        raise ValueError('The selected forecast does not have consecutive history.')
    end = matches[0]
    history = group.iloc[end-length+1:end+1]
    return history, history[features].to_numpy(dtype='float32')[None]


def benign_references(frame, features, length=10, size=100):
    # Find valid origins vectorially, then materialize only the sampled histories.
    group = frame.sort_values(['campaign_id', 'entity_id', 'window_start']).reset_index(drop=True)
    times = pd.to_datetime(group.window_start, utc=True).astype('datetime64[ns, UTC]').astype('int64').to_numpy()
    same_host = ((group.campaign_id == group.campaign_id.shift()) &
                 (group.entity_id == group.entity_id.shift())).to_numpy()
    contiguous = np.r_[False, np.diff(times) == 30_000_000_000] & same_host
    breaks = np.cumsum(~contiguous)
    candidates = np.arange(length-1, len(group))
    valid = candidates[breaks[candidates] == breaks[candidates-length+1]]
    totals = np.r_[0, np.cumsum(group.binary_label.to_numpy() != 0)]
    valid = valid[totals[valid+1] == totals[valid-length+1]]
    if not len(valid):
        raise ValueError('No fully benign consecutive reference histories in gallery.')
    rng = np.random.default_rng(1337)
    chosen = rng.choice(valid, min(size,len(valid)), replace=False)
    from src.explain.shap_wrapper import sample_background
    pool = np.stack([group.iloc[end-length+1:end+1][features].to_numpy(dtype='float32') for end in chosen])
    return sample_background(pool, np.zeros(len(pool)), size=min(size, len(pool)))


def first_sustained(timeline, key, threshold):
    for i in range(1, len(timeline)):
        previous, current = timeline.iloc[i-1], timeline.iloc[i]
        if (current.window_start-previous.window_start).total_seconds() == 30 and min(previous[key], current[key]) >= threshold:
            return current.window_start + pd.Timedelta(seconds=30), float(current[key])
    return None


def attack_intervals(host):
    intervals = []
    for row in host.sort_values('window_start').itertuples():
        if row.binary_label:
            end = row.window_start + pd.Timedelta(seconds=30)
            if intervals and intervals[-1][1] == row.window_start:
                intervals[-1] = (intervals[-1][0], end)
            else:
                intervals.append((row.window_start, end))
    return intervals


def forecast_log(host, timeline, feature_names, baseline, thresholds, primary=4):
    """Join real forecasts to every observed window, without filling history gaps.

    Forecasts become available when the origin window closes. The selected
    horizon covers the next K windows, not an exact predicted attack timestamp.
    Evidence is observed elevation; SHAP remains a separate focused explanation.
    """
    from src.inference.engine import explain_window
    from src.mitre.stage_mapping import STAGE_NAMES

    merged = host.merge(timeline, on='window_start', how='left', validate='one_to_one')
    merged = merged.sort_values('window_start')
    rows = []
    for _, window in merged.iterrows():
        available = pd.notna(window[f'risk_k{primary}'])
        issued = window.window_start + pd.Timedelta(seconds=30) if available else pd.NaT
        record = {
            'Window start (UTC)': window.window_start,
            'Forecast available (UTC)': issued,
            f'Forecast through (+{30*primary} s, UTC)': issued + pd.Timedelta(seconds=30*primary),
        }
        for k in thresholds:
            risk = window[f'risk_k{k}']
            record[f'+{30*k} s risk'] = risk
            record[f'+{30*k} s stage'] = STAGE_NAMES[int(window[f'stage_k{k}'])] if pd.notna(risk) else None
        if available:
            record['Forecast status'] = ('Above alert threshold' if window[f'risk_k{primary}'] >= thresholds[primary]
                                         else 'Below alert threshold')
            sentence, drivers = explain_window(window, baseline, feature_names, top_k=3)
            record['Observed evidence (not SHAP)'] = (sentence.replace('normal ~', 'reference ~') if drivers
                else 'No feature notably elevated above the benign gallery reference.')
        else:
            record['Forecast status'] = 'Insufficient consecutive history'
            record['Observed evidence (not SHAP)'] = 'No prediction: the required consecutive history is not available.'
        rows.append(record)
    return pd.DataFrame(rows)


def patch_converter():
    if importlib.metadata.version('cicflowmeter') != '0.5.0':
        raise ValueError('Install demo/requirements.txt: cicflowmeter 0.5.0 is required.')
    spec = importlib.util.find_spec('cicflowmeter')
    source = Path(spec.origin).parent / 'sniffer.py'
    old = 'input_file, input_interface, output_mode, output, input_directory=None, fields=None, verbose=False'
    new = 'input_file, input_interface, output_mode, output, fields=None, verbose=False, input_directory=None'
    text = source.read_text(encoding='utf-8')
    if old in text:
        source.write_text(text.replace(old, new, 1), encoding='utf-8')
        return True
    if new not in text:
        raise ValueError('Unrecognized cicflowmeter signature; installed source was not modified.')
    return False


def convert_capture(source, destination, timeout=300):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    started = time.monotonic()
    patch_converter()
    executable = Path(sys.executable).parent / ('cicflowmeter.exe' if sys.platform == 'win32' else 'cicflowmeter')
    try:
        result = subprocess.run([str(executable), '-f', str(source), '-c', str(destination)],
                                capture_output=True, text=True, timeout=timeout, shell=False)
    except subprocess.TimeoutExpired as exc:
        raise ValueError('Capture conversion exceeded the five-minute limit.') from exc
    if result.returncode and 'tcpdump is not available' in result.stderr:
        # Windows without a capture driver: keep the same CICFlowMeter FlowSession,
        # replacing only the offline BPF reader with an equivalent packet predicate.
        try:
            result = subprocess.run([sys.executable, '-m', 'demo.helpers', str(source), str(destination)],
                                    cwd=Path(__file__).resolve().parents[1], capture_output=True,
                                    text=True, timeout=max(.01, timeout-(time.monotonic()-started)), shell=False)
        except subprocess.TimeoutExpired as exc:
            raise ValueError('Capture conversion exceeded the five-minute limit.') from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise ValueError('Capture conversion failed. Check that this is a valid supported capture. ' +
                         (detail[-1][:300] if detail else 'Converter returned a nonzero exit status.'))
    path = Path(destination)
    if not path.exists() or not path.stat().st_size:
        raise ValueError('Capture contains no supported IPv4 TCP/UDP flow records.')
    preview = pd.read_csv(path, nrows=1)
    if preview.empty or 'src_ip' not in preview or 'timestamp' not in preview:
        raise ValueError('Converter output lacks a valid header or flow records.')


def ingest_upload(payload, suffix, *, return_flows=False):
    if not payload:
        raise ValueError('The uploaded file is empty.')
    if len(payload) > 2 * 1024 * 1024 * 1024:
        raise ValueError('The upload exceeds 2 GB.')
    if suffix not in {'.csv', '.pcap', '.pcapng'}:
        raise ValueError('Choose a CSV, PCAP or PCAPNG file.')
    with tempfile.TemporaryDirectory(prefix='wm-demo-') as directory:
        source = Path(directory) / ('capture' + suffix)
        source.write_bytes(payload)
        csv = source if suffix == '.csv' else Path(directory) / 'flows.csv'
        if suffix != '.csv':
            convert_capture(source, csv)
        header = [str(c).strip() for c in pd.read_csv(csv, nrows=0).columns]
        kind, mapping = _detect_map(header)
        available = {mapping[c] for c in header if c in mapping}
        flows, cleaning = load_live_flows(csv, return_report=True, preserve_labels=True)
        windows = build_windows(flows)
        if windows.empty:
            raise ValueError('No usable timestamped host windows were found.')
        missing = [c for c in MODEL_COLUMNS if c not in windows]
        if missing:
            raise ValueError(f'Missing model columns: {missing}')
        values = windows[list(MODEL_COLUMNS)].to_numpy(dtype=float)
        if not np.isfinite(values).all():
            raise ValueError('Non-finite model features were produced.')
        catalog = host_catalog(windows)
        cleaning['windows_built'] = int(len(windows))
        cleaning['hosts'] = int(windows.entity_id.nunique())
        cleaning['hosts_with_history'] = int((catalog.forecasts > 0).sum())
        audit = {'column_map': kind, 'model_columns': len(MODEL_COLUMNS), 'finite': True,
                 'ground_truth': bool(cleaning.get('ground_truth', False)),
                 'cleaning': cleaning,
                 'nonzero_columns': int(np.any(values != 0, axis=0).sum()),
                 'all_zero_columns': [c for c, populated in zip(MODEL_COLUMNS, np.any(values != 0, axis=0)) if not populated],
                 'missing_source_fields': sorted(set(FLOW_FEATURE_COLUMNS)-available),
                 'packet_source_mappings': {s: {'target': t, 'present': s in header} for s,t in PACKET_MAP.items()}}
        return (windows, audit, flows) if return_flows else (windows, audit)


if __name__ == '__main__':
    from scapy.utils import PcapReader
    from cicflowmeter.flow_session import FlowSession
    session = FlowSession(output_mode='csv', output=sys.argv[2])
    with PcapReader(sys.argv[1]) as packets:
        for packet in packets:
            if 'IP' in packet and ('TCP' in packet or 'UDP' in packet):
                session.process(packet)
    session.flush_flows()
