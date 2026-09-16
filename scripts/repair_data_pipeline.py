"""Rebuild CIC-IDS2017 windows with audited clocks and immutable source metadata."""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.data import loaders, unified_schema, labeller, windowing as W
from src.data.paths import PROCESSED_DIR, RAW_DIR, REPORTS_DIR
from src.eval import splits as S


def main() -> None:
    source = RAW_DIR / 'CIC-IDS2017' / 'TrafficLabelling'
    manifest = {"pipeline": "clock-repair-v2", "sources": [
        {"name": p.name, "size": p.stat().st_size, "mtime_ns": p.stat().st_mtime_ns}
        for p in sorted(source.glob('*.csv'))]}
    key = hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()[:12]
    frames, audit = [], {}
    for day in loaders.CICIDS2017_WEEKDAYS:
        target = PROCESSED_DIR / f'windows_repaired_{day}_{key}.parquet'
        start = time.perf_counter()
        if target.exists():
            windows = pd.read_parquet(target)
        else:
            raw = loaders.load_cicids2017(day)
            flows = labeller.label_frame(unified_schema.to_unified(raw,'cicids2017'),dataset='cicids2017',add_distance=False)
            del raw
            windows = W.build_windows(flows)
            del flows
            windows.to_parquet(target,index=False)
        frames.append(windows)
        audit[day] = {"windows": len(windows), "attacks": int(windows.binary_label.sum()),
                      "start": str(windows.window_start.min()), "end": str(windows.window_start.max())}
        print(f'[rebuild] {day}: {audit[day]} elapsed={time.perf_counter()-start:.1f}s',flush=True)
    windows = pd.concat(frames,ignore_index=True)
    destination = PROCESSED_DIR / 'windows_repaired_cicids2017_v2.parquet'
    windows.to_parquet(destination,index=False)
    manifest['audit'] = audit
    destination.with_suffix('.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    splits = S.chronological_split(windows,config=S.SplitConfig(time_col='window_start'))
    for name,frame in splits.items():
        batch = W.build_sequences(frame)
        W.save_sequences(batch,PROCESSED_DIR / f'repaired_{name}_v2.npz')
        print(f'[sequences] {name}: {len(batch.x)} positives={batch.y_risk.sum(0).tolist()}',flush=True)
        masked = W.build_sequences(frame,W.WindowConfig(history_policy='masked'))
        W.save_sequences(masked,PROCESSED_DIR / f'repaired_{name}_masked_v2.npz')
        print(f'[masked] {name}: {len(masked.x)} positives={masked.y_risk.sum(0).tolist()}',flush=True)
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR/'pipeline_repair_audit.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('[done]',destination,flush=True)


if __name__ == '__main__':
    main()
