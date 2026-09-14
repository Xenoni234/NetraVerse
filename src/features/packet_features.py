"""Packet-level features from PCAP, via a TShark wrapper.

Optional enrichment. The flow-level CSVs the public datasets ship are already
aggregated, which loses the fine timing structure that distinguishes, say, C2
beaconing from ordinary polling. Where raw PCAPs exist, this module extracts
sub-flow detail and merges it back onto the ``(entity, window)`` grid.

This path is **optional by design**: ``configs/dev.yaml`` sets
``features.use_packet_features: false`` so the whole pipeline runs without
Wireshark installed, and ``src/eval/ablations.py`` has a ``flow_only`` ablation
that measures whether these features pay for themselves.

Requirements
------------
System ``tshark`` binary on ``PATH`` (Wireshark), plus ``pyshark``. ``scapy`` is
the fallback for small captures where spawning TShark is not worth it.

TODO
----
* [ ] Implement ``tshark_available`` and make every public function degrade
      gracefully (return empty features + a warning) when it is False.
* [ ] Implement ``extract_pcap_features`` using ``tshark -T fields`` batch export
      rather than per-packet Python iteration — pyshark's live iteration is
      roughly two orders of magnitude slower.
* [ ] Implement ``beacon_score`` (IAT periodicity via autocorrelation or the
      coefficient of variation of inter-arrival times).
* [ ] Implement ``tls_handshake_features`` (JA3-ish: cipher-suite count, SNI
      presence, self-signed certs) — decide whether these enter the LOCKED
      schema or stay experimental.
* [ ] Align PCAP clock with flow CSV clock — the CIC captures are offset.
* [ ] Cache extracted packet features per PCAP so re-runs are cheap.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final, Iterator, Mapping, Sequence

import pandas as pd

#: TShark fields exported in the batch call. Keep in sync with the parser.
TSHARK_FIELDS: Final[tuple[str, ...]] = (
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.window_size_value",
    "udp.srcport",
    "udp.dstport",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
)

#: Columns this module contributes. Experimental until promoted into the
#: LOCKED FEATURE_COLUMNS list in unified_schema.
PACKET_FEATURE_COLUMNS: Final[tuple[str, ...]] = (
    "pkt_size_p50",
    "pkt_size_p95",
    "iat_cv",              # coefficient of variation of inter-arrival times
    "beacon_score",        # 0..1, higher = more periodic
    "tcp_window_mean",
    "tls_client_hello_count",
    "distinct_sni_count",
)


def tshark_available() -> bool:
    """Return whether a usable ``tshark`` binary is on ``PATH``.

    Every other function in this module must check this first and degrade to a
    warning plus empty features rather than raising — a teammate without
    Wireshark should still be able to run the pipeline.
    """
    raise NotImplementedError("TODO: shutil.which('tshark') + a version probe")


def extract_pcap_features(
    pcap_path: Path,
    *,
    window_seconds: int = 30,
    stride_seconds: int = 10,
    entity_granularity: str = "src_ip",
    cache_dir: Path | None = None,
) -> pd.DataFrame:
    """Extract :data:`PACKET_FEATURE_COLUMNS` per ``(entity, window)`` from a PCAP.

    Args:
        pcap_path: Capture file to read.
        window_seconds: Window span; must match the flow pipeline.
        stride_seconds: Window stride; must match the flow pipeline.
        entity_granularity: ``src_ip`` or ``src_dst_pair``.
        cache_dir: If given, memoise the TShark export here.

    Returns:
        Frame indexed by ``entity_id`` / ``window_start``, or an empty frame with
        the right columns when TShark is unavailable.
    """
    raise NotImplementedError("TODO: tshark batch export -> parse -> window -> aggregate")


def run_tshark(
    pcap_path: Path, fields: Sequence[str] = TSHARK_FIELDS, *, display_filter: str | None = None
) -> pd.DataFrame:
    """Run ``tshark -T fields`` over ``pcap_path`` and parse the TSV output.

    Batch export (one subprocess, streamed TSV) rather than per-packet Python
    iteration — the latter is far too slow for multi-GB captures.
    """
    raise NotImplementedError("TODO: subprocess with -T fields -E separator=/t, parse to frame")


def iter_packets_scapy(pcap_path: Path) -> Iterator[Mapping[str, object]]:
    """Fallback packet iterator using scapy, for small captures and tests."""
    raise NotImplementedError("TODO: scapy PcapReader yielding minimal packet dicts")


def beacon_score(inter_arrival_times: Sequence[float]) -> float:
    """Score how periodic a packet stream is, in ``[0, 1]``.

    Regular, low-variance inter-arrival times (classic C2 beaconing) score high;
    bursty human traffic scores low. Implement as ``1 - normalised CV``, or via
    autocorrelation peak strength if CV proves too noisy.
    """
    raise NotImplementedError("TODO: CV-based score, consider autocorrelation variant")


def tls_handshake_features(packets: pd.DataFrame) -> Mapping[str, float]:
    """Summarise TLS handshakes in a window (ClientHello count, distinct SNI)."""
    raise NotImplementedError("TODO: filter handshake types, count distinct SNI values")


def merge_packet_features(
    flow_features: pd.DataFrame, packet_features: pd.DataFrame
) -> pd.DataFrame:
    """Left-join packet features onto the flow feature grid.

    Windows with no packet coverage get 0.0, not NaN, and a ``has_pcap`` flag so
    the ablation can tell "absent" from "genuinely zero".
    """
    raise NotImplementedError("TODO: left join on (entity_id, window_start), fill 0.0")


def align_pcap_clock(packets: pd.DataFrame, offset_seconds: float) -> pd.DataFrame:
    """Shift packet timestamps to match the flow CSV clock.

    The CIC captures need a per-day offset; get it by cross-correlating packet
    volume against flow volume, then record it in ``docs/`` rather than guessing.
    """
    raise NotImplementedError("TODO: apply offset; add a helper to estimate it")


__all__ = [
    "TSHARK_FIELDS",
    "PACKET_FEATURE_COLUMNS",
    "tshark_available",
    "extract_pcap_features",
    "run_tshark",
    "iter_packets_scapy",
    "beacon_score",
    "tls_handshake_features",
    "merge_packet_features",
    "align_pcap_clock",
]
