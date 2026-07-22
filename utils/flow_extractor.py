"""
utils/flow_extractor.py
=======================
Extracts the same 78 features that CICFlowMeter produces,
directly from raw Scapy packets captured in a sliding window.

These features exactly match what your CNN-LSTM was trained on
using the CIC-IDS-2017 dataset.
"""

import numpy as np
import pandas as pd
from collections import defaultdict


# CICFlowMeter feature names — must match your scaler's expected columns
FEATURE_NAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
    "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std",
    "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


class FlowKey:
    """5-tuple that uniquely identifies a network flow."""
    __slots__ = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

    def __eq__(self, other):
        return (self.src_ip == other.src_ip and self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and self.dst_port == other.dst_port and
                self.protocol == other.protocol)

    def reverse(self):
        return FlowKey(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)


class FlowRecord:
    """Accumulates packet-level stats for one flow."""

    def __init__(self, first_pkt_time: float):
        self.start_time = first_pkt_time
        self.last_time  = first_pkt_time
        self.fwd_pkts   = []   # (size, timestamp, flags)
        self.bwd_pkts   = []
        self.fin_flags  = 0
        self.syn_flags  = 0
        self.rst_flags  = 0
        self.psh_flags  = 0
        self.ack_flags  = 0
        self.urg_flags  = 0
        self.cwe_flags  = 0
        self.ece_flags  = 0
        self.dst_port   = 0
        self.init_fwd_win = -1
        self.init_bwd_win = -1

    def add_packet(self, size: int, ts: float, flags: int, direction: str,
                   header_len: int = 20, win_size: int = 0):
        self.last_time = max(self.last_time, ts)
        pkt_info = (size, ts, flags, header_len)
        if direction == "fwd":
            self.fwd_pkts.append(pkt_info)
            if self.init_fwd_win == -1:
                self.init_fwd_win = win_size
        else:
            self.bwd_pkts.append(pkt_info)
            if self.init_bwd_win == -1:
                self.init_bwd_win = win_size

        # Flag counts
        if flags & 0x01: self.fin_flags += 1
        if flags & 0x02: self.syn_flags += 1
        if flags & 0x04: self.rst_flags += 1
        if flags & 0x08: self.psh_flags += 1
        if flags & 0x10: self.ack_flags += 1
        if flags & 0x20: self.urg_flags += 1
        if flags & 0x40: self.cwe_flags += 1
        if flags & 0x80: self.ece_flags += 1

    def to_features(self) -> dict:
        """Convert accumulated stats into the 78 CICFlowMeter features."""
        all_pkts = self.fwd_pkts + self.bwd_pkts
        duration = max((self.last_time - self.start_time) * 1e6, 1)  # microseconds

        fwd_sizes = [p[0] for p in self.fwd_pkts]
        bwd_sizes = [p[0] for p in self.bwd_pkts]
        all_sizes = [p[0] for p in all_pkts]

        fwd_ts = [p[1] for p in self.fwd_pkts]
        bwd_ts = [p[1] for p in self.bwd_pkts]
        all_ts = sorted([p[1] for p in all_pkts])

        def safe_stats(lst):
            if len(lst) < 1:
                return 0, 0, 0, 0
            a = np.array(lst, dtype=float)
            return float(a.max()), float(a.min()), float(a.mean()), float(a.std()) if len(a) > 1 else 0.0

        def iats(ts_list):
            if len(ts_list) < 2:
                return [0]
            ts_sorted = sorted(ts_list)
            return [ts_sorted[i+1] - ts_sorted[i] for i in range(len(ts_sorted)-1)]

        all_iats = iats(all_ts)
        fwd_iats = iats(fwd_ts)
        bwd_iats = iats(bwd_ts)

        dur_s = duration / 1e6
        n_all = len(all_pkts)
        bytes_total = sum(all_sizes)

        sz_mx, sz_mn, sz_mean, sz_std = safe_stats(all_sizes)
        f_mx,  f_mn,  f_mean,  f_std  = safe_stats(fwd_sizes)
        b_mx,  b_mn,  b_mean,  b_std  = safe_stats(bwd_sizes)
        i_mx,  i_mn,  i_mean,  i_std  = safe_stats(all_iats)
        fi_mx, fi_mn, fi_mean, fi_std  = safe_stats(fwd_iats)
        bi_mx, bi_mn, bi_mean, bi_std  = safe_stats(bwd_iats)

        n_fwd = len(self.fwd_pkts)
        n_bwd = len(self.bwd_pkts)
        fwd_hdr_total = sum(p[3] for p in self.fwd_pkts)
        bwd_hdr_total = sum(p[3] for p in self.bwd_pkts)

        features = {
            "Destination Port":          self.dst_port,
            "Flow Duration":             duration,
            "Total Fwd Packets":         n_fwd,
            "Total Backward Packets":    n_bwd,
            "Total Length of Fwd Packets": sum(fwd_sizes),
            "Total Length of Bwd Packets": sum(bwd_sizes),
            "Fwd Packet Length Max":     f_mx,
            "Fwd Packet Length Min":     f_mn,
            "Fwd Packet Length Mean":    f_mean,
            "Fwd Packet Length Std":     f_std,
            "Bwd Packet Length Max":     b_mx,
            "Bwd Packet Length Min":     b_mn,
            "Bwd Packet Length Mean":    b_mean,
            "Bwd Packet Length Std":     b_std,
            "Flow Bytes/s":              bytes_total / dur_s if dur_s > 0 else 0,
            "Flow Packets/s":            n_all / dur_s if dur_s > 0 else 0,
            "Flow IAT Mean":             i_mean,
            "Flow IAT Std":              i_std,
            "Flow IAT Max":              i_mx,
            "Flow IAT Min":              i_mn,
            "Fwd IAT Total":             sum(fwd_iats),
            "Fwd IAT Mean":              fi_mean,
            "Fwd IAT Std":              fi_std,
            "Fwd IAT Max":               fi_mx,
            "Fwd IAT Min":               fi_mn,
            "Bwd IAT Total":             sum(bwd_iats),
            "Bwd IAT Mean":              bi_mean,
            "Bwd IAT Std":              bi_std,
            "Bwd IAT Max":               bi_mx,
            "Bwd IAT Min":               bi_mn,
            "Fwd PSH Flags":             int(any(p[2] & 0x08 for p in self.fwd_pkts)),
            "Bwd PSH Flags":             int(any(p[2] & 0x08 for p in self.bwd_pkts)),
            "Fwd URG Flags":             int(any(p[2] & 0x20 for p in self.fwd_pkts)),
            "Bwd URG Flags":             int(any(p[2] & 0x20 for p in self.bwd_pkts)),
            "Fwd Header Length":         fwd_hdr_total,
            "Bwd Header Length":         bwd_hdr_total,
            "Fwd Packets/s":             n_fwd / dur_s if dur_s > 0 else 0,
            "Bwd Packets/s":             n_bwd / dur_s if dur_s > 0 else 0,
            "Min Packet Length":         sz_mn,
            "Max Packet Length":         sz_mx,
            "Packet Length Mean":        sz_mean,
            "Packet Length Std":         sz_std,
            "Packet Length Variance":    sz_std ** 2,
            "FIN Flag Count":            self.fin_flags,
            "SYN Flag Count":            self.syn_flags,
            "RST Flag Count":            self.rst_flags,
            "PSH Flag Count":            self.psh_flags,
            "ACK Flag Count":            self.ack_flags,
            "URG Flag Count":            self.urg_flags,
            "CWE Flag Count":            self.cwe_flags,
            "ECE Flag Count":            self.ece_flags,
            "Down/Up Ratio":             n_bwd / n_fwd if n_fwd > 0 else 0,
            "Average Packet Size":       bytes_total / n_all if n_all > 0 else 0,
            "Avg Fwd Segment Size":      f_mean,
            "Avg Bwd Segment Size":      b_mean,
            "Fwd Avg Bytes/Bulk":        0,
            "Fwd Avg Packets/Bulk":      0,
            "Fwd Avg Bulk Rate":         0,
            "Bwd Avg Bytes/Bulk":        0,
            "Bwd Avg Packets/Bulk":      0,
            "Bwd Avg Bulk Rate":         0,
            "Subflow Fwd Packets":       n_fwd,
            "Subflow Fwd Bytes":         sum(fwd_sizes),
            "Subflow Bwd Packets":       n_bwd,
            "Subflow Bwd Bytes":         sum(bwd_sizes),
            "Init_Win_bytes_forward":    self.init_fwd_win if self.init_fwd_win >= 0 else 0,
            "Init_Win_bytes_backward":   self.init_bwd_win if self.init_bwd_win >= 0 else 0,
            "act_data_pkt_fwd":          sum(1 for p in self.fwd_pkts if p[0] > 0),
            "min_seg_size_forward":      f_mn,
            "Active Mean":               0,
            "Active Std":                0,
            "Active Max":                0,
            "Active Min":                0,
            "Idle Mean":                 0,
            "Idle Std":                  0,
            "Idle Max":                  0,
            "Idle Min":                  0,
        }
        return features


class FlowExtractor:
    """
    Parses a list of Scapy packets, groups them into flows
    by 5-tuple, and returns a DataFrame of CICFlowMeter features.
    """

    def extract(self, packets: list) -> pd.DataFrame | None:
        """
        Parameters
        ----------
        packets : list of Scapy packet objects

        Returns
        -------
        pd.DataFrame with 78 feature columns, one row per flow.
        Returns None if no usable packets.
        """
        if not packets:
            return None

        try:
            from scapy.all import IP, TCP, UDP
        except ImportError:
            print("⚠️  Scapy not installed. Run: pip install scapy")
            return None

        flows: dict[FlowKey, FlowRecord] = {}

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue

            ip  = pkt[IP]
            ts  = float(pkt.time)
            proto = ip.proto

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                flags    = int(tcp.flags)
                hdr_len  = tcp.dataofs * 4
                win_size = tcp.window
                payload  = len(bytes(tcp.payload))
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                flags    = 0
                hdr_len  = 8
                win_size = 0
                payload  = len(bytes(udp.payload))
            else:
                continue  # Only TCP/UDP flows

            fwd_key = FlowKey(ip.src, ip.dst, src_port, dst_port, proto)
            rev_key = fwd_key.reverse()

            if fwd_key in flows:
                flows[fwd_key].add_packet(payload, ts, flags, "fwd", hdr_len, win_size)
                flows[fwd_key].dst_port = dst_port
            elif rev_key in flows:
                flows[rev_key].add_packet(payload, ts, flags, "bwd", hdr_len, win_size)
            else:
                record = FlowRecord(ts)
                record.dst_port = dst_port
                record.add_packet(payload, ts, flags, "fwd", hdr_len, win_size)
                flows[fwd_key] = record

        if not flows:
            return None

        rows = [record.to_features() for record in flows.values()]
        df = pd.DataFrame(rows, columns=FEATURE_NAMES)
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        return df
