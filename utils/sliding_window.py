"""
utils/sliding_window.py
=======================
Groups captured packets into fixed-size time windows.
When a window closes (after window_seconds), all buffered packets
are flushed for feature extraction and prediction.
"""

import time
import threading
from collections import deque


class SlidingWindowBuffer:
    """
    Thread-safe sliding window that accumulates Scapy packets.

    Usage
    -----
    window = SlidingWindowBuffer(window_seconds=5)

    # In packet handler:
    window.add_packet(pkt)
    if window.is_ready():
        packets = window.flush()   # returns list, resets buffer
        # ... extract features and predict on `packets`
    """

    def __init__(self, window_seconds: int = 5):
        self.window_seconds = window_seconds
        self._lock          = threading.Lock()
        self._buffer        = deque()
        self._window_start  = time.time()

    def add_packet(self, pkt) -> None:
        """Add a Scapy packet to the current window."""
        with self._lock:
            self._buffer.append(pkt)

    def is_ready(self) -> bool:
        """Return True when the current window has elapsed."""
        return (time.time() - self._window_start) >= self.window_seconds

    def flush(self) -> list:
        """
        Close the current window, return all buffered packets,
        and start a new window. Thread-safe.
        """
        with self._lock:
            packets = list(self._buffer)
            self._buffer.clear()
            self._window_start = time.time()
        return packets

    def size(self) -> int:
        """Current number of packets in the buffer."""
        with self._lock:
            return len(self._buffer)

    def elapsed(self) -> float:
        """Seconds elapsed since the current window started."""
        return time.time() - self._window_start


class AdaptiveWindowBuffer(SlidingWindowBuffer):
    """
    Extended version that auto-adjusts window size based on traffic volume.

    - High traffic (> max_pkts_per_window): shrinks window to 2s for faster detection
    - Low traffic (< min_pkts_per_window):  grows window to 10s to gather enough flows
    - Normal traffic: uses the default window_seconds
    """

    def __init__(
        self,
        window_seconds:     int = 5,
        min_window:         int = 2,
        max_window:         int = 10,
        min_pkts_per_window: int = 10,
        max_pkts_per_window: int = 500,
    ):
        super().__init__(window_seconds)
        self.min_window          = min_window
        self.max_window          = max_window
        self.min_pkts_per_window = min_pkts_per_window
        self.max_pkts_per_window = max_pkts_per_window
        self._last_flush_count   = 0

    def flush(self) -> list:
        packets = super().flush()
        count   = len(packets)

        # Adapt window size for next cycle
        if count > self.max_pkts_per_window:
            self.window_seconds = max(self.min_window, self.window_seconds - 1)
        elif count < self.min_pkts_per_window:
            self.window_seconds = min(self.max_window, self.window_seconds + 1)

        self._last_flush_count = count
        return packets

    @property
    def last_count(self) -> int:
        return self._last_flush_count
