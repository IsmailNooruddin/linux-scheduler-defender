"""
Real-Time inotify Watcher and Sliding-Window Burst Detector (Member B).

Project: Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?
Course:  Operating Systems (Term Project - Part 4), Section L4

Overview:
---------
This module is the "eyes" of the defender. It has two parts:

1. `BurstDetector`  - pure-Python sliding-window logic. It receives
   (filename, timestamp) pairs and answers one question: "have at least K
   DISTINCT files been modified within the last W milliseconds?"
   It does not touch the OS, so it can be unit-tested anywhere.

2. `SandboxMonitor` - wires the detector to the Linux kernel's `inotify`
   interface (via the tiny `inotify_simple` wrapper). It watches
   `<sandbox_root>/files/` for `IN_MODIFY` / `IN_CLOSE_WRITE` events and
   returns a `BurstResult` the moment the detector fires.

Why a sliding window on DISTINCT files?
---------------------------------------
  - Ransomware touches MANY different files in a short time.
  - Normal programs (our `benign_activity.py`) touch ONE file every ~0.75 s.
  - One logical write produces several inotify events (IN_MODIFY, then
    IN_CLOSE_WRITE) for the SAME file, so counting raw events would inflate
    the numbers. Counting distinct filenames avoids that.

Thresholds (K = BURST_EVENT_THRESHOLD, W = BURST_WINDOW_MS) come from
`config/experiment_config.py` and are never hardcoded here.

Known limitation (worth mentioning in the report/viva):
-------------------------------------------------------
inotify events carry NO timestamp. We stamp each event with
`time.monotonic_ns()` when the defender wakes up and reads it. If the defender
is CPU-starved, several events that happened at different times are stamped
with (almost) the same time. This is exactly the effect the experiment
measures: a starved defender reacts late.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Deque, Dict, Optional, Tuple

from config.experiment_config import (
    BURST_EVENT_THRESHOLD,
    BURST_WINDOW_MS,
    DEFENDER_POLL_TIMEOUT_MS,
)


# ==============================================================================
# 1. SLIDING-WINDOW BURST DETECTOR (pure logic, no OS calls)
# ==============================================================================

class BurstDetector:
    """
    Declare a burst when >= `threshold` DISTINCT files are modified within
    `window_ms` milliseconds.

    Data structures (both O(1) amortized per event):
      - `_events`: deque of (timestamp_ns, filename), oldest on the left.
      - `_counts`: dict filename -> number of events for it still inside the
        window. `len(_counts)` is therefore the number of distinct files.
    """

    def __init__(
        self,
        threshold: int = BURST_EVENT_THRESHOLD,
        window_ms: float = BURST_WINDOW_MS,
    ) -> None:
        if threshold < 1:
            raise ValueError(f"threshold must be >= 1 (got {threshold}).")
        if window_ms <= 0:
            raise ValueError(f"window_ms must be > 0 (got {window_ms}).")

        self.threshold: int = threshold
        self.window_ns: int = int(window_ms * 1_000_000)
        self._events: Deque[Tuple[int, str]] = deque()
        self._counts: Dict[str, int] = {}

    def _expire(self, now_ns: int) -> None:
        """Drop every event older than `now_ns - window_ns` from the window."""
        cutoff_ns = now_ns - self.window_ns
        while self._events and self._events[0][0] < cutoff_ns:
            _, old_name = self._events.popleft()
            remaining = self._counts[old_name] - 1
            if remaining:
                self._counts[old_name] = remaining
            else:
                del self._counts[old_name]

    def record(self, filename: str, now_ns: int) -> bool:
        """
        Register one modification event and report whether a burst is active.

        Parameters
        ----------
        filename : str
            Name of the modified file (relative to the watched directory).
        now_ns : int
            Timestamp of the event (`time.monotonic_ns()` clock).

        Returns
        -------
        bool
            True if >= `threshold` distinct files are inside the window.
        """
        self._expire(now_ns)
        self._events.append((now_ns, filename))
        self._counts[filename] = self._counts.get(filename, 0) + 1
        return len(self._counts) >= self.threshold

    @property
    def distinct_files(self) -> int:
        """Number of distinct files currently inside the window."""
        return len(self._counts)

    def reset(self) -> None:
        """Forget all events."""
        self._events.clear()
        self._counts.clear()


# ==============================================================================
# 2. RESULT RECORD
# ==============================================================================

@dataclass
class BurstResult:
    """What the monitor reports when it declares a ransomware burst."""

    detection_time_ns: int      # time.monotonic_ns() at the moment of declaration
    events_seen: int            # inotify MODIFY/CLOSE_WRITE events processed so far
    distinct_files: int         # distinct files inside the window at detection
    trigger_file: str           # file whose event completed the burst
    overflow: bool = False      # True if declared because the kernel queue overflowed


# ==============================================================================
# 3. inotify-BACKED MONITOR
# ==============================================================================

class SandboxMonitor:
    """
    Watch one directory with inotify and detect ransomware-style bursts.

    Usage:
        monitor = SandboxMonitor(files_dir)
        monitor.start()                      # watch is now ACTIVE (safe to signal "ready")
        result = monitor.wait_for_burst()    # blocks until burst / stop / deadline
        monitor.close()

    Note: inotify watches are NOT recursive; only files directly inside
    `files_dir` are watched. That is intentional - `telemetry/` and
    `manifest.json` live outside `files/`, so the project's own bookkeeping
    never triggers the defender.
    """

    def __init__(
        self,
        files_dir: Path | str,
        threshold: int = BURST_EVENT_THRESHOLD,
        window_ms: float = BURST_WINDOW_MS,
        poll_timeout_ms: int = DEFENDER_POLL_TIMEOUT_MS,
    ) -> None:
        self.files_dir = Path(files_dir)
        self.detector = BurstDetector(threshold=threshold, window_ms=window_ms)
        self.poll_timeout_ms = poll_timeout_ms
        self.events_seen: int = 0
        self._inotify = None  # created in start() so this module imports anywhere

    # -- lifecycle -------------------------------------------------------------

    def start(self) -> None:
        """Create the inotify instance and add the watch on `files_dir`."""
        # Imported lazily: `inotify_simple` only exists on Linux, and this keeps
        # BurstDetector importable/testable on any platform.
        from inotify_simple import INotify, flags

        if not self.files_dir.is_dir():
            raise FileNotFoundError(
                f"Cannot watch '{self.files_dir}': directory does not exist. "
                f"Run `python -m src.attacker.sandbox_setup --reset` first."
            )
        self._inotify = INotify()
        self._inotify.add_watch(str(self.files_dir), flags.MODIFY | flags.CLOSE_WRITE)

    def close(self) -> None:
        """Release the inotify file descriptor."""
        if self._inotify is not None:
            self._inotify.close()
            self._inotify = None

    def __enter__(self) -> "SandboxMonitor":
        self.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # -- main loop -------------------------------------------------------------

    def wait_for_burst(
        self,
        should_stop: Callable[[], bool] = lambda: False,
        deadline_ns: Optional[int] = None,
    ) -> Optional[BurstResult]:
        """
        Block until a burst is detected, `should_stop()` is True, or the
        deadline passes.

        The inotify read uses a short timeout (`DEFENDER_POLL_TIMEOUT_MS`), so
        `should_stop` and the deadline are re-checked at least every ~50 ms
        without any busy-waiting: the process sleeps inside the kernel
        (poll) until an event arrives, which keeps CPU use near zero.

        Returns
        -------
        BurstResult | None
            The burst description, or None if stopped / deadline reached.
        """
        if self._inotify is None:
            raise RuntimeError("SandboxMonitor.start() must be called first.")

        from inotify_simple import flags

        interesting = flags.MODIFY | flags.CLOSE_WRITE

        while not should_stop():
            if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
                return None

            events = self._inotify.read(timeout=self.poll_timeout_ms)
            if not events:
                continue

            # One timestamp per wake-up: inotify itself provides none.
            now_ns = time.monotonic_ns()

            for event in events:
                # Kernel event queue overflowed (defender was starved too long):
                # we lost events, so assume the worst and treat it as a burst.
                if event.mask & flags.Q_OVERFLOW:
                    return BurstResult(
                        detection_time_ns=time.monotonic_ns(),
                        events_seen=self.events_seen,
                        distinct_files=self.detector.distinct_files,
                        trigger_file="<Q_OVERFLOW>",
                        overflow=True,
                    )

                if not (event.mask & interesting) or not event.name:
                    continue

                self.events_seen += 1
                if self.detector.record(event.name, now_ns):
                    return BurstResult(
                        detection_time_ns=time.monotonic_ns(),
                        events_seen=self.events_seen,
                        distinct_files=self.detector.distinct_files,
                        trigger_file=event.name,
                    )

        return None
