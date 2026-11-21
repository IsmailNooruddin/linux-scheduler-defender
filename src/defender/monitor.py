"""
TODO: To be implemented by Member B (Hassaan Ul Qadir).

Module: src/defender/monitor.py
Purpose:
  - Watch `SANDBOX_FILES_DIR` (/tmp/os_defense_sandbox/files) using `inotify_simple`.
  - Track file-write events inside a sliding window of `BURST_WINDOW_MS` (500 ms).
  - Trigger a burst alert when >= `BURST_EVENT_THRESHOLD` (5) distinct decoy files
    are modified within the window, while ignoring slow edits from `benign_activity.py`.
"""
