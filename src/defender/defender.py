"""
TODO: To be implemented by Member B (Hassaan Ul Qadir).

Module: src/defender/defender.py
Purpose:
  - Create `DEFENDER_READY_FLAG` once the `inotify` watch is active.
  - On burst detection from `monitor.py`, identify the active attacker PID
    and immediately freeze it using `os.kill(attacker_pid, signal.SIGSTOP)`.
  - Write detection telemetry (`detection_time_ns`, `freeze_time_ns`, `frozen_pid`,
    `triggered`) to `DEFENDER_TELEMETRY_PATH`.
"""
