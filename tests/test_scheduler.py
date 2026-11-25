"""
Verification tests for scheduler profiles and the trial runner (Member C).

Modules under test: src/scheduler/profiles.py, src/scheduler/runner.py

What these tests prove:
  * CPU-list parsing, per-setup control plans and cgroup v2 limit files are correct
    (cgroup writes are checked against a fake cgroup directory, so no root is needed).
  * Controls really take effect on a spawned process and are read back from the kernel
    (`verify_profile`), and a missing control is detected.
  * The real-time watchdog kills its target on time and can be cancelled.
  * The trial schedule is interleaved, complete and reproducible; CSV rows follow the shared schema.
  * A full trial (attack, undetected attack, solo baseline) works with a small stand-in defender,
    harness failures are reported as infrastructure errors (never as data), and nothing is left behind.

The runner tests use the real sandbox path (/tmp/os_defense_sandbox) because all modules share it,
so do not run them while a benchmark is running.

Run:  pytest -v tests/test_scheduler.py        (root-only tests are skipped without sudo)
"""

from __future__ import annotations

import csv
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import List

import psutil
import pytest

from config.experiment_config import RAW_CSV_COLUMNS, SCHEDULER_PARAMS, SCHEDULER_SETUPS
from src.scheduler import profiles, runner
from src.scheduler.profiles import ProfileError

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Scheduler tests need Linux (run them in WSL2).")

MULTI_CPU = hasattr(os, "sched_getaffinity") and len(os.sched_getaffinity(0)) >= 2


def _spawn_sleeper(seconds: int = 30, setup: str = "default", role: str = "defender") -> subprocess.Popen:
    return profiles.spawn_with_profile(["sleep", str(seconds)], setup, role)


def _reap(proc: subprocess.Popen) -> None:
    proc.kill()
    proc.wait(timeout=5)


# ==============================================================================
# profiles.py : parsing and planning
# ==============================================================================

def test_parse_cpu_list() -> None:
    assert profiles.parse_cpu_list("0") == [0]
    assert profiles.parse_cpu_list("1-3") == [1, 2, 3]
    assert profiles.parse_cpu_list("0,2-4, 7") == [0, 2, 3, 4, 7]
    for bad in ("", "3-1", "a", "1,,2"):
        with pytest.raises(ValueError):
            profiles.parse_cpu_list(bad)


def test_unknown_setup_or_role_is_rejected() -> None:
    with pytest.raises(ProfileError):
        profiles.plan_controls("not_a_setup", "defender")
    with pytest.raises(ProfileError):
        profiles.plan_controls("default", "attacker")


def test_plans_match_the_configured_traffic_rules() -> None:
    assert profiles.plan_controls("baseline_no_load", "defender") == {}
    assert profiles.plan_controls("nice", "defender") == {"nice": -20}
    assert profiles.plan_controls("nice", "workload") == {"nice": 19}

    chrt = profiles.plan_controls("chrt", "defender")
    assert chrt == {"rt": (os.SCHED_FIFO, 50)}
    assert profiles.plan_controls("chrt", "workload") == {}, "only the defender is real-time"

    for setup in profiles.CGROUP_SETUPS:
        defender = profiles.plan_controls(setup, "defender")
        workload = profiles.plan_controls(setup, "workload")
        assert defender["cgroup"] == "os_proj_defender"
        assert workload["cgroup"] == "os_proj_workload"
        assert defender["cgroup_procs"].endswith("os_proj_defender/cgroup.procs")


def test_taskset_plan_pins_defender_and_workload_to_disjoint_cores(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(profiles, "available_cpus", lambda: [0, 1, 2, 3])
    monkeypatch.setitem(SCHEDULER_PARAMS["taskset"], "defender_cores", "0")
    monkeypatch.setitem(SCHEDULER_PARAMS["taskset"], "workload_cores", "1-3")
    assert profiles.plan_controls("taskset", "defender") == {"cores": [0]}
    assert profiles.plan_controls("taskset", "workload") == {"cores": [1, 2, 3]}

    monkeypatch.setitem(SCHEDULER_PARAMS["taskset"], "workload_cores", "0-3")  # overlaps the defender
    with pytest.raises(ProfileError):
        profiles.taskset_core_plan()

    monkeypatch.setattr(profiles, "available_cpus", lambda: [0])  # a single core cannot be split
    with pytest.raises(ProfileError):
        profiles.taskset_core_plan()


def test_cgroup_quota_is_a_share_of_all_cores() -> None:
    assert profiles.workload_cpu_quota_us(total_cpus=4) == (200_000, 100_000)  # 50% of 4 cores = 2 cores' worth
    assert profiles.workload_cpu_quota_us(total_cpus=1) == (50_000, 100_000)
    assert profiles.workload_cpu_quota_us(total_cpus=16)[0] == 800_000


# ==============================================================================
# profiles.py : cgroup v2 files (fake cgroup root, no privileges needed)
# ==============================================================================

@pytest.fixture()
def fake_cgroup_root(tmp_path: Path) -> Path:
    (tmp_path / "cgroup.controllers").write_text("cpu io memory pids\n")
    (tmp_path / "cgroup.subtree_control").write_text("")
    return tmp_path


def test_cgroup_v2_status_detects_missing_hierarchy_and_missing_cpu(tmp_path: Path) -> None:
    ok, reason = profiles.cgroup_v2_status(tmp_path)
    assert not ok and "cgroup_no_v1=all" in reason  # tells the user the WSL2 fix

    (tmp_path / "cgroup.controllers").write_text("io memory\n")
    ok, reason = profiles.cgroup_v2_status(tmp_path)
    assert not ok and "cpu controller" in reason


def test_cgroup_weight_setup_writes_weights_1000_vs_100(fake_cgroup_root: Path) -> None:
    written = profiles.configure_cgroups("cgroup_weight", fake_cgroup_root)
    assert (fake_cgroup_root / "cgroup.subtree_control").read_text() == "+cpu"
    assert written["os_proj_defender/cpu.weight"] == "1000"
    assert written["os_proj_workload/cpu.weight"] == "100"
    assert written["os_proj_defender/cpu.max"] == "max 100000"
    assert written["os_proj_workload/cpu.max"] == "max 100000"


def test_cgroup_max_caps_only_the_workload_and_resets_previous_weights(fake_cgroup_root: Path) -> None:
    profiles.configure_cgroups("cgroup_weight", fake_cgroup_root)
    written = profiles.configure_cgroups("cgroup_max", fake_cgroup_root)  # must not inherit weight 1000
    quota_us, period_us = profiles.workload_cpu_quota_us()
    assert written["os_proj_workload/cpu.max"] == f"{quota_us} {period_us}"
    assert written["os_proj_defender/cpu.max"] == "max 100000"
    assert written["os_proj_defender/cpu.weight"] == "100"
    assert written["os_proj_workload/cpu.weight"] == "100"


def test_configure_cgroups_rejects_non_cgroup_setups(fake_cgroup_root: Path) -> None:
    with pytest.raises(ProfileError):
        profiles.configure_cgroups("nice", fake_cgroup_root)


# ==============================================================================
# profiles.py : controls on real processes
# ==============================================================================

def test_spawned_process_gets_nice_value_and_it_is_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(SCHEDULER_PARAMS["nice"], "defender_nice", 7)  # raising nice needs no root
    proc = _spawn_sleeper(setup="nice", role="defender")
    try:
        time.sleep(0.1)
        assert profiles.describe_process(proc.pid)["nice"] == 7
        assert profiles.verify_profile("nice", "defender", proc.pid) == []
    finally:
        _reap(proc)


def test_verify_profile_detects_a_control_that_did_not_take_effect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(SCHEDULER_PARAMS["nice"], "defender_nice", 7)
    plain = subprocess.Popen(["sleep", "30"])  # started WITHOUT the profile
    try:
        problems = profiles.verify_profile("nice", "defender", plain.pid)
        assert problems and "expected nice 7" in problems[0]
    finally:
        _reap(plain)


def test_apply_to_running_process_and_its_children(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(SCHEDULER_PARAMS["nice"], "workload_nice", 9)
    parent = subprocess.Popen(["sh", "-c", "sleep 30 & wait"])
    try:
        time.sleep(0.3)
        pids = profiles.apply_to_pid("nice", "workload", parent.pid)
        assert len(pids) == 2  # the shell and its sleep child
        assert profiles.verify_profile("nice", "workload", parent.pid, include_children=True) == []
    finally:
        for child in psutil.Process(parent.pid).children(recursive=True):
            child.kill()
        _reap(parent)


@pytest.mark.skipif(not MULTI_CPU, reason="core pinning needs at least 2 CPU cores")
def test_taskset_pins_process_to_requested_core(monkeypatch: pytest.MonkeyPatch) -> None:
    cpus = sorted(os.sched_getaffinity(0))
    monkeypatch.setitem(SCHEDULER_PARAMS["taskset"], "defender_cores", str(cpus[0]))
    monkeypatch.setitem(SCHEDULER_PARAMS["taskset"], "workload_cores", ",".join(str(c) for c in cpus[1:]))
    proc = _spawn_sleeper(setup="taskset", role="defender")
    try:
        time.sleep(0.1)
        assert profiles.describe_process(proc.pid)["cores"] == [cpus[0]]
        assert profiles.verify_profile("taskset", "defender", proc.pid) == []
    finally:
        _reap(proc)


@pytest.mark.skipif(
    not (profiles.is_root() and profiles.rt_throttling_enabled()),
    reason="real-time scheduling needs root and kernel RT throttling",
)
def test_chrt_gives_defender_sched_fifo_priority_50_and_negative_nice_works() -> None:
    proc = _spawn_sleeper(setup="chrt", role="defender")
    try:
        time.sleep(0.1)
        state = profiles.describe_process(proc.pid)
        assert (state["policy"], state["rt_priority"]) == ("SCHED_FIFO", 50)
        assert profiles.verify_profile("chrt", "defender", proc.pid) == []
    finally:
        _reap(proc)

    proc = _spawn_sleeper(setup="nice", role="defender")
    try:
        time.sleep(0.1)
        assert profiles.describe_process(proc.pid)["nice"] == -20
    finally:
        _reap(proc)


def test_preflight_demands_root_for_privileged_setups(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(profiles, "is_root", lambda: False)
    for setup in ("nice", "chrt", "cgroup_weight", "cgroup_max"):
        with pytest.raises(ProfileError, match="needs root"):
            profiles.preflight(setup)


def test_preflight_refuses_realtime_when_throttling_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(profiles, "is_root", lambda: True)
    monkeypatch.setattr(profiles, "rt_throttling_enabled", lambda: False)
    with pytest.raises(ProfileError, match="Refusing to run real-time"):
        profiles.preflight("chrt")


def test_watchdog_kills_target_on_time_and_can_be_cancelled() -> None:
    target = subprocess.Popen(["sleep", "30"])
    watchdog = profiles.start_watchdog([target.pid], timeout_s=0.5, realtime=False)
    t0 = time.monotonic()
    target.wait(timeout=10)
    assert target.returncode == -signal.SIGKILL
    assert 0.3 <= time.monotonic() - t0 <= 3.0
    profiles.stop_watchdog(watchdog)

    survivor = subprocess.Popen(["sleep", "30"])
    watchdog = profiles.start_watchdog([survivor.pid], timeout_s=0.5, realtime=False)
    profiles.stop_watchdog(watchdog)  # cancelled before it fires
    time.sleep(1.0)
    try:
        assert survivor.poll() is None, "a cancelled watchdog must not kill its target"
    finally:
        _reap(survivor)


# ==============================================================================
# runner.py : schedule, CSV, helpers
# ==============================================================================

def test_schedule_is_complete_interleaved_and_reproducible() -> None:
    setups = ["baseline_workload_solo", "default", "nice"]
    schedule = runner.build_schedule(setups, trials=4, benign_trials=2, seed=1)

    assert schedule == runner.build_schedule(setups, trials=4, benign_trials=2, seed=1)
    assert schedule != runner.build_schedule(setups, trials=4, benign_trials=2, seed=2)
    assert len(schedule) == len(set(schedule)), "no trial may be scheduled twice"

    count = lambda s, m: sum(1 for (su, _t, mo) in schedule if su == s and mo == m)  # noqa: E731
    assert count("default", "attack") == 4 and count("nice", "attack") == 4
    assert count("default", "benign") == 2 and count("nice", "benign") == 2
    assert count("baseline_workload_solo", "solo") == 4
    assert count("baseline_workload_solo", "attack") == 0 and count("baseline_workload_solo", "benign") == 0

    # Interleaved: round 1 finishes (all setups) before any round-2 attack trial starts.
    first_round2 = min(i for i, (_s, tid, mo) in enumerate(schedule) if tid == 2 and mo != "benign")
    assert all(tid == 1 for (_s, tid, mo) in schedule[:first_round2] if mo != "benign")


def test_valid_modes() -> None:
    assert runner.valid_modes("baseline_workload_solo") == ["solo"]
    for setup in SCHEDULER_SETUPS:
        if setup != "baseline_workload_solo":
            assert runner.valid_modes(setup) == ["attack", "benign"]


def test_append_row_writes_header_once_and_follows_schema(tmp_path: Path) -> None:
    out = tmp_path / "trials.csv"
    row = runner._blank_row("default", 1, "attack")
    row.update(detected=True, detection_delay_ms=12.5, files_damaged=5, total_decoy_files=300, workload_throughput=140.1)
    runner.append_row(out, row)
    runner.append_row(out, runner._blank_row("baseline_workload_solo", 1, "solo"))

    rows = list(csv.DictReader(out.open()))
    assert tuple(rows[0].keys()) == RAW_CSV_COLUMNS
    assert out.read_text().count("setup,trial_id") == 1
    assert rows[0]["detected"] == "True" and rows[0]["detection_delay_ms"] == "12.5"
    assert rows[1]["detection_delay_ms"] == "" and rows[1]["files_damaged"] == ""  # not applicable -> blank


def test_proc_state_sees_sigstop() -> None:
    proc = subprocess.Popen(["sleep", "30"])
    try:
        time.sleep(0.1)
        assert not runner._is_stopped(proc.pid)
        os.kill(proc.pid, signal.SIGSTOP)
        time.sleep(0.1)
        assert runner._is_stopped(proc.pid)
    finally:
        _reap(proc)
    assert runner._proc_state(proc.pid) is None


# ==============================================================================
# runner.py : whole trials with a stand-in defender
# ==============================================================================

STAND_IN_DEFENDER = textwrap.dedent(
    '''
    """Minimal stand-in for Member B's defender, used only to test the runner."""
    import json, os, signal, sys, time
    sys.path.insert(0, {repo!r})
    from inotify_simple import INotify, flags
    from config.experiment_config import *

    stop = False
    def _term(*_):
        global stop
        stop = True
    signal.signal(signal.SIGTERM, _term)

    MODE = sys.argv[1]  # "guard" = detect bursts, "lazy" = never reacts, "crash" = dies at start, "no_target" = triggers without freezing
    if MODE == "crash":
        sys.exit(3)
    inotify = INotify()
    inotify.add_watch(str(SANDBOX_FILES_DIR), flags.MODIFY | flags.CLOSE_WRITE)
    DEFENDER_READY_FLAG.write_text("ready")
    window, events = [], 0
    while not stop:
        for ev in inotify.read(timeout=DEFENDER_POLL_TIMEOUT_MS):
            if MODE not in ("guard", "no_target") or not ev.name.startswith(DECOY_FILE_PREFIX):
                continue
            events += 1
            now = time.monotonic_ns()
            window = [(t, n) for t, n in window + [(now, ev.name)] if now - t <= BURST_WINDOW_MS * 1e6]
            if len({{n for _, n in window}}) >= BURST_EVENT_THRESHOLD:
                detection = time.monotonic_ns()
                if MODE == "no_target":
                    DEFENDER_TELEMETRY_PATH.write_text(json.dumps(dict(
                        detection_time_ns=detection, freeze_time_ns=None, frozen_pid=None,
                        events_seen=events, triggered=True, status="burst_no_target")))
                    sys.exit(0)
                pid = json.loads(ATTACKER_TELEMETRY_PATH.read_text())["pid"]
                os.kill(pid, signal.SIGSTOP)
                freeze = time.monotonic_ns()
                DEFENDER_TELEMETRY_PATH.write_text(json.dumps(dict(
                    detection_time_ns=detection, freeze_time_ns=freeze, frozen_pid=pid,
                    events_seen=events, triggered=True)))
                while not stop:
                    time.sleep(0.05)
                sys.exit(0)
    '''
)

try:
    import inotify_simple  # noqa: F401
    HAVE_INOTIFY = True
except ImportError:
    HAVE_INOTIFY = False

needs_inotify = pytest.mark.skipif(not HAVE_INOTIFY, reason="inotify_simple not installed")


@pytest.fixture()
def stand_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Return a function mode -> defender command, with a short measurement window for fast tests."""
    from config.experiment_config import REPO_ROOT

    script = tmp_path / "stand_in_defender.py"
    script.write_text(STAND_IN_DEFENDER.format(repo=str(REPO_ROOT)))
    monkeypatch.setattr(runner, "MIN_WORKLOAD_WINDOW_S", 1.0)
    monkeypatch.setattr(runner, "MAX_INFRA_RETRIES", 0)
    yield lambda mode: [sys.executable, str(script), mode]
    assert runner.find_stale_project_processes() == [], "a trial left processes behind"
    assert not [c for c in psutil.Process().children(recursive=True) if c.status() == psutil.STATUS_ZOMBIE]


@needs_inotify
def test_attack_trial_is_detected_frozen_and_measured(stand_in) -> None:
    row = runner.run_trial("default", 1, "attack", stand_in("guard"))
    assert row["detected"] is True and row["false_alarm"] is False and row["timed_out"] is False
    assert 0 < row["detection_delay_ms"] < 2_000
    assert 1 <= row["files_damaged"] < 300, "the defender must stop the attack long before it finishes"
    assert row["total_decoy_files"] == 300
    assert row["workload_throughput"] > 0


@needs_inotify
def test_undetected_attack_is_recorded_as_data_not_as_an_error(stand_in) -> None:
    row = runner.run_trial("default", 1, "attack", stand_in("lazy"))
    assert row["detected"] is False and row["detection_delay_ms"] is None
    assert row["files_damaged"] == 300
    assert "undetected" in row["notes"]


@needs_inotify
def test_benign_trial_with_guard_has_no_false_alarm(stand_in) -> None:
    # Note: benign_activity runs in a child subprocess using BENIGN_DURATION_S from config.
    row = runner.run_trial("default", 1, "benign", stand_in("guard"))
    assert row["false_alarm"] is False and row["detected"] is False
    assert row["files_damaged"] == 0


@needs_inotify
def test_solo_trial_measures_only_workload_throughput(stand_in) -> None:
    row = runner.run_trial("baseline_workload_solo", 1, "solo", stand_in("guard"))
    assert row["workload_throughput"] > 0
    assert row["detection_delay_ms"] is None and row["files_damaged"] is None and row["detected"] is False


@needs_inotify
def test_burst_without_frozen_target_is_not_counted_as_detected(stand_in) -> None:
    row = runner.run_trial("default", 1, "attack", stand_in("no_target"))
    assert row["detected"] is False and row["detection_delay_ms"] is None
    assert row["files_damaged"] == 300
    assert "burst_no_target" in row["notes"]


@needs_inotify
def test_broken_defender_is_a_harness_error_never_a_csv_row(stand_in) -> None:
    with pytest.raises(runner.TrialInfrastructureError, match="exited before becoming ready"):
        runner.run_trial("default", 1, "attack", stand_in("crash"))
