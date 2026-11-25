"""
Linux Scheduler Profile Wrappers (Member C).

Project: Can Linux Scheduler Controls Keep a Defender Fast Under CPU Load?
Course:  Operating Systems (Term Project - Part 4), Section L4
Author:  Munir Tariq (Member C)

Overview:
---------
This module turns each row of `SCHEDULER_PARAMS` (the "traffic rules" table in
`config/experiment_config.py`) into real Linux scheduling controls applied to the
two processes whose CPU share we want to steer:

    role "defender" : Member B's inotify + SIGSTOP guard
    role "workload" : Member C's synthetic CPU hog (`cpu_stress.py`)

The attacker, the benign script and the runner itself are never touched, so the
only thing that changes between experiments is the scheduling rule.

The six controls and the kernel interface behind each one:
  default        -> nothing (Completely Fair Scheduler, everyone nice 0)
  nice           -> setpriority(2)            = `nice` / `renice`
  chrt           -> sched_setscheduler(2)     = `chrt -f 50`  (SCHED_FIFO real-time)
  cgroup_weight  -> cgroup v2 `cpu.weight`    (proportional CPU share)
  cgroup_max     -> cgroup v2 `cpu.max`       (hard CPU bandwidth cap)
  taskset        -> sched_setaffinity(2)      = `taskset -c`  (core pinning)

How the controls get applied (important design decision):
---------------------------------------------------------
Controls are applied *inside the child process between fork() and exec()*
(`spawn_with_profile`). This has three advantages:
  1. No race: the defender is already under its control when its first
     instruction runs, so its "ready" signal can be trusted.
  2. Inheritance: Linux children inherit nice value, scheduling policy, CPU
     affinity and cgroup membership at fork(). The workload's worker processes
     are forked *after* the parent was configured, so they obey automatically.
  3. We never change the runner's own scheduling.

Because a control that silently failed would make an experiment meaningless,
`verify_profile()` reads the real state back from the kernel (`/proc`, `os.sched_*`)
and the runner aborts a trial whose control did not take effect.

Safety (real-time scheduling):
------------------------------
A SCHED_FIFO process that never blocks can starve a whole machine, including
WSL2. Three layers protect us: (1) the kernel's RT throttling
(`/proc/sys/kernel/sched_rt_runtime_us`, which we refuse to run without),
(2) the defender blocks in `inotify` reads instead of spinning, and
(3) `start_watchdog()` starts a tiny SCHED_FIFO-99 sleeper that SIGKILLs the RT
process after a hard deadline - it outranks the defender, so it always wakes on time.

Command-Line Usage:
-------------------
  python -m src.scheduler.profiles --list
  python -m src.scheduler.profiles --check chrt          # what would be applied, is it available?
  python -m src.scheduler.profiles --describe <PID>      # show a live process's scheduling state
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import psutil

from config.experiment_config import SCHEDULER_PARAMS, SCHEDULER_SETUPS


# ==============================================================================
# 1. CONSTANTS
# ==============================================================================

ROLE_DEFENDER: str = "defender"
ROLE_WORKLOAD: str = "workload"
ROLES: Tuple[str, str] = (ROLE_DEFENDER, ROLE_WORKLOAD)

# Mount point of the cgroup v2 unified hierarchy (the same path on WSL2 and native Linux).
CGROUP_ROOT: Path = Path("/sys/fs/cgroup")

# Kernel defaults, used to reset the cgroups between setups so no setting leaks.
DEFAULT_CPU_WEIGHT: int = 100
DEFAULT_CGROUP_PERIOD_US: int = 100_000

# Setups that need root (negative nice, real-time policy, writing under /sys/fs/cgroup).
ROOT_REQUIRED_SETUPS: Tuple[str, ...] = ("nice", "chrt", "cgroup_weight", "cgroup_max")

# Setups that use cgroup v2.
CGROUP_SETUPS: Tuple[str, ...] = ("cgroup_weight", "cgroup_max")

# Priority of the real-time watchdog (must be above the defender's chrt priority).
WATCHDOG_RT_PRIORITY: int = 99

_RT_POLICIES: Dict[str, int] = {
    "fifo": os.SCHED_FIFO,
    "rr": os.SCHED_RR,
}
_POLICY_NAMES: Dict[int, str] = {
    os.SCHED_OTHER: "SCHED_OTHER",
    os.SCHED_FIFO: "SCHED_FIFO",
    os.SCHED_RR: "SCHED_RR",
    os.SCHED_BATCH: "SCHED_BATCH",
    os.SCHED_IDLE: "SCHED_IDLE",
}


class ProfileError(RuntimeError):
    """Raised when a scheduler profile cannot be prepared, applied or verified."""


# ==============================================================================
# 2. SMALL HELPERS
# ==============================================================================

def parse_cpu_list(spec: str) -> List[int]:
    """
    Parse a Linux CPU list such as `"0"`, `"1-3"` or `"0,2-4"` into sorted core numbers.

    Raises
    ------
    ValueError
        If the text is empty or malformed.
    """
    cores: set = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"Empty element in CPU list '{spec}'.")
        if "-" in part:
            low_s, high_s = part.split("-", 1)
            low, high = int(low_s), int(high_s)
            if high < low:
                raise ValueError(f"Descending range '{part}' in CPU list '{spec}'.")
            cores.update(range(low, high + 1))
        else:
            cores.add(int(part))
    return sorted(cores)


def available_cpus() -> List[int]:
    """Return the CPU numbers this process is allowed to run on."""
    return sorted(os.sched_getaffinity(0))


def is_root() -> bool:
    """True if running as root (effective UID 0)."""
    return os.geteuid() == 0


def policy_name(policy: int) -> str:
    """Human-readable name of a scheduling-policy constant."""
    return _POLICY_NAMES.get(policy, f"policy_{policy}")


def _write_file(path: Path, value: str) -> None:
    """Write `value` to a kernel control file, turning OS errors into clear messages."""
    try:
        with open(path, "w", encoding="ascii") as f:
            f.write(value)
    except OSError as exc:
        raise ProfileError(f"Could not write '{value}' to {path}: {exc}") from exc


def _read_file(path: Path) -> str:
    """Read a kernel control file."""
    try:
        return Path(path).read_text(encoding="ascii").strip()
    except OSError as exc:
        raise ProfileError(f"Could not read {path}: {exc}") from exc


def _cgroup_name(setup: str, role: str) -> Optional[str]:
    """Name of the cgroup for `role` under `setup` (None if the setup has no cgroups)."""
    return SCHEDULER_PARAMS.get(setup, {}).get(f"{role}_cgroup_name")


# ==============================================================================
# 3. CGROUP v2 MANAGEMENT
# ==============================================================================

def cgroup_v2_status(root: Path = CGROUP_ROOT) -> Tuple[bool, str]:
    """
    Check that `root` is a cgroup v2 hierarchy offering the `cpu` controller.

    Returns
    -------
    (bool, str)
        `(True, "ok")` or `(False, reason)` where `reason` explains the fix.
    """
    controllers_file = Path(root) / "cgroup.controllers"
    if not controllers_file.exists():
        return False, (
            f"{controllers_file} not found: cgroup v2 is not mounted at {root}. "
            "On WSL2 add `kernelCommandLine = cgroup_no_v1=all` under [wsl2] in "
            "%UserProfile%\\.wslconfig, run `wsl --shutdown`, then reopen Ubuntu."
        )
    try:
        controllers = controllers_file.read_text(encoding="ascii").split()
    except OSError as exc:
        return False, f"Cannot read {controllers_file}: {exc}"
    if "cpu" not in controllers:
        return False, (
            f"The cpu controller is not available in cgroup v2 (controllers: {controllers or 'none'}). "
            "It is probably bound to the legacy v1 hierarchy; see the WSL2 fix in the README."
        )
    return True, "ok"


def cgroup_dir(name: str, root: Path = CGROUP_ROOT) -> Path:
    """Directory of the cgroup called `name` directly under `root`."""
    return Path(root) / name


def enable_cpu_controller(root: Path = CGROUP_ROOT) -> None:
    """
    Enable the `cpu` controller for child cgroups (`+cpu` in `cgroup.subtree_control`).

    Without this, child cgroups have no `cpu.weight` / `cpu.max` files at all.
    """
    ok, reason = cgroup_v2_status(root)
    if not ok:
        raise ProfileError(reason)
    subtree = Path(root) / "cgroup.subtree_control"
    if "cpu" not in _read_file(subtree).split():
        _write_file(subtree, "+cpu")


def cgroup_names_in_use() -> List[str]:
    """Distinct cgroup directory names used by the cgroup-based setups."""
    names: List[str] = []
    for setup in CGROUP_SETUPS:
        for role in ROLES:
            name = _cgroup_name(setup, role)
            if name and name not in names:
                names.append(name)
    return names


def create_cgroups(root: Path = CGROUP_ROOT) -> List[Path]:
    """Enable the cpu controller and create the defender/workload cgroup directories."""
    enable_cpu_controller(root)
    created: List[Path] = []
    for name in cgroup_names_in_use():
        path = cgroup_dir(name, root)
        path.mkdir(exist_ok=True)
        created.append(path)
    return created


def _write_cgroup_cpu_limits(path: Path, weight: int, quota_us: Optional[int], period_us: int) -> None:
    """Set `cpu.weight` and `cpu.max` of one cgroup (`quota_us=None` means unlimited)."""
    if not 1 <= weight <= 10_000:
        raise ProfileError(f"cpu.weight must be 1..10000 (got {weight}).")
    _write_file(path / "cpu.weight", str(weight))
    quota_text = "max" if quota_us is None else str(int(quota_us))
    _write_file(path / "cpu.max", f"{quota_text} {int(period_us)}")


def workload_cpu_quota_us(total_cpus: Optional[int] = None) -> Tuple[int, int]:
    """
    Compute the `cpu.max` quota for the `cgroup_max` setup.

    `workload_cpu_quota_pct` is a percentage of *all* logical cores, so on a
    4-core machine 50% means 200 000 us of CPU time per 100 000 us period
    (= two cores' worth, however the kernel spreads it).

    Returns
    -------
    (quota_us, period_us)
    """
    params = SCHEDULER_PARAMS["cgroup_max"]
    period_us = int(params.get("cgroup_period_us", DEFAULT_CGROUP_PERIOD_US))
    pct = float(params["workload_cpu_quota_pct"])
    cpus = total_cpus if total_cpus is not None else (os.cpu_count() or 1)
    quota_us = max(1000, int(period_us * cpus * pct / 100.0))  # kernel minimum quota is 1 ms
    return quota_us, period_us


def configure_cgroups(setup: str, root: Path = CGROUP_ROOT) -> Dict[str, str]:
    """
    Create the cgroups (if needed) and write the CPU limits required by `setup`.

    Every call first resets *both* cgroups to the kernel defaults, so a limit
    from the previous setup can never leak into the next one.

    Returns
    -------
    Dict[str, str]
        What was written, e.g. `{"os_proj_defender/cpu.weight": "1000", ...}` (for logs/notes).
    """
    if setup not in CGROUP_SETUPS:
        raise ProfileError(f"Setup '{setup}' does not use cgroups (expected one of {CGROUP_SETUPS}).")

    create_cgroups(root)
    params = SCHEDULER_PARAMS[setup]
    period_us = int(params.get("cgroup_period_us", DEFAULT_CGROUP_PERIOD_US))
    defender_cg = cgroup_dir(params["defender_cgroup_name"], root)
    workload_cg = cgroup_dir(params["workload_cgroup_name"], root)

    for path in (defender_cg, workload_cg):  # reset to defaults
        _write_cgroup_cpu_limits(path, DEFAULT_CPU_WEIGHT, None, period_us)

    if setup == "cgroup_weight":
        _write_cgroup_cpu_limits(defender_cg, int(params["defender_cpu_weight"]), None, period_us)
        _write_cgroup_cpu_limits(workload_cg, int(params["workload_cpu_weight"]), None, period_us)
    else:  # cgroup_max
        quota_us, period_us = workload_cpu_quota_us()
        _write_cgroup_cpu_limits(workload_cg, DEFAULT_CPU_WEIGHT, quota_us, period_us)

    written: Dict[str, str] = {}
    for path in (defender_cg, workload_cg):
        written[f"{path.name}/cpu.weight"] = _read_file(path / "cpu.weight")
        written[f"{path.name}/cpu.max"] = _read_file(path / "cpu.max")
    return written


def cleanup_cgroups(root: Path = CGROUP_ROOT) -> List[str]:
    """
    Remove the project's cgroups, first moving any leftover process back to the root cgroup.

    A cgroup directory can only be removed when it has no processes, so leftovers
    (for example a crashed run) are evacuated before `rmdir`. Safe to call repeatedly.

    Returns
    -------
    List[str]
        Names of the cgroups that were removed.
    """
    removed: List[str] = []
    root = Path(root)
    for name in cgroup_names_in_use():
        path = cgroup_dir(name, root)
        if not path.is_dir():
            continue
        try:
            for pid_text in (path / "cgroup.procs").read_text(encoding="ascii").split():
                try:
                    (root / "cgroup.procs").write_text(pid_text, encoding="ascii")
                except OSError:
                    pass  # process already gone
            path.rmdir()
            removed.append(name)
        except OSError:
            continue  # busy or already removed; the shell script can retry
    return removed


# ==============================================================================
# 4. PLANNING: WHAT EXACTLY GETS APPLIED TO EACH ROLE
# ==============================================================================

def validate_setup_name(setup: str) -> None:
    """Raise ProfileError if `setup` is not one of `SCHEDULER_SETUPS`."""
    if setup not in SCHEDULER_PARAMS or setup not in SCHEDULER_SETUPS:
        raise ProfileError(f"Unknown scheduler setup '{setup}'. Valid setups: {', '.join(SCHEDULER_SETUPS)}")


def taskset_core_plan() -> Tuple[List[int], List[int]]:
    """
    Return `(defender_cores, workload_cores)` for the `taskset` setup, validated.

    Raises
    ------
    ProfileError
        With fewer than 2 usable cores, or if the configured cores are not
        available to this process or overlap (pinning would be meaningless).
    """
    cpus = available_cpus()
    if len(cpus) < 2:
        raise ProfileError(
            f"The taskset setup needs at least 2 CPU cores (this process may use {cpus}). "
            "Increase `processors` in .wslconfig or run on a machine with more cores."
        )
    params = SCHEDULER_PARAMS["taskset"]
    defender = parse_cpu_list(params["defender_cores"])
    workload = parse_cpu_list(params["workload_cores"])
    if not set(defender) | set(workload) <= set(cpus):
        raise ProfileError(
            f"Configured cores defender={defender}, workload={workload} are not all available (available: {cpus})."
        )
    if set(defender) & set(workload):
        raise ProfileError(f"Defender cores {defender} overlap workload cores {workload}.")
    return defender, workload


def plan_controls(setup: str, role: str, cgroup_root: Path = CGROUP_ROOT) -> Dict[str, Any]:
    """
    Work out which controls `setup` demands for `role` (pure function, changes nothing).

    Returns
    -------
    Dict[str, Any]
        Any of these keys (absent = leave that aspect alone):
          `nice`        : int nice value
          `rt`          : (policy_constant, priority) for SCHED_FIFO / SCHED_RR
          `cgroup`      : cgroup directory name
          `cgroup_procs`: absolute path of that cgroup's `cgroup.procs`
          `cores`       : sorted list of CPU numbers for the affinity mask
    """
    validate_setup_name(setup)
    if role not in ROLES:
        raise ProfileError(f"Unknown role '{role}' (expected one of {ROLES}).")

    params = SCHEDULER_PARAMS[setup]
    controls: Dict[str, Any] = {}

    nice_value = params.get(f"{role}_nice")
    if nice_value is not None:
        controls["nice"] = int(nice_value)

    rt_policy = params.get(f"{role}_rt_policy")
    if rt_policy is not None:
        if rt_policy not in _RT_POLICIES:
            raise ProfileError(f"Unknown real-time policy '{rt_policy}' (use one of {sorted(_RT_POLICIES)}).")
        controls["rt"] = (_RT_POLICIES[rt_policy], int(params[f"{role}_rt_priority"]))

    cgroup_name = _cgroup_name(setup, role)
    if cgroup_name:
        controls["cgroup"] = cgroup_name
        controls["cgroup_procs"] = str(cgroup_dir(cgroup_name, cgroup_root) / "cgroup.procs")

    if setup == "taskset":
        defender_cores, workload_cores = taskset_core_plan()
        controls["cores"] = defender_cores if role == ROLE_DEFENDER else workload_cores

    return controls


def describe_plan(setup: str, role: str) -> str:
    """One-line human-readable summary of what `setup` does to `role` (for logs and notes)."""
    try:
        controls = plan_controls(setup, role)
    except ProfileError as exc:
        return f"unavailable ({exc})"
    if not controls:
        return "no change (default CFS)"
    parts: List[str] = []
    if "nice" in controls:
        parts.append(f"nice {controls['nice']}")
    if "rt" in controls:
        policy, prio = controls["rt"]
        parts.append(f"{policy_name(policy)} prio {prio}")
    if "cgroup" in controls:
        parts.append(f"cgroup {controls['cgroup']}")
    if "cores" in controls:
        parts.append(f"cores {controls['cores']}")
    return ", ".join(parts)


# ==============================================================================
# 5. PREFLIGHT: CAN THIS SETUP RUN ON THIS MACHINE RIGHT NOW?
# ==============================================================================

def rt_throttling_enabled() -> bool:
    """
    True if the kernel limits real-time CPU usage (`sched_rt_runtime_us` != -1).

    With throttling disabled, a runaway SCHED_FIFO task can lock up the machine,
    so we refuse to run the `chrt` setup in that case.
    """
    try:
        return int(Path("/proc/sys/kernel/sched_rt_runtime_us").read_text().strip()) != -1
    except (OSError, ValueError):
        return False


def preflight(setup: str, cgroup_root: Path = CGROUP_ROOT) -> None:
    """
    Raise ProfileError, with a fix-it message, if `setup` cannot run right now.

    Checks: setup name, root privileges, cgroup v2 + cpu controller, RT throttling
    safety net, and enough CPU cores for pinning.
    """
    validate_setup_name(setup)
    if sys.platform != "linux":
        raise ProfileError("Scheduler controls only exist on Linux. Run inside WSL2 (Ubuntu).")

    if setup in ROOT_REQUIRED_SETUPS and not is_root():
        raise ProfileError(
            f"Setup '{setup}' needs root (negative nice, real-time policy or cgroup writes). "
            "Run via `scripts/run_all_experiments.sh`, or prefix the command with "
            "`sudo \"$(which python)\"` so the virtual environment is kept."
        )
    if setup in CGROUP_SETUPS:
        ok, reason = cgroup_v2_status(cgroup_root)
        if not ok:
            raise ProfileError(reason)
    if setup == "chrt" and not rt_throttling_enabled():
        raise ProfileError(
            "Refusing to run real-time scheduling: /proc/sys/kernel/sched_rt_runtime_us is -1 "
            "(RT throttling disabled), so a runaway SCHED_FIFO task could freeze the machine. "
            "Restore it with `sudo sysctl kernel.sched_rt_runtime_us=950000`."
        )
    if setup == "taskset":
        taskset_core_plan()  # raises ProfileError if pinning is impossible


def prepare_setup(setup: str, cgroup_root: Path = CGROUP_ROOT) -> Dict[str, str]:
    """
    Run `preflight()` and write any kernel-side configuration the setup needs (cgroup limits).

    Returns
    -------
    Dict[str, str]
        What was configured (empty for setups that need no preparation).
    """
    preflight(setup, cgroup_root)
    if setup in CGROUP_SETUPS:
        return configure_cgroups(setup, cgroup_root)
    return {}


# ==============================================================================
# 6. APPLYING CONTROLS: AT SPAWN TIME AND TO RUNNING PROCESSES
# ==============================================================================

def _make_preexec(controls: Dict[str, Any]) -> Callable[[], None]:
    """
    Build the function that runs in the child between fork() and exec().

    It must stay tiny and use only `os` calls (it runs before exec in a freshly
    forked copy of the runner). Failures are reported on stderr and do not stop the
    exec; `verify_profile()` then catches any control that did not take effect.
    """
    cgroup_procs: Optional[str] = controls.get("cgroup_procs")
    cores = controls.get("cores")
    nice_value = controls.get("nice")
    rt = controls.get("rt")

    def _preexec() -> None:
        def _report(what: str, exc: BaseException) -> None:
            os.write(2, f"[profiles] could not apply {what}: {exc}\n".encode())

        if cgroup_procs is not None:
            try:
                fd = os.open(cgroup_procs, os.O_WRONLY)
                try:
                    os.write(fd, str(os.getpid()).encode())
                finally:
                    os.close(fd)
            except OSError as exc:
                _report("cgroup membership", exc)
        if cores is not None:
            try:
                os.sched_setaffinity(0, cores)
            except OSError as exc:
                _report("CPU affinity", exc)
        if nice_value is not None:
            try:
                os.setpriority(os.PRIO_PROCESS, 0, nice_value)
            except OSError as exc:
                _report("nice value", exc)
        if rt is not None:  # last: nothing after this should run at real-time priority
            try:
                os.sched_setscheduler(0, rt[0], os.sched_param(rt[1]))
            except OSError as exc:
                _report("real-time policy", exc)

    return _preexec


def spawn_with_profile(
    cmd: List[str],
    setup: str,
    role: str,
    cgroup_root: Path = CGROUP_ROOT,
    **popen_kwargs: Any,
) -> subprocess.Popen:
    """
    Start `cmd` as a new process (own session/process group) already under `setup`'s control for `role`.

    `prepare_setup(setup)` must have been called first (it creates the cgroups).
    Extra keyword arguments (`cwd`, `stdout`, `env`, ...) go to `subprocess.Popen`.
    """
    controls = plan_controls(setup, role, cgroup_root)
    popen_kwargs.setdefault("start_new_session", True)
    if controls:
        popen_kwargs["preexec_fn"] = _make_preexec(controls)
    return subprocess.Popen(cmd, **popen_kwargs)


def apply_to_pid(
    setup: str,
    role: str,
    pid: int,
    include_children: bool = True,
    cgroup_root: Path = CGROUP_ROOT,
) -> List[int]:
    """
    Apply `setup`'s control for `role` to an already-running process (and its descendants).

    Used for demos and tests (`spawn_with_profile` is what the runner uses, because it is
    race-free). Returns the PIDs that were configured. Raises ProfileError on failure.
    """
    controls = plan_controls(setup, role, cgroup_root)
    try:
        proc = psutil.Process(pid)
        targets = [proc] + (proc.children(recursive=True) if include_children else [])
    except psutil.Error as exc:
        raise ProfileError(f"Cannot inspect PID {pid}: {exc}") from exc

    done: List[int] = []
    for target in targets:
        try:
            if "cgroup_procs" in controls:
                _write_file(Path(controls["cgroup_procs"]), str(target.pid))
            if "cores" in controls:
                os.sched_setaffinity(target.pid, controls["cores"])
            if "nice" in controls:
                os.setpriority(os.PRIO_PROCESS, target.pid, controls["nice"])
            if "rt" in controls:
                os.sched_setscheduler(target.pid, controls["rt"][0], os.sched_param(controls["rt"][1]))
        except (OSError, psutil.Error) as exc:
            raise ProfileError(f"Could not apply {setup}/{role} to PID {target.pid}: {exc}") from exc
        done.append(target.pid)
    return done


# ==============================================================================
# 7. VERIFICATION: READ THE REAL STATE BACK FROM THE KERNEL
# ==============================================================================

def describe_process(pid: int) -> Dict[str, Any]:
    """
    Snapshot of a process's scheduling state as the kernel sees it.

    Keys: `nice`, `policy`, `rt_priority`, `cores`, `cgroup` (path from `/proc/<pid>/cgroup`).
    """
    info: Dict[str, Any] = {
        "pid": pid,
        "nice": os.getpriority(os.PRIO_PROCESS, pid),
        "policy": policy_name(os.sched_getscheduler(pid)),
        "rt_priority": os.sched_getparam(pid).sched_priority,
        "cores": sorted(os.sched_getaffinity(pid)),
        "cgroup": None,
    }
    try:
        for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
            if line.startswith("0::"):  # the unified (v2) entry
                info["cgroup"] = line[3:]
    except OSError:
        pass
    return info


def verify_profile(
    setup: str,
    role: str,
    pid: int,
    include_children: bool = False,
    cgroup_root: Path = CGROUP_ROOT,
) -> List[str]:
    """
    Check that `pid` (and optionally its descendants) really run under `setup`'s control for `role`.

    Returns
    -------
    List[str]
        Mismatch descriptions; an empty list means everything took effect.
    """
    controls = plan_controls(setup, role, cgroup_root)
    if not controls:
        return []

    try:
        proc = psutil.Process(pid)
        pids = [pid] + ([c.pid for c in proc.children(recursive=True)] if include_children else [])
    except psutil.Error as exc:
        return [f"{role} PID {pid} is gone: {exc}"]

    problems: List[str] = []
    for target_pid in pids:
        try:
            state = describe_process(target_pid)
        except (OSError, ProfileError):
            continue  # process exited between listing and inspection
        label = f"{role} PID {target_pid}"
        if "nice" in controls and state["nice"] != controls["nice"]:
            problems.append(f"{label}: expected nice {controls['nice']}, got {state['nice']}")
        if "rt" in controls:
            want_policy, want_prio = controls["rt"]
            if state["policy"] != policy_name(want_policy) or state["rt_priority"] != want_prio:
                problems.append(
                    f"{label}: expected {policy_name(want_policy)} prio {want_prio}, "
                    f"got {state['policy']} prio {state['rt_priority']}"
                )
        if "cores" in controls and state["cores"] != controls["cores"]:
            problems.append(f"{label}: expected cores {controls['cores']}, got {state['cores']}")
        if "cgroup" in controls and Path(cgroup_root) == CGROUP_ROOT:
            want_cgroup = "/" + controls["cgroup"]
            if state["cgroup"] != want_cgroup:
                problems.append(f"{label}: expected cgroup {want_cgroup}, got {state['cgroup']}")
    return problems


# ==============================================================================
# 8. REAL-TIME SAFETY WATCHDOG
# ==============================================================================

def start_watchdog(target_pids: List[int], timeout_s: float, realtime: bool = True) -> subprocess.Popen:
    """
    Start a background watchdog that SIGKILLs `target_pids` after `timeout_s` seconds.

    With `realtime=True` (and root) the watchdog itself runs as SCHED_FIFO priority 99, above the
    defender's priority 50. A sleeping real-time task preempts everything the moment its timer
    fires, so even a runaway real-time defender cannot stop the watchdog from killing it.
    Call `stop_watchdog()` on normal completion.
    """
    pid_list = " ".join(str(int(p)) for p in target_pids)
    shell_cmd = f"sleep {float(timeout_s):.3f}; kill -KILL {pid_list} 2>/dev/null"
    cmd = ["sh", "-c", shell_cmd]
    if realtime and is_root():
        cmd = ["chrt", "--fifo", str(WATCHDOG_RT_PRIORITY)] + cmd
    return subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def stop_watchdog(watchdog: Optional[subprocess.Popen]) -> None:
    """Cancel a watchdog started by `start_watchdog()` (kills its whole process group)."""
    if watchdog is None:
        return
    try:
        os.killpg(watchdog.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        watchdog.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        pass


# ==============================================================================
# 9. COMMAND-LINE INTERFACE (handy for demos and the viva)
# ==============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect the Linux scheduler profiles used by the experiments.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="List every setup and what it does to each role.")
    group.add_argument("--check", metavar="SETUP", help="Show whether SETUP can run on this machine right now.")
    group.add_argument("--describe", metavar="PID", type=int, help="Show a live process's scheduling state.")
    return parser


def main() -> int:
    """Entry point for `python -m src.scheduler.profiles`."""
    args = _build_arg_parser().parse_args()

    if args.list:
        for setup in SCHEDULER_SETUPS:
            print(f"{setup:<24} {SCHEDULER_PARAMS[setup]['description']}")
            for role in ROLES:
                print(f"    {role:<9}-> {describe_plan(setup, role)}")
        return 0

    if args.check:
        try:
            preflight(args.check)
        except ProfileError as exc:
            print(f"[NOT READY] {args.check}: {exc}")
            return 1
        print(f"[READY] {args.check}")
        for role in ROLES:
            print(f"    {role:<9}-> {describe_plan(args.check, role)}")
        return 0

    try:
        print(json.dumps(describe_process(args.describe), indent=2))
    except OSError as exc:
        print(f"Cannot inspect PID {args.describe}: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
