#!/usr/bin/env bash
# =============================================================================
# check_env.sh - Environment check for the scheduler-control experiments.
# Member C (Munir Tariq) | OS Term Project Part 4, Section L4
#
# Verifies everything the experiments rely on, and prints a fix for anything missing:
#   * Linux / WSL2 kernel, repository and /tmp on a native Linux filesystem
#   * cgroup v2 (cgroup2fs) with the "cpu" controller
#   * nice / chrt / taskset, sudo (or root) access, enough CPU cores
#   * real-time throttling safety net (needed before we run SCHED_FIFO)
#   * Python version, virtual environment and Python packages
#
# Usage:   scripts/check_env.sh
# Exit:    0 = ready (warnings allowed), 1 = at least one required check failed
# =============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CGROUP_ROOT="/sys/fs/cgroup"

if [ -t 1 ]; then
    GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
else
    GREEN=""; YELLOW=""; RED=""; RESET=""
fi

PASS=0; WARN=0; FAIL=0
ok()   { echo "  ${GREEN}[ OK ]${RESET} $*"; PASS=$((PASS + 1)); }
warn() { echo "  ${YELLOW}[WARN]${RESET} $*"; WARN=$((WARN + 1)); }
fail() { echo "  ${RED}[FAIL]${RESET} $*"; FAIL=$((FAIL + 1)); }
section() { echo; echo "== $* =="; }

# --- 1. Operating system ------------------------------------------------------
section "Operating system"
if [ "$(uname -s)" != "Linux" ]; then
    fail "Not Linux ($(uname -s)). Run everything inside WSL2 (Ubuntu), never in cmd/PowerShell."
else
    KERNEL="$(uname -r)"
    if grep -qi "microsoft" /proc/version 2>/dev/null; then
        if echo "${KERNEL}" | grep -qi "WSL2\|microsoft-standard"; then
            ok "WSL2 kernel: ${KERNEL}"
        else
            fail "WSL1 detected (kernel ${KERNEL}). Convert with: wsl --set-version <distro> 2"
        fi
    else
        ok "Native Linux kernel: ${KERNEL}"
    fi
fi

case "${REPO_ROOT}" in
    /mnt/*) warn "Repository is on the Windows drive (${REPO_ROOT}). Clone it into your Linux home (~) for speed." ;;
    *)      ok "Repository on the Linux filesystem: ${REPO_ROOT}" ;;
esac

TMP_FS="$(stat -f -c %T /tmp 2>/dev/null || echo unknown)"
case "${TMP_FS}" in
    9p|v9fs|drvfs|fuseblk|ntfs*|vfat) fail "/tmp is on '${TMP_FS}' (Windows-backed). inotify would be unreliable." ;;
    *) ok "/tmp is on a native filesystem (${TMP_FS})" ;;
esac

# --- 2. cgroup v2 -------------------------------------------------------------
section "cgroup v2"
CG_FS="$(stat -f -c %T "${CGROUP_ROOT}" 2>/dev/null || echo unknown)"
if [ "${CG_FS}" = "cgroup2fs" ]; then
    ok "${CGROUP_ROOT} is cgroup v2 (cgroup2fs)"
    if grep -qw cpu "${CGROUP_ROOT}/cgroup.controllers" 2>/dev/null; then
        ok "cpu controller available ($(tr '\n' ' ' < "${CGROUP_ROOT}/cgroup.controllers"))"
    else
        fail "cpu controller missing from ${CGROUP_ROOT}/cgroup.controllers"
    fi
else
    fail "${CGROUP_ROOT} is '${CG_FS}', not cgroup2fs. On WSL2 add this to %UserProfile%\\.wslconfig:"
    echo "         [wsl2]"
    echo "         kernelCommandLine = cgroup_no_v1=all"
    echo "       then run 'wsl --shutdown' in PowerShell and reopen Ubuntu."
fi

# --- 3. Scheduler tools and privileges ------------------------------------------
section "Scheduler tools and privileges"
for tool in nice chrt taskset; do
    if command -v "${tool}" >/dev/null 2>&1; then
        ok "${tool} found ($(command -v "${tool}"))"
    else
        fail "${tool} not found. Install with: sudo apt install util-linux coreutils"
    fi
done

if [ "$(id -u)" -eq 0 ]; then
    ok "Running as root"
elif command -v sudo >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null; then
        ok "sudo works without a password prompt"
    else
        warn "sudo will ask for your password when the experiments start (this is fine)"
    fi
else
    fail "sudo not found and not root. nice -20, chrt and cgroups need root."
fi

NCPU="$(nproc 2>/dev/null || echo 1)"
if [ "${NCPU}" -lt 2 ]; then
    fail "Only ${NCPU} CPU core visible. The taskset setup needs >= 2 (set 'processors=' in .wslconfig)."
elif [ "${NCPU}" -lt 4 ]; then
    warn "${NCPU} CPU cores visible. Works, but 4+ gives much clearer scheduler differences."
else
    ok "${NCPU} CPU cores visible"
fi

# --- 4. Real-time safety net ----------------------------------------------------
section "Real-time scheduling safety"
RT_RUNTIME="$(cat /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null || echo unknown)"
if [ "${RT_RUNTIME}" = "-1" ]; then
    fail "sched_rt_runtime_us = -1 (RT throttling OFF): a runaway SCHED_FIFO task could freeze WSL2."
    echo "       Fix: sudo sysctl kernel.sched_rt_runtime_us=950000"
elif [ "${RT_RUNTIME}" = "unknown" ]; then
    warn "Could not read /proc/sys/kernel/sched_rt_runtime_us"
else
    ok "RT throttling active (${RT_RUNTIME} us of every 1 s allowed for real-time tasks)"
fi

# --- 5. Python ------------------------------------------------------------------
section "Python environment"
if [ -n "${VIRTUAL_ENV:-}" ]; then
    PYTHON_BIN="${VIRTUAL_ENV}/bin/python"
    ok "Virtual environment active: ${VIRTUAL_ENV}"
else
    PYTHON_BIN="$(command -v python3 || true)"
    warn "No virtual environment active. Run: source ~/venvs/linux-scheduler-defender/bin/activate"
fi

if [ -z "${PYTHON_BIN}" ] || [ ! -x "${PYTHON_BIN}" ]; then
    fail "Python 3 not found."
else
    if "${PYTHON_BIN}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
        ok "Python $("${PYTHON_BIN}" -c 'import platform; print(platform.python_version())') (>= 3.9)"
    else
        fail "Python >= 3.9 required (found $("${PYTHON_BIN}" --version 2>&1))."
    fi
    for module in psutil inotify_simple; do
        if "${PYTHON_BIN}" -c "import ${module}" 2>/dev/null; then
            ok "Python package '${module}' installed"
        else
            fail "Python package '${module}' missing. Run: pip install -r requirements.txt"
        fi
    done
    for module in pandas matplotlib; do
        if "${PYTHON_BIN}" -c "import ${module}" 2>/dev/null; then
            ok "Python package '${module}' installed"
        else
            warn "Python package '${module}' missing (needed only for the analysis step): pip install -r requirements.txt"
        fi
    done
fi

# --- 6. Leftovers from earlier runs ---------------------------------------------
section "Leftover processes"
STALE="$(pgrep -af 'src\.(workload\.cpu_stress|attacker\.(ransomware_sim|benign_activity)|defender\.defender)' 2>/dev/null || true)"
if [ -n "${STALE}" ]; then
    warn "Project processes from an earlier run are still alive (they would distort results):"
    echo "${STALE}" | sed 's/^/         /'
    echo "       Stop them with: sudo pkill -f 'src\\.(workload|attacker|defender)'"
else
    ok "No leftover project processes"
fi

# --- Summary ----------------------------------------------------------------------
echo
echo "Summary: ${PASS} ok, ${WARN} warning(s), ${FAIL} failure(s)."
if [ "${FAIL}" -gt 0 ]; then
    echo "${RED}Environment NOT ready. Fix the [FAIL] items above and run this script again.${RESET}"
    exit 1
fi
echo "${GREEN}Environment ready.${RESET}"
exit 0
