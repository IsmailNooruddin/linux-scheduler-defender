#!/usr/bin/env bash
# =============================================================================
# setup_cgroups.sh - Create / inspect / remove the cgroup v2 groups used by the
# `cgroup_weight` and `cgroup_max` scheduler setups.
# Member C (Munir Tariq) | OS Term Project Part 4, Section L4
#
# Groups (names must match config/experiment_config.py):
#   /sys/fs/cgroup/os_proj_defender    <- the defender runs here
#   /sys/fs/cgroup/os_proj_workload    <- the synthetic CPU workload runs here
#
# Usage:   scripts/setup_cgroups.sh setup     # enable +cpu, create both groups, reset to defaults
#          scripts/setup_cgroups.sh status    # show weights, limits and member PIDs
#          scripts/setup_cgroups.sh cleanup   # move leftover PIDs to the root group, remove groups
#
# Notes:
#   * Needs root; the script re-runs itself with sudo if necessary.
#   * The Python runner configures the per-setup weights/limits itself
#     (src/scheduler/profiles.py), so this script is for manual setup, demos and cleanup.
#   * `cleanup` leaves "+cpu" enabled in the root cgroup.subtree_control; that is harmless.
# =============================================================================

set -u

CGROUP_ROOT="/sys/fs/cgroup"
GROUPS_TO_MANAGE=("os_proj_defender" "os_proj_workload")
DEFAULT_WEIGHT=100
DEFAULT_MAX="max 100000"

if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo "$0" "$@"
    fi
    echo "This script needs root (sudo not found)." >&2
    exit 1
fi

require_cgroup_v2() {
    local fs
    fs="$(stat -f -c %T "${CGROUP_ROOT}" 2>/dev/null || echo unknown)"
    if [ "${fs}" != "cgroup2fs" ]; then
        echo "ERROR: ${CGROUP_ROOT} is '${fs}', not cgroup v2." >&2
        echo "On WSL2 add 'kernelCommandLine = cgroup_no_v1=all' under [wsl2] in %UserProfile%\\.wslconfig," >&2
        echo "run 'wsl --shutdown' in PowerShell, then reopen Ubuntu." >&2
        exit 1
    fi
    if ! grep -qw cpu "${CGROUP_ROOT}/cgroup.controllers"; then
        echo "ERROR: the cpu controller is not available in ${CGROUP_ROOT}/cgroup.controllers." >&2
        exit 1
    fi
}

do_setup() {
    require_cgroup_v2
    if ! grep -qw cpu "${CGROUP_ROOT}/cgroup.subtree_control"; then
        echo "+cpu" > "${CGROUP_ROOT}/cgroup.subtree_control" || {
            echo "ERROR: could not enable the cpu controller for child groups." >&2
            exit 1
        }
    fi
    local name
    for name in "${GROUPS_TO_MANAGE[@]}"; do
        mkdir -p "${CGROUP_ROOT}/${name}" || exit 1
        echo "${DEFAULT_WEIGHT}" > "${CGROUP_ROOT}/${name}/cpu.weight" || exit 1
        echo "${DEFAULT_MAX}"    > "${CGROUP_ROOT}/${name}/cpu.max"    || exit 1
    done
    echo "cgroups ready (cpu controller enabled, weights reset to ${DEFAULT_WEIGHT}, no cpu.max cap)."
}

do_status() {
    local name dir
    for name in "${GROUPS_TO_MANAGE[@]}"; do
        dir="${CGROUP_ROOT}/${name}"
        if [ -d "${dir}" ]; then
            echo "${name}: cpu.weight=$(cat "${dir}/cpu.weight" 2>/dev/null) cpu.max='$(cat "${dir}/cpu.max" 2>/dev/null)' pids=[$(tr '\n' ' ' < "${dir}/cgroup.procs")]"
        else
            echo "${name}: (does not exist)"
        fi
    done
}

do_cleanup() {
    local name dir pid
    for name in "${GROUPS_TO_MANAGE[@]}"; do
        dir="${CGROUP_ROOT}/${name}"
        [ -d "${dir}" ] || continue
        # A cgroup can only be removed when empty: move any leftover process to the root cgroup.
        while read -r pid; do
            [ -n "${pid}" ] && echo "${pid}" > "${CGROUP_ROOT}/cgroup.procs" 2>/dev/null
        done < "${dir}/cgroup.procs"
        rmdir "${dir}" 2>/dev/null && echo "removed ${name}" || echo "WARNING: could not remove ${name} (still busy?)" >&2
    done
}

case "${1:-}" in
    setup)   do_setup ;;
    status)  do_status ;;
    cleanup) do_cleanup ;;
    *)
        echo "Usage: $0 {setup|status|cleanup}" >&2
        exit 1
        ;;
esac
