#!/usr/bin/env bash
# =============================================================================
# run_all_experiments.sh - One command for the complete benchmark.
# Member C (Munir Tariq) | OS Term Project Part 4, Section L4
#
# Steps:
#   1. check_env.sh            (stops here if the environment is not ready)
#   2. setup_cgroups.sh setup  (and always `cleanup` at the end, even on Ctrl+C)
#   3. src.scheduler.runner    (as root; ~20 attack trials per setup + benign + solo trials)
#   4. summarize + plots       (as your normal user; Member D's modules)
#
# Usage:   scripts/run_all_experiments.sh                 # full benchmark (fresh trials.csv)
#          scripts/run_all_experiments.sh --quick         # ~2 minute smoke test
#          scripts/run_all_experiments.sh --trials 5 --setups default chrt
#
# Own options:   --no-analysis      skip step 4
#                --skip-env-check   skip step 1 (not recommended)
# Every other option is passed to the runner (see: python -m src.scheduler.runner --help).
#
# Run it from your activated virtual environment:
#   source ~/venvs/linux-scheduler-defender/bin/activate
# =============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}" || exit 1

RUN_ANALYSIS=1
RUN_ENV_CHECK=1
IS_DRY_RUN=0
RUNNER_ARGS=()
for arg in "$@"; do
    case "${arg}" in
        --no-analysis)    RUN_ANALYSIS=0 ;;
        --skip-env-check) RUN_ENV_CHECK=0 ;;
        --dry-run)        IS_DRY_RUN=1; RUNNER_ARGS+=("${arg}") ;;
        *)                RUNNER_ARGS+=("${arg}") ;;
    esac
done

# Use the virtual environment's interpreter by absolute path, so it survives `sudo`.
if [ -n "${VIRTUAL_ENV:-}" ]; then
    PYTHON_BIN="${VIRTUAL_ENV}/bin/python"
else
    PYTHON_BIN="$(command -v python3)"
    echo "WARNING: no virtual environment active; using ${PYTHON_BIN}" >&2
fi

# Dry run prints the planned schedule without needing sudo, cgroups, --fresh archiving, or analysis.
if [ "${IS_DRY_RUN}" -eq 1 ]; then
    exec "${PYTHON_BIN}" -m src.scheduler.runner "${RUNNER_ARGS[@]}"
fi

if [ "$(id -u)" -eq 0 ]; then
    SUDO=()
else
    SUDO=(sudo)
fi

# --- 1. Environment check ---------------------------------------------------------
if [ "${RUN_ENV_CHECK}" -eq 1 ]; then
    echo "### Step 1/4: environment check"
    if ! "${SCRIPT_DIR}/check_env.sh"; then
        echo "Aborting: fix the problems above (or use --skip-env-check at your own risk)." >&2
        exit 1
    fi
fi

# Ask for the sudo password once, up front, instead of in the middle of the benchmark.
if [ "${#SUDO[@]}" -gt 0 ]; then
    sudo -v || { echo "sudo is required for nice/chrt/cgroups." >&2; exit 1; }
fi

# --- 2. cgroups (always cleaned up on exit) ------------------------------------------
cleanup() {
    echo "### Cleaning up cgroups"
    "${SUDO[@]}" "${SCRIPT_DIR}/setup_cgroups.sh" cleanup
}
trap cleanup EXIT

echo "### Step 2/4: cgroup v2 setup"
if ! "${SUDO[@]}" "${SCRIPT_DIR}/setup_cgroups.sh" setup; then
    echo "WARNING: cgroup setup failed; the runner will skip the cgroup_* setups." >&2
fi

# --- 3. Experiments -------------------------------------------------------------------
echo "### Step 3/4: running experiments"
"${SUDO[@]}" env PYTHONDONTWRITEBYTECODE=1 "${PYTHON_BIN}" -m src.scheduler.runner --fresh "${RUNNER_ARGS[@]+"${RUNNER_ARGS[@]}"}"
RUNNER_STATUS=$?
case "${RUNNER_STATUS}" in
    0) ;;
    2) echo "NOTE: some setups were skipped as unavailable (see the [SKIP] lines above)." >&2 ;;
    *) echo "Runner failed with exit code ${RUNNER_STATUS}; skipping analysis." >&2
       exit "${RUNNER_STATUS}" ;;
esac

# --- 4. Analysis ----------------------------------------------------------------------
if [ "${RUN_ANALYSIS}" -eq 1 ]; then
    echo "### Step 4/4: summary tables and figures"
    "${PYTHON_BIN}" -m src.analysis.summarize   || echo "WARNING: summarize step failed." >&2
    "${PYTHON_BIN}" -m src.analysis.plot_results || echo "WARNING: plot step failed." >&2
else
    echo "### Step 4/4: skipped (--no-analysis)"
fi

ROWS=$(( $(wc -l < results/raw/trials.csv 2>/dev/null || echo 1) - 1 ))
echo
echo "Done. ${ROWS} trial rows in results/raw/trials.csv"
exit "${RUNNER_STATUS}"
