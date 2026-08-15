#!/usr/bin/env bash
set -Eeuo pipefail

repository_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
samba_compose="${repository_root}/tests/interop/samba/compose.yml"
windows_runner="${repository_root}/tests/interop/windows/run.py"
native_manifest="${repository_root}/native/aiosmb_compression/Cargo.toml"

mode="baseline"
mode_was_set=0
python_command="${PYTHON:-python3}"
windows_profile=""
keep_venv=0
skip_native=0
temporary_root=""
venv_directory=""
declare -a windows_targets=()
declare -a pytest_arguments=()

usage() {
    cat <<'EOF'
Usage: ./test.sh [MODE] [OPTIONS] [-- PYTEST_ARGS...]

Modes:
  baseline          Unit, fake-peer, and component tests (default)
  full              Baseline, Rust/native compression, and disposable Samba
  samba             Disposable Samba interoperability only
  goad-discovery    Credential-free GOAD discovery and capability checks
  goad-readonly     Normal-user SMB and read-only RPC GOAD tests
  goad-privileged   Separately gated privileged read-only GOAD tests
  goad-full         Every GOAD test, including privileged and destructive
  destructive       Explicitly gated destructive GOAD tests

The modes may also be written as flags: --baseline, --full, --samba,
--goad-discovery, --goad-readonly, --goad-privileged, --goad-full, or
--destructive.

Options:
  --windows-profile PATH   Active ignored GOAD profile (required except discovery)
  --target ID              Select one GOAD target; repeatable
  --python COMMAND         Python used to create the temporary virtualenv
  --skip-native            Skip Rust/native checks in full mode
  --keep-venv              Keep the generated virtualenv and print its path
  -h, --help               Show this help

Arguments after -- are forwarded to pytest. Examples:
  ./test.sh
  ./test.sh baseline -- -x -k compression
  ./test.sh full
  ./test.sh goad-discovery --target kingslanding
  ./test.sh goad-readonly --windows-profile tests/interop/windows/profile.local.yml
  AIOSMB_CONFIRM_DESTRUCTIVE=YES ./test.sh goad-full \
    --windows-profile tests/interop/windows/profile.local.yml
  AIOSMB_CONFIRM_DESTRUCTIVE=YES ./test.sh destructive \
    --windows-profile tests/interop/windows/profile.local.yml

Every mode creates an isolated temporary virtualenv. It is removed on success,
failure, Ctrl-C, or termination. Managed Samba containers, volumes, and
networks are also removed automatically.
EOF
}

die() {
    printf 'test.sh: %s\n' "$*" >&2
    exit 2
}

set_mode() {
    if [[ "$mode_was_set" -eq 1 ]]; then
        die "choose exactly one test mode"
    fi
    mode="$1"
    mode_was_set=1
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        baseline|full|samba|goad-discovery|goad-readonly|goad-privileged|goad-full|destructive)
            set_mode "$1"
            shift
            ;;
        --baseline|--full|--samba|--goad-discovery|--goad-readonly|--goad-privileged|--goad-full|--destructive)
            set_mode "${1#--}"
            shift
            ;;
        --windows-profile)
            [[ "$#" -ge 2 ]] || die "--windows-profile requires a path"
            windows_profile="$2"
            shift 2
            ;;
        --target)
            [[ "$#" -ge 2 ]] || die "--target requires an id"
            windows_targets+=("$2")
            shift 2
            ;;
        --python)
            [[ "$#" -ge 2 ]] || die "--python requires a command"
            python_command="$2"
            shift 2
            ;;
        --skip-native)
            skip_native=1
            shift
            ;;
        --keep-venv)
            keep_venv=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            pytest_arguments=("$@")
            break
            ;;
        *)
            die "unknown argument '$1' (put pytest arguments after --)"
            ;;
    esac
done

case "$mode" in
    full|samba)
        command -v docker >/dev/null 2>&1 ||
            die "Docker is required for '${mode}' mode"
        docker compose version >/dev/null 2>&1 ||
            die "Docker Compose is required for '${mode}' mode"
        docker info >/dev/null 2>&1 ||
            die "the Docker daemon is unavailable for '${mode}' mode"
        ;;
esac

if [[ "$mode" == "full" && "$skip_native" -eq 0 ]]; then
    command -v cargo >/dev/null 2>&1 ||
        die "cargo is required for full mode (or pass --skip-native)"
    [[ -f "$native_manifest" ]] ||
        die "native compression sources are missing (or pass --skip-native)"
fi

case "$mode" in
    goad-readonly|goad-privileged|goad-full|destructive)
        [[ -n "$windows_profile" ]] ||
            die "--windows-profile is required for '${mode}' mode"
        [[ -f "$windows_profile" ]] ||
            die "Windows profile does not exist: ${windows_profile}"
        ;;
    goad-discovery)
        if [[ -n "$windows_profile" && ! -f "$windows_profile" ]]; then
            die "Windows profile does not exist: ${windows_profile}"
        fi
        ;;
esac

if [[ ("$mode" == "destructive" || "$mode" == "goad-full") &&
      "${AIOSMB_CONFIRM_DESTRUCTIVE:-}" != "YES" ]]; then
    die "set AIOSMB_CONFIRM_DESTRUCTIVE=YES for '${mode}' mode"
fi

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    set +e

    if [[ "$mode" == "full" || "$mode" == "samba" ]]; then
        docker compose -f "$samba_compose" down \
            --volumes --remove-orphans >/dev/null 2>&1
    fi

    if [[ -n "$temporary_root" && -d "$temporary_root" ]]; then
        if [[ "$keep_venv" -eq 1 ]]; then
            printf 'Kept test virtualenv: %s\n' "$venv_directory"
        else
            rm -rf -- "$temporary_root"
        fi
    fi

    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '==> Creating isolated test environment\n'
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/aiosmb-tests.XXXXXXXX")
venv_directory="${temporary_root}/venv"
"$python_command" -m venv "$venv_directory"
test_python="${venv_directory}/bin/python"

export PIP_DISABLE_PIP_VERSION_CHECK=1
"$test_python" -m pip install --quiet --upgrade pip
"$test_python" -m pip install --quiet \
    -e "$repository_root" \
    -r "${repository_root}/requirements-test.txt"

cd "$repository_root"
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"

run_baseline() {
    printf '==> Running baseline Python suite\n'
    "$test_python" -m pytest \
        tests/unit tests/fake_peer tests/component \
        "${pytest_arguments[@]}"
}

run_native() {
    if [[ "$skip_native" -eq 1 ]]; then
        printf '==> Skipping optional native compression checks\n'
        return
    fi

    "$test_python" -c \
        'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' ||
        die "native compression requires Python 3.9+ (or pass --skip-native)"

    printf '==> Running Rust compression tests\n'
    cargo test --manifest-path "$native_manifest" --all-targets

    printf '==> Installing and checking the native Python extension\n'
    "$test_python" -m pip install --quiet \
        "${repository_root}/native/aiosmb_compression"
    "$test_python" -m pytest \
        tests/unit/foundations/test_compression_backend.py \
        "${pytest_arguments[@]}"
}

run_samba() {
    printf '==> Building and running disposable Samba lab\n'
    PYTHON="$test_python" \
        "${repository_root}/tests/interop/samba/run-lab.sh" \
        "${pytest_arguments[@]}"
}

declare -a windows_common=()
if [[ -n "$windows_profile" ]]; then
    windows_common+=(--profile "$windows_profile")
fi
for target in "${windows_targets[@]}"; do
    windows_common+=(--target "$target")
done

run_goad_group() {
    local group="$1"
    shift
    local -a controller_pytest_arguments=()
    local argument
    for argument in "${pytest_arguments[@]}"; do
        controller_pytest_arguments+=("--pytest-arg=${argument}")
    done
    printf '==> Running GOAD %s tests\n' "$group"
    "$test_python" "$windows_runner" test \
        "${windows_common[@]}" \
        --group "$group" \
        "$@" \
        "${controller_pytest_arguments[@]}"
}

case "$mode" in
    baseline)
        run_baseline
        ;;
    full)
        run_baseline
        run_samba
        run_native
        ;;
    samba)
        run_samba
        ;;
    goad-discovery)
        printf '==> Running credential-free GOAD discovery\n'
        "$test_python" "$windows_runner" discover "${windows_common[@]}"
        ;;
    goad-readonly)
        run_goad_group user
        run_goad_group rpc
        ;;
    goad-privileged)
        run_goad_group privileged --privileged
        ;;
    goad-full)
        run_goad_group all \
            --privileged \
            --destructive \
            --pytest-arg=--run-slow \
            --pytest-arg=--capability \
            --pytest-arg=compression
        ;;
    destructive)
        run_goad_group destructive --destructive
        ;;
    *)
        die "unsupported mode: ${mode}"
        ;;
esac

printf '==> Test mode %s completed successfully\n' "$mode"
