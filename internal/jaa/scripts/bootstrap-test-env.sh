#!/bin/sh
set -eu

REPOSITORY_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PROJECT_ROOT=$(git -C "$REPOSITORY_ROOT" rev-parse --show-toplevel)
PYTHON_BOOTSTRAP=${PYTHON_BOOTSTRAP:-python3.12}
: "${TEST_ENV:?set TEST_ENV to a fresh path outside the repository checkout}"
INSTALL_BROWSER=${INSTALL_BROWSER:-0}
INSTALL_BROWSER_DEPS=${INSTALL_BROWSER_DEPS:-0}

cd "$REPOSITORY_ROOT"
"$PYTHON_BOOTSTRAP" - <<'PY'
import platform

if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.13":
    raise SystemExit("bootstrap requires exact CPython 3.12.13")
PY
if ! git diff --quiet --ignore-submodules -- || \
   ! git diff --cached --quiet --ignore-submodules -- || \
   git ls-files --others --exclude-standard | grep -q .; then
  printf '%s\n' "Refusing to certify a dirty source tree; commit the exact candidate first." >&2
  exit 1
fi
TEST_ENV=$(
  "$PYTHON_BOOTSTRAP" - "$TEST_ENV" "$PROJECT_ROOT" <<'PY'
import sys
from pathlib import Path

environment = Path(sys.argv[1]).resolve()
repository = Path(sys.argv[2]).resolve()
try:
    environment.relative_to(repository)
except ValueError:
    pass
else:
    raise SystemExit("TEST_ENV must resolve outside the repository checkout")
print(environment)
PY
)
if [ -e "$TEST_ENV" ] || [ -L "$TEST_ENV" ]; then
  printf '%s\n' "Refusing to reuse existing environment: $TEST_ENV" >&2
  printf '%s\n' "Choose a new TEST_ENV so validation cannot inherit stale packages." >&2
  exit 1
fi
if [ "$INSTALL_BROWSER" = "1" ]; then
  if [ -z "${PLAYWRIGHT_BROWSERS_PATH:-}" ]; then
    printf '%s\n' "INSTALL_BROWSER=1 requires a fresh PLAYWRIGHT_BROWSERS_PATH inside TEST_ENV" >&2
    exit 1
  fi
  PLAYWRIGHT_BROWSERS_PATH=$(
    "$PYTHON_BOOTSTRAP" - "$TEST_ENV" "$PLAYWRIGHT_BROWSERS_PATH" <<'PY'
import sys
from pathlib import Path

environment = Path(sys.argv[1]).resolve()
browser_cache = Path(sys.argv[2]).resolve()
try:
    relative = browser_cache.relative_to(environment)
except ValueError as exc:
    raise SystemExit("PLAYWRIGHT_BROWSERS_PATH must resolve inside TEST_ENV") from exc
if not relative.parts:
    raise SystemExit("PLAYWRIGHT_BROWSERS_PATH must not be TEST_ENV itself")
print(browser_cache)
PY
  )
  if [ -e "$PLAYWRIGHT_BROWSERS_PATH" ] || [ -L "$PLAYWRIGHT_BROWSERS_PATH" ]; then
    printf '%s\n' "Refusing to reuse existing browser cache: $PLAYWRIGHT_BROWSERS_PATH" >&2
    exit 1
  fi
  export PLAYWRIGHT_BROWSERS_PATH
elif [ "$INSTALL_BROWSER" != "0" ]; then
  printf '%s\n' "INSTALL_BROWSER must be 0 or 1" >&2
  exit 1
fi
if [ "$INSTALL_BROWSER_DEPS" != "0" ] && [ "$INSTALL_BROWSER_DEPS" != "1" ]; then
  printf '%s\n' "INSTALL_BROWSER_DEPS must be 0 or 1" >&2
  exit 1
fi
if [ "$INSTALL_BROWSER" = "0" ] && [ "$INSTALL_BROWSER_DEPS" = "1" ]; then
  printf '%s\n' "INSTALL_BROWSER_DEPS=1 requires INSTALL_BROWSER=1" >&2
  exit 1
fi
BUILD_SOURCE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/jaa-source.XXXXXX")
SECOND_BUILD_SOURCE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/jaa-source-two.XXXXXX")
WHEEL_DIR=$(mktemp -d "${TMPDIR:-/tmp}/jaa-wheel.XXXXXX")
SECOND_WHEEL_DIR=$(mktemp -d "${TMPDIR:-/tmp}/jaa-wheel-two.XXXXXX")
trap 'rm -rf -- "$BUILD_SOURCE_DIR" "$SECOND_BUILD_SOURCE_DIR" "$WHEEL_DIR" "$SECOND_WHEEL_DIR"' EXIT HUP INT TERM
git -C "$PROJECT_ROOT" archive --format=tar HEAD pyproject.toml README.md src internal/jaa | tar -xf - -C "$BUILD_SOURCE_DIR"
git -C "$PROJECT_ROOT" archive --format=tar HEAD pyproject.toml README.md src internal/jaa | tar -xf - -C "$SECOND_BUILD_SOURCE_DIR"
SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
export SOURCE_DATE_EPOCH

"$PYTHON_BOOTSTRAP" -m venv "$TEST_ENV"
TEST_PYTHON="$TEST_ENV/bin/python"
(
  cd "$BUILD_SOURCE_DIR"
  "$TEST_PYTHON" -m pip --isolated install --no-deps --requirement internal/jaa/requirements-bootstrap.lock
  "$TEST_PYTHON" -m pip --isolated install --no-build-isolation --no-deps --requirement internal/jaa/requirements-test.lock
  "$TEST_PYTHON" -m pip --isolated wheel --no-build-isolation --no-deps --wheel-dir "$WHEEL_DIR" . ./internal/jaa
)
(
  cd "$SECOND_BUILD_SOURCE_DIR"
  "$TEST_PYTHON" -m pip --isolated wheel --no-build-isolation --no-deps --wheel-dir "$SECOND_WHEEL_DIR" . ./internal/jaa
)
JAA_WHEEL=$(find "$WHEEL_DIR" -maxdepth 1 -type f -name 'job_application_automation-1.0.0-*.whl' -print)
SECOND_JAA_WHEEL=$(find "$SECOND_WHEEL_DIR" -maxdepth 1 -type f -name 'job_application_automation-1.0.0-*.whl' -print)
if [ -z "$JAA_WHEEL" ] || [ "$(printf '%s\n' "$JAA_WHEEL" | wc -l)" -ne 1 ]; then
  printf '%s\n' "Expected exactly one JAA wheel" >&2
  exit 1
fi
if [ -z "$SECOND_JAA_WHEEL" ] || [ "$(printf '%s\n' "$SECOND_JAA_WHEEL" | wc -l)" -ne 1 ]; then
  printf '%s\n' "Expected exactly one independent second JAA wheel" >&2
  exit 1
fi
if ! cmp -s "$JAA_WHEEL" "$SECOND_JAA_WHEEL"; then
  printf '%s\n' "Independent clean-head wheel builds are not byte-identical" >&2
  exit 1
fi
MARKET_WHEEL=$(find "$WHEEL_DIR" -maxdepth 1 -type f -name 'market_aligner-*.whl' -print)
SECOND_MARKET_WHEEL=$(find "$SECOND_WHEEL_DIR" -maxdepth 1 -type f -name 'market_aligner-*.whl' -print)
if [ -z "$MARKET_WHEEL" ] || [ "$(printf '%s\n' "$MARKET_WHEEL" | wc -l)" -ne 1 ] || \
   [ -z "$SECOND_MARKET_WHEEL" ] || [ "$(printf '%s\n' "$SECOND_MARKET_WHEEL" | wc -l)" -ne 1 ]; then
  printf '%s\n' "Expected exactly one Market wheel per build" >&2
  exit 1
fi
if ! cmp -s "$MARKET_WHEEL" "$SECOND_MARKET_WHEEL"; then
  printf '%s\n' "Independent Market wheel builds are not byte-identical" >&2
  exit 1
fi
"$TEST_PYTHON" -m pip --isolated install --no-deps "$JAA_WHEEL" "$MARKET_WHEEL"
"$TEST_PYTHON" -m pip --isolated check
(
  cd "$WHEEL_DIR"
  "$TEST_PYTHON" "$REPOSITORY_ROOT/scripts/verify-installed-wheel.py" \
    --source-root "$PROJECT_ROOT" \
    --source-root "$BUILD_SOURCE_DIR" \
    --source-root "$SECOND_BUILD_SOURCE_DIR"
)
if [ "$INSTALL_BROWSER" = "1" ]; then
  if [ -e "$PLAYWRIGHT_BROWSERS_PATH" ] || [ -L "$PLAYWRIGHT_BROWSERS_PATH" ]; then
    printf '%s\n' "Browser cache appeared before installation: $PLAYWRIGHT_BROWSERS_PATH" >&2
    exit 1
  fi
  if [ "$INSTALL_BROWSER_DEPS" = "1" ]; then
    "$TEST_PYTHON" -m playwright install --with-deps chromium
  else
    "$TEST_PYTHON" -m playwright install chromium
  fi
  (
    cd "$WHEEL_DIR"
    "$TEST_PYTHON" -m career_automation.runtime_compatibility --launch
  )
fi

RECEIPT_BROWSER_ARGUMENTS=
if [ "$INSTALL_BROWSER" = "1" ]; then
  RECEIPT_BROWSER_ARGUMENTS=$PLAYWRIGHT_BROWSERS_PATH
fi
if [ -n "$RECEIPT_BROWSER_ARGUMENTS" ]; then
  "$TEST_PYTHON" "$REPOSITORY_ROOT/scripts/verify-gate-environment.py" \
    --repository-root "$REPOSITORY_ROOT" \
    --write \
    --wheel "$JAA_WHEEL" --market-wheel "$MARKET_WHEEL" \
    --browser-cache "$RECEIPT_BROWSER_ARGUMENTS"
else
  "$TEST_PYTHON" "$REPOSITORY_ROOT/scripts/verify-gate-environment.py" \
    --repository-root "$REPOSITORY_ROOT" \
    --write \
    --wheel "$JAA_WHEEL" --market-wheel "$MARKET_WHEEL"
fi

printf '%s\n' "Test environment created at $TEST_ENV"
printf '%s\n' "Activate it with: . $TEST_ENV/bin/activate"
printf '%s\n' "Verify environment: $TEST_PYTHON $REPOSITORY_ROOT/scripts/verify-gate-environment.py --repository-root $REPOSITORY_ROOT"
printf '%s\n' "Mandatory tests: $TEST_PYTHON $REPOSITORY_ROOT/scripts/run-pytest-no-skips.py followed by explicit pytest targets"
