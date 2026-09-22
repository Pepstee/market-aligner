#!/bin/sh
set -eu

REPOSITORY_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
JAA_TEST_PYTHON=${JAA_TEST_PYTHON:-python}

if [ -z "${PLAYWRIGHT_BROWSERS_PATH:-}" ]; then
  printf '%s\n' "Browser gate requires PLAYWRIGHT_BROWSERS_PATH" >&2
  exit 1
fi

PLAYWRIGHT_BROWSERS_PATH=$(
  "$JAA_TEST_PYTHON" - "$PLAYWRIGHT_BROWSERS_PATH" <<'PY'
import platform
import sys
from pathlib import Path

if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.13":
    raise SystemExit("browser gate requires exact CPython 3.12.13")
if sys.prefix == sys.base_prefix:
    raise SystemExit("browser gate requires an isolated virtual environment")
environment = Path(sys.prefix).resolve()
browser_cache = Path(sys.argv[1]).resolve()
try:
    relative = browser_cache.relative_to(environment)
except ValueError as exc:
    raise SystemExit("PLAYWRIGHT_BROWSERS_PATH must resolve inside the active environment") from exc
if not relative.parts:
    raise SystemExit("PLAYWRIGHT_BROWSERS_PATH must not be the environment itself")
if not browser_cache.is_dir():
    raise SystemExit("PLAYWRIGHT_BROWSERS_PATH must be an installed, explicit cache directory")
print(browser_cache)
PY
)
export PLAYWRIGHT_BROWSERS_PATH

"$JAA_TEST_PYTHON" "$REPOSITORY_ROOT/scripts/verify-gate-environment.py" \
  --repository-root "$REPOSITORY_ROOT" --forbid-protected-corpus \
  --browser-cache "$PLAYWRIGHT_BROWSERS_PATH"

# Import the installed wheel and launch its pinned browser from outside the
# checkout before pytest is allowed to import source-tree modules.
RUNTIME_WITNESS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/jaa-browser-witness.XXXXXX")
trap 'rm -rf -- "$RUNTIME_WITNESS_DIR"' EXIT HUP INT TERM
(
  cd "$RUNTIME_WITNESS_DIR"
  "$JAA_TEST_PYTHON" -m career_automation.runtime_compatibility --launch
)

cd "$REPOSITORY_ROOT"
exec "$JAA_TEST_PYTHON" scripts/run-pytest-no-skips.py -q \
  test_production_ats_executor.py \
  career_automation/test_browser_workflows.py
