#!/bin/sh
set -eu

REPOSITORY_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
JAA_TEST_PYTHON=${JAA_TEST_PYTHON:-python}

if [ -z "${PLAYWRIGHT_BROWSERS_PATH:-}" ]; then
  printf '%s\n' "Linux witness gate requires PLAYWRIGHT_BROWSERS_PATH" >&2
  exit 1
fi

PLAYWRIGHT_BROWSERS_PATH=$(
  "$JAA_TEST_PYTHON" - "$PLAYWRIGHT_BROWSERS_PATH" <<'PY'
import platform
import sys
from pathlib import Path

if platform.system() != "Linux":
    raise SystemExit("Linux witness gate requires Linux")
if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.13":
    raise SystemExit("Linux witness gate requires exact CPython 3.12.13")
if sys.prefix == sys.base_prefix:
    raise SystemExit("Linux witness gate requires an isolated virtual environment")
environment = Path(sys.prefix).resolve()
browser_cache = Path(sys.argv[1]).resolve()
try:
    relative = browser_cache.relative_to(environment)
except ValueError as exc:
    raise SystemExit("PLAYWRIGHT_BROWSERS_PATH must resolve inside the active environment") from exc
if not relative.parts or not browser_cache.is_dir():
    raise SystemExit("Linux witness gate requires an installed in-environment browser cache")
print(browser_cache)
PY
)
export PLAYWRIGHT_BROWSERS_PATH

"$JAA_TEST_PYTHON" "$REPOSITORY_ROOT/scripts/verify-gate-environment.py" \
  --repository-root "$REPOSITORY_ROOT" --forbid-protected-corpus \
  --browser-cache "$PLAYWRIGHT_BROWSERS_PATH"

cd "$REPOSITORY_ROOT"
exec "$JAA_TEST_PYTHON" scripts/run-pytest-no-skips.py -q \
  test_jaa10_linux_network_namespace_witness.py \
  test_jaa10_linux_network_namespace_witness_negative_controls.py \
  test_jaa10_network_witnessed_fixture_negative_controls.py \
  test_gigabyte_current_time_service.py::test_verified_runtime_link_accepts_exact_pinned_venv_chain
