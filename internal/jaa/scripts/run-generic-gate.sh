#!/bin/sh
set -eu

REPOSITORY_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
JAA_TEST_PYTHON=${JAA_TEST_PYTHON:-python}

TEST_PREFIX=$(
  "$JAA_TEST_PYTHON" - <<'PY'
import platform
import sys
from pathlib import Path

if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.13":
    raise SystemExit("generic gate requires exact CPython 3.12.13")
if sys.prefix == sys.base_prefix:
    raise SystemExit("generic gate requires an isolated virtual environment")
print(Path(sys.prefix).resolve())
PY
)

"$JAA_TEST_PYTHON" "$REPOSITORY_ROOT/scripts/verify-gate-environment.py" \
  --repository-root "$REPOSITORY_ROOT" --forbid-protected-corpus

# Point Playwright at an intentionally absent cache. If a supposedly generic
# test starts a browser, it fails instead of discovering ~/.cache/ms-playwright.
GENERIC_BROWSER_SENTINEL="$TEST_PREFIX/.jaa-generic-browser-cache-must-not-exist"
if [ -e "$GENERIC_BROWSER_SENTINEL" ] || [ -L "$GENERIC_BROWSER_SENTINEL" ]; then
  printf '%s\n' "Generic browser sentinel already exists: $GENERIC_BROWSER_SENTINEL" >&2
  exit 1
fi
PLAYWRIGHT_BROWSERS_PATH="$GENERIC_BROWSER_SENTINEL"
export PLAYWRIGHT_BROWSERS_PATH

cd "$REPOSITORY_ROOT"
"$JAA_TEST_PYTHON" scripts/generate_jaa_event_golden.py --check
# Private materialization belongs to the protected gate; the pinned Linux link
# acceptance belongs to the Linux witness gate. Neither is a generic contract.
exec "$JAA_TEST_PYTHON" scripts/run-pytest-no-skips.py -q \
  --deselect=internal/jaa/test_candidate_release_gate.py::test_candidate_gate_accepts_exact_cogna_market_materialization \
  --deselect=internal/jaa/test_gigabyte_current_time_service.py::test_verified_runtime_link_accepts_exact_pinned_venv_chain \
  test_portable_lock_verification.py \
  test_split_repair_contract.py \
  test_runtime_compatibility.py \
  test_gigabyte_current_time_service.py \
  test_gigabyte_current_time_broker.py \
  test_ats_application_authority.py \
  test_candidate_release_gate.py \
  test_review_material_accessor_contract.py \
  test_application_archive.py \
  test_event_receipts.py \
  ../../tests/test_jaa_events_v1.py
