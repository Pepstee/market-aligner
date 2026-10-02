#!/bin/sh
set -eu

REPOSITORY_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
JAA_TEST_PYTHON=${JAA_TEST_PYTHON:-python}
: "${PLAYWRIGHT_BROWSERS_PATH:?protected evidence gate requires PLAYWRIGHT_BROWSERS_PATH}"

if [ "${JAA_CERTIFIED_CORPUS_ROOT+x}" = "x" ] || \
   [ "${JAA_CERTIFIED_CORPUS_BOOTSTRAP_SOURCE+x}" = "x" ]; then
  printf '%s\n' "Protected evidence runtime refuses caller-selected corpus locators" >&2
  exit 1
fi
if [ -n "${JAA09_EVIDENCE_CONTROL_ROOT:-}" ]; then
  printf '%s\n' "Protected evidence gate refuses JAA09_EVIDENCE_CONTROL_ROOT; source evidence is read-only" >&2
  exit 1
fi

PLAYWRIGHT_BROWSERS_PATH=$(
  "$JAA_TEST_PYTHON" - "$PLAYWRIGHT_BROWSERS_PATH" <<'PY'
import platform
import sys
from pathlib import Path

if platform.python_implementation() != "CPython" or platform.python_version() != "3.12.13":
    raise SystemExit("protected evidence gate requires exact CPython 3.12.13")
if sys.prefix == sys.base_prefix:
    raise SystemExit("protected evidence gate requires an isolated virtual environment")
browser_cache = Path(sys.argv[1]).resolve(strict=True)
try:
    relative = browser_cache.relative_to(Path(sys.prefix).resolve())
except ValueError as exc:
    raise SystemExit("PLAYWRIGHT_BROWSERS_PATH must resolve inside the active environment") from exc
if not relative.parts or not browser_cache.is_dir():
    raise SystemExit("protected evidence gate requires an installed in-environment browser cache")
print(browser_cache)
PY
)
export PLAYWRIGHT_BROWSERS_PATH

"$JAA_TEST_PYTHON" "$REPOSITORY_ROOT/scripts/verify-gate-environment.py" \
  --repository-root "$REPOSITORY_ROOT" \
  --browser-cache "$PLAYWRIGHT_BROWSERS_PATH" \
  --require-protected-corpus

PROTECTED_CORPUS=$(
  "$JAA_TEST_PYTHON" - "$REPOSITORY_ROOT" <<'PY'
import sys
from career_automation.protected_corpus_binding import (
    load_installed_protected_corpus_binding,
)

root, _binding = load_installed_protected_corpus_binding(sys.argv[1])
print(root)
PY
)

corpus_fingerprint() {
  "$JAA_TEST_PYTHON" - "$PROTECTED_CORPUS" <<'PY'
import sys
from career_automation.protected_corpus_binding import protected_corpus_tree_sha256

_root, digest, _identity = protected_corpus_tree_sha256(sys.argv[1])
print(digest)
PY
}

CORPUS_BEFORE=$(corpus_fingerprint)
cd "$REPOSITORY_ROOT"
set +e
"$JAA_TEST_PYTHON" scripts/run-pytest-no-skips.py -q \
  test_jaa09_real_vacancy_acceptance.py \
  test_jaa09_real_vacancy_negative_controls.py \
  test_jaa10_network_witnessed_fixture.py \
  test_candidate_release_gate.py::test_candidate_gate_accepts_exact_cogna_market_materialization
TEST_STATUS=$?
set -e
CORPUS_AFTER=$(corpus_fingerprint)
if [ "$CORPUS_BEFORE" != "$CORPUS_AFTER" ]; then
  printf '%s\n' "Protected corpus changed during the evidence gate" >&2
  exit 1
fi
exit "$TEST_STATUS"
