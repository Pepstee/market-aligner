#!/bin/sh
set -eu

REPOSITORY_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_ENV="$REPOSITORY_ROOT/.venv"
PYTHON_BOOTSTRAP=${PYTHON_BOOTSTRAP:-python3.12}

"$PYTHON_BOOTSTRAP" -m venv "$TEST_ENV"
"$TEST_ENV/bin/python" -m pip install --upgrade pip==25.1.1 setuptools==80.9.0
"$TEST_ENV/bin/python" -m pip install --no-build-isolation \
  --requirement "$REPOSITORY_ROOT/requirements-test.lock" \
  --editable "$REPOSITORY_ROOT"

printf '%s\n' "Test environment created at $TEST_ENV"
