#!/bin/sh
set -eu

REPOSITORY_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON_BOOTSTRAP=${PYTHON_BOOTSTRAP:-python3.12}
TEST_ENV=${TEST_ENV:-.venv}

cd "$REPOSITORY_ROOT"
"$PYTHON_BOOTSTRAP" -m venv "$TEST_ENV"
TEST_PYTHON="$TEST_ENV/bin/python"
"$TEST_PYTHON" -m pip install --upgrade pip==25.1.1 setuptools==80.9.0
"$TEST_PYTHON" -m pip install --no-build-isolation --requirement requirements-test.lock
"$TEST_PYTHON" -m pip install --no-build-isolation --no-deps --editable .

printf '%s\n' "Test environment created at $TEST_ENV"
printf '%s\n' "Activate it with: . $TEST_ENV/bin/activate"
printf '%s\n' "Then validate with: python -m pytest -q"
