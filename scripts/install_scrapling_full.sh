#!/bin/sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON_BIN=${SCRAPLING_BOOTSTRAP_PYTHON:-/opt/homebrew/bin/python3.12}
RUNTIME_DIR=${SCRAPLING_RUNTIME_DIR:-"$PROJECT_ROOT/.venv-scrapling"}

if [ ! -x "$PYTHON_BIN" ]; then
  echo "Python 3.12 was not found at $PYTHON_BIN" >&2
  echo "Set SCRAPLING_BOOTSTRAP_PYTHON to a Python 3.10-3.13 executable." >&2
  exit 1
fi

"$PYTHON_BIN" -m venv "$RUNTIME_DIR"
"$RUNTIME_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
"$RUNTIME_DIR/bin/python" -m pip install -r "$PROJECT_ROOT/requirements-scrapling-full.txt"

# Install assets for both upstream browser engines. Scrapling's own install
# command currently installs Playwright Chromium only, so Patchright is made
# explicit rather than assumed to share a cache forever.
"$RUNTIME_DIR/bin/python" -m playwright install chromium
"$RUNTIME_DIR/bin/python" -m patchright install chromium

cd "$PROJECT_ROOT"
"$RUNTIME_DIR/bin/python" -m scraper.scrapling_worker <<'EOF'
{"operation":"capabilities"}
EOF
