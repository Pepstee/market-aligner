#!/bin/sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SCRAPLING_BIN=${SCRAPLING_BIN:-"$PROJECT_ROOT/.venv-scrapling/bin/scrapling"}

if [ ! -x "$SCRAPLING_BIN" ]; then
  echo "Full Scrapling runtime is missing. Run scripts/install_scrapling_full.sh" >&2
  exit 1
fi

exec "$SCRAPLING_BIN" "$@"
