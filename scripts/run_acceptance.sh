#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$PROJECT_ROOT"

: "${JAA_ORIGINAL_SOURCE_ROOT:?set JAA_ORIGINAL_SOURCE_ROOT to the original brownfield project root}"
: "${JAA_RECERTIFICATION_EVIDENCE_DIR:?set JAA_RECERTIFICATION_EVIDENCE_DIR outside the original source root}"

python3 -m baseline_adoption.cli recertify-sources \
  --source-root "$JAA_ORIGINAL_SOURCE_ROOT" \
  --evidence-directory "$JAA_RECERTIFICATION_EVIDENCE_DIR"
python3 scripts/accept_jaa_01c.py
python3 -m pytest -q career_automation/test_jaa_01e_lifecycle_no_bypass.py
python3 scripts/reproduce_jaa01_terra_rejection.py
python3 -m pytest -q
