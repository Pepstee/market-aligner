#!/usr/bin/env python3
"""Materialise the borrowed control-plane contracts in the career SQLite DB."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.blueprints import (  # noqa: E402
    backend_capability_authorizer,
    career_pipeline_flow,
)
from career_automation.browser_workflows import BrowserWorkflowStore  # noqa: E402
from career_automation.database import CareerDatabase  # noqa: E402
from career_automation.deployment import DeploymentStore  # noqa: E402
from career_automation.fetching import (  # noqa: E402
    FetchControlStore,
    default_job_fetch_policy,
)
from career_automation.migrations import MigrationRunner  # noqa: E402
from career_automation.observability import ObservabilityStore  # noqa: E402


DEFAULT_DB = ROOT / "outputs" / "career_automation" / "career_pipeline.sqlite3"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=str(DEFAULT_DB))
    return parser


def main() -> None:
    args = build_parser().parse_args()
    path = Path(args.database)
    if not path.is_absolute():
        path = ROOT / path

    # Each store creates only its own namespaced tables and can safely share the
    # canonical SQLite file.  Browser workflows are registered later per ATS;
    # creating a generic submit workflow would weaken host and selector policy.
    CareerDatabase(path)
    observability = ObservabilityStore(path)
    BrowserWorkflowStore(path)
    DeploymentStore(path)
    fetching = FetchControlStore(path)
    MigrationRunner(path)

    flow = career_pipeline_flow()
    newly_registered = observability.register_flow(flow)
    fetch_policy = default_job_fetch_policy()
    fetch_policy_newly_registered = fetching.register_policy(fetch_policy)
    capabilities = backend_capability_authorizer()

    conn = sqlite3.connect(path)
    try:
        tables = tuple(
            row[0]
            for row in conn.execute(
                """SELECT name FROM sqlite_master
                   WHERE type='table' AND (
                     name LIKE 'ca_obs_%' OR
                     name LIKE 'browser_%' OR
                     name LIKE 'career_deployment_%' OR
                     name LIKE 'ca_fetch_%' OR
                     name='career_schema_migrations'
                   ) ORDER BY name"""
            ).fetchall()
        )
    finally:
        conn.close()

    print(json.dumps({
        "database": str(path),
        "flow_id": flow.flow_id,
        "flow_version": flow.version,
        "flow_hash": flow.content_hash,
        "flow_newly_registered": newly_registered,
        "fetch_policy_hash": fetch_policy.content_hash,
        "fetch_policy_newly_registered": fetch_policy_newly_registered,
        "capability_backends": sorted(capabilities.manifests),
        "borrowed_tables": tables,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
