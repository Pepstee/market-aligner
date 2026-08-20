"""Machine-readable, fail-closed outcome reporting for the JAA-04 certifier."""

from __future__ import annotations

import json
import os
from pathlib import Path


_passed_by_suite: dict[str, int] = {}
_deselected = 0


def pytest_runtest_logreport(report: object) -> None:
    if (getattr(report, "when", None) == "call"
            and getattr(report, "outcome", None) == "passed"
            and not hasattr(report, "wasxfail")):
        suite = str(getattr(report, "nodeid")).split("::", 1)[0]
        suite = Path(suite).name
        _passed_by_suite[suite] = _passed_by_suite.get(suite, 0) + 1


def pytest_deselected(items: list[object]) -> None:
    global _deselected
    _deselected += len(items)


def pytest_sessionfinish(session: object, exitstatus: int) -> None:
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    stats = reporter.stats if reporter is not None else {}
    result = {
        "collected": int(getattr(session, "testscollected", -1)),
        "exit_code": int(exitstatus),
        "outcomes": {
            name: len(stats.get(name, ()))
            for name in ("passed", "skipped", "xfailed", "xpassed", "failed", "error")
        },
        "deselected": _deselected,
        "passed_by_suite": dict(sorted(_passed_by_suite.items())),
    }
    Path(os.environ["JAA04_PYTEST_REPORT"]).write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
