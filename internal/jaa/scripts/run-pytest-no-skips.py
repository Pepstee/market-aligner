#!/usr/bin/env python3
"""Run pytest and fail if any collected or executed test is skipped."""

from __future__ import annotations

import sys

import pytest


class _NoSkips:
    def __init__(self) -> None:
        self.skips: set[tuple[str, str]] = set()

    def pytest_collectreport(self, report: object) -> None:
        if getattr(report, "skipped", False):
            self.skips.add(
                (
                    str(getattr(report, "nodeid", "collection")),
                    "collection",
                )
            )

    def pytest_runtest_logreport(self, report: object) -> None:
        if getattr(report, "skipped", False):
            self.skips.add(
                (
                    str(getattr(report, "nodeid", "test")),
                    str(getattr(report, "when", "unknown")),
                )
            )


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        raise SystemExit("run-pytest-no-skips.py requires explicit pytest targets")
    plugin = _NoSkips()
    result = int(pytest.main(arguments, plugins=[plugin]))
    if plugin.skips:
        for nodeid, phase in sorted(plugin.skips):
            print(f"MANDATORY SKIP: {nodeid} ({phase})", file=sys.stderr)
        return result or 1
    return result


if __name__ == "__main__":
    raise SystemExit(main())
