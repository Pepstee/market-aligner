"""Apply the canonical host-capability profile to direct pytest runs.

The certification profile already owns the exact list of suites that cannot
execute on macOS.  Direct ``pytest`` collection must use that same owner so a
Mac run records truthful skips while Linux continues to execute the suites.
"""

from __future__ import annotations

import platform

import pytest

from scripts.jaa_certification_profile import MAC_INAPPLICABLE_TESTS


_MAC_INAPPLICABLE = frozenset(MAC_INAPPLICABLE_TESTS)
_MAC_SKIP_REASON = (
    "excluded by the canonical mac-with-retained-linux-evidence profile; "
    "current-source execution is required on the pinned Linux host"
)

# These tests exercise fixed Gigabyte/Linux filesystem identities directly.
# Keep their exclusions beside the certification-profile bridge so direct Mac
# pytest runs cannot accidentally treat an absent /proc or Linux uid as a
# product failure.  The same nodes remain mandatory on the pinned Linux host.
_DARWIN_NODE_EXCLUSIONS = {
    "test_gigabyte_current_time_service.py": frozenset(
        {"test_verified_runtime_link_accepts_exact_pinned_venv_chain"}
    ),
    "test_production_operational_surfaces.py": frozenset(
        {"test_admission_created_then_replay_are_explicit_and_non_release"}
    ),
}
_DARWIN_NODE_REASON = (
    "requires the pinned Gigabyte/Linux uid and /proc file-descriptor surface; "
    "current-source execution is required on the pinned Linux host"
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip only the profile-owned Linux suites on Darwin."""
    if platform.system() != "Darwin":
        return
    marker = pytest.mark.skip(reason=_MAC_SKIP_REASON)
    node_marker = pytest.mark.skip(reason=_DARWIN_NODE_REASON)
    for item in items:
        if item.path.name in _MAC_INAPPLICABLE:
            item.add_marker(marker)
        elif item.name in _DARWIN_NODE_EXCLUSIONS.get(item.path.name, ()):
            item.add_marker(node_marker)
