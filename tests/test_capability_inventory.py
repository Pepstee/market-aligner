from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_capability_inventory", ROOT / "scripts" / "build_capability_inventory.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_jaa_paths_are_never_normalised_as_a_separate_product() -> None:
    assert (
        MODULE._normalise_repository_path("career_automation/engine.py", jaa_only=True)
        == "internal/jaa/career_automation/engine.py"
    )
    assert (
        MODULE._normalise_tar_path(
            "home/gutua/software-factory/project/jaa/career_automation/engine.py"
        )
        == "internal/jaa/career_automation/engine.py"
    )


def test_exact_relocation_is_not_reported_as_missing() -> None:
    source = b"def retained(value: int) -> int:\n    return value + 1\n"
    inventory = MODULE.Inventory()
    inventory.add(
        logical_path="src/market_aligner/new.py",
        data=source,
        origin="canonical",
        physical_path="src/market_aligner/new.py",
    )
    inventory.add(
        logical_path="src/market_aligner/old.py",
        data=source,
        origin="git-history",
        physical_path="src/market_aligner/old.py",
    )
    records = inventory.serialise()
    retained = next(
        item
        for item in records
        if item["logical_path"].endswith("old.py") and item["symbol"] == "retained"
    )
    assert retained["status"] == "canonical_relocated_exact"


def test_changed_same_symbol_fails_closed_for_review() -> None:
    inventory = MODULE.Inventory()
    inventory.add(
        logical_path="src/market_aligner/capability.py",
        data=b"def decide():\n    return 'canonical'\n",
        origin="canonical",
        physical_path="canonical.py",
    )
    inventory.add(
        logical_path="src/market_aligner/capability.py",
        data=b"def decide():\n    return 'donor'\n",
        origin="git-history",
        physical_path="donor.py",
    )
    records = inventory.serialise()
    donor = next(
        item
        for item in records
        if item["symbol"] == "decide" and item["status"] != "canonical"
    )
    assert donor["status"] == "conflicting_variant_review"


def test_semantic_hash_ignores_source_locations() -> None:
    first = ast.parse("def f():\n    return 1\n").body[0]
    second = ast.parse("\n\ndef f():\n    return 1\n").body[0]
    assert MODULE._semantic_bytes(first) == MODULE._semantic_bytes(second)


def test_required_gmail_lifecycle_capability_is_fail_closed(tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    MODULE._write_report(report, [])
    rendered = report.read_text(encoding="utf-8")
    assert "market.lifecycle.gmail-employer-response.v1" in rendered
    assert "required_missing_owner_gate_pending" in rendered
    assert "all 146 preserved Git refs" in rendered
    assert "forbidden mutations: send, reply, archive, delete" in rendered
    assert "unknown/ambiguous" in rendered
    assert "**Canary:** withheld" in rendered
    capability = MODULE.GMAIL_LIFECYCLE_CAPABILITY
    assert capability["owner"] == "Market Aligner / internal JAA"
    assert capability["status"] == "required_missing_owner_gate_pending"
    assert "send" in capability["forbidden"]
