from __future__ import annotations

import ast
import importlib.util
import subprocess
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


def test_reviewed_adaptation_closes_only_the_exact_donor_feature() -> None:
    inventory = MODULE.Inventory()
    inventory.add(
        logical_path="src/market_aligner/donor.py",
        data=b"def decide():\n    return 'donor'\n",
        origin="git-history",
        physical_path="donor.py",
    )
    unresolved = inventory.serialise()[0]
    disposition = {
        "canonical_target": "src/market_aligner/current.py:decide",
        "feature_id": unresolved["feature_id"],
        "ledger_entry_id": "ma-test",
        "reason": "adapted to the current contract",
        "schema": MODULE.DISPOSITION_SCHEMA,
        "status": "adopted_adapted",
    }

    reviewed = inventory.serialise({unresolved["feature_id"]: disposition})[0]

    assert reviewed["status"] == "adopted_adapted"
    assert reviewed["reviewed_disposition"] == disposition


def test_repository_dispositions_are_ledger_bound_and_target_real_code() -> None:
    dispositions = MODULE._load_dispositions(
        ROOT / "docs/migration/capability-dispositions.jsonl"
    )
    ledger_ids = {
        __import__("json").loads(line)["entry_id"]
        for line in (ROOT / "docs/migration/ledger.jsonl").read_text().splitlines()
        if line.strip()
    }
    assert dispositions
    for value in dispositions.values():
        assert value["ledger_entry_id"] in ledger_ids
        for item in value["canonical_target"].split("+"):
            target = item.split(":", 1)[0]
            assert (ROOT / target).is_file()


def test_semantic_hash_ignores_source_locations() -> None:
    first = ast.parse("def f():\n    return 1\n").body[0]
    second = ast.parse("\n\ndef f():\n    return 1\n").body[0]
    assert MODULE._semantic_bytes(first) == MODULE._semantic_bytes(second)


def test_canonical_files_include_staged_new_sources(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    source = tmp_path / "new_capability.py"
    source.write_text("def adopted():\n    return True\n", encoding="utf-8")
    subprocess.run(["git", "add", "new_capability.py"], cwd=tmp_path, check=True)

    files = dict(MODULE._canonical_files(tmp_path))

    assert files["new_capability.py"] == source.read_bytes()


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
