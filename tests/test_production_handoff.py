from __future__ import annotations

import hashlib
import inspect
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from market_aligner.applications import production_handoff as production_module
from market_aligner.applications.handoff import canonical_json_bytes
from market_aligner.applications.production_handoff import (
    PRODUCTION_CANDIDATE_AUTHORITY_PATH,
    PRODUCTION_CANDIDATE_AUTHORITY_SHA256,
    ProductionHandoffError,
    _persist_execution_receipt,
    _git_commit,
    _protected_candidate_authority,
    _research_evidence,
    _workable_identity,
    _build_production_handoff_from_authenticated_time,
)
from market_aligner.research.models import RESEARCH_ARCHIVE_ROOT_POLICY_SHA256

PROFILE_ID = "prf_" + "1" * 32
JOB_KEY = "workable:cogna:847CFBC5F4"
FLAT_URL = "https://apply.workable.com/j/847CFBC5F4"
TENANT_URL = "https://apply.workable.com/cogna/j/847CFBC5F4"
SOURCE_SHA = "a" * 64
PROMOTION_SHA = "b" * 64


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _private_tree(root: Path) -> None:
    for path in [root, *root.rglob("*")]:
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


def _archive(
    tmp_path: Path, *, url: str = FLAT_URL,
    accessed_at: str = "2026-08-21T00:00:00+00:00",
    object_schema: str = "market-aligner.canonical-collector-vacancy.v1",
):
    raw_text = "Build agentic software systems."
    envelope = {
        "authority_source_content_sha256": SOURCE_SHA, "fetched_at": accessed_at,
        "job_key": JOB_KEY, "raw_json": None, "raw_text": raw_text,
        "schema_version": object_schema, "url": url,
    }
    if object_schema == "market-aligner.canonical-collector-vacancy.v2":
        envelope.update({
            "canonical_current_content_sha256": "c" * 64,
            "collection_refresh_context_sha256": "d" * 64,
            "collection_refresh_event_id": 22,
            "collection_refresh_id": _sha(canonical_json_bytes({
                "context_sha256": "d" * 64,
                "schema_version": "market-aligner.vacancy-refresh-id.v1",
            })),
            "collection_refresh_operation_id": "cogna-refresh-r1",
            "collection_refresh_raw_object_sha256": "f" * 64,
            "collection_refresh_receipt_file_sha256": "1" * 64,
            "collection_refresh_receipt_sha256": "2" * 64,
            "collection_refresh_transition_sha256": "3" * 64,
            "promotion_receipt_sha256": PROMOTION_SHA,
        })
    object_bytes = canonical_json_bytes(envelope)
    object_sha = _sha(object_bytes)
    start = object_bytes.index(raw_text.encode())
    end = start + len(raw_text.encode())
    metadata = {
        "accessed_at": accessed_at, "citation_id": "official_job",
        "content_sha256": object_sha,
        "content_type": "application/vnd.market-aligner.canonical-vacancy+json",
        "final_url": url, "redirect_chain": [url], "requested_url": url,
        "schema_version": "market-aligner.public-research-source.v2",
        "source_kind": "canonical_vacancy", "status": 200,
        "title": "Canonical collector vacancy",
    }
    metadata_bytes = canonical_json_bytes(metadata)
    metadata_sha = _sha(metadata_bytes)
    snapshot_sha = _sha(canonical_json_bytes({
        "company": "Cogna", "job_key": JOB_KEY,
        "promotion_receipt_sha256": PROMOTION_SHA,
        "schema_version": "market-aligner.research-vacancy-snapshot.v1",
        "source_content_sha256": SOURCE_SHA, "title": "Software Engineer", "url": url,
    }))
    dossier = {
        "canonical_vacancy_object_sha256": object_sha,
        "citations": [{"accessed_at": accessed_at, "citation_id": "official_job",
            "content_sha256": object_sha, "source_kind": "canonical_vacancy",
            "title": "Canonical collector vacancy", "url": url}],
        "claims": [{"citation_ids": ["official_job"], "claim": raw_text,
            "confidence": 1.0, "supports": [{"citation_id": "official_job",
            "excerpt_sha256": _sha(raw_text.encode()), "excerpt": raw_text,
            "selector": f"bytes:{start}-{end}"}]}],
        "company": "Cogna", "job_key": JOB_KEY, "profile_id": PROFILE_ID,
        "promotion_receipt_sha256": PROMOTION_SHA, "role": "Software Engineer",
        "schema_version": "market-aligner.employer-dossier.v2",
        "source_content_sha256": SOURCE_SHA, "unknowns": [],
        "vacancy_snapshot_sha256": snapshot_sha,
    }
    dossier_bytes = json.dumps(dossier, ensure_ascii=False, sort_keys=True).encode()
    dossier_sha = _sha(dossier_bytes)
    receipt_body = {
        "application_authority": False, "claim_semantic_authority": "verbatim_source_text_v2",
        "canonical_vacancy_object_sha256": object_sha, "dossier_sha256": dossier_sha,
        "entries": [{"citation_id": "official_job", "metadata_sha256": metadata_sha,
                     "object_sha256": object_sha}],
        "job_key": JOB_KEY, "production_authority": True, "profile_id": PROFILE_ID,
        "promotion_receipt_sha256": PROMOTION_SHA, "release_authority": False,
        "schema_version": "market-aligner.public-research-materialization.v2",
        "source_content_sha256": SOURCE_SHA, "vacancy_snapshot_sha256": snapshot_sha,
    }
    semantic_sha = _sha(canonical_json_bytes(receipt_body))
    receipt_bytes = canonical_json_bytes({**receipt_body, "semantic_receipt_sha256": semantic_sha})
    root = tmp_path / "state" / "public-employer-research-v2"
    (root / "objects").mkdir(parents=True)
    (root / "metadata").mkdir()
    (root / "receipts").mkdir()
    (root / "objects" / object_sha).write_bytes(object_bytes)
    (root / "metadata" / f"{metadata_sha}.json").write_bytes(metadata_bytes)
    (root / "receipts" / f"{semantic_sha}.json").write_bytes(receipt_bytes)
    _private_tree(tmp_path)
    row = {
        "archive_root_identity": "state/public-employer-research-v2",
        "archive_root_policy_sha256": RESEARCH_ARCHIVE_ROOT_POLICY_SHA256,
        "canonical_vacancy_object_sha256": object_sha, "dossier_hash": dossier_sha,
        "promotion_receipt_sha256": PROMOTION_SHA, "receipt_file_sha256": _sha(receipt_bytes),
        "receipt_relative_path": f"receipts/{semantic_sha}.json",
        "schema_version": "market-aligner.research-store-binding.v2",
        "semantic_receipt_sha256": semantic_sha, "source_content_sha256": SOURCE_SHA,
        "vacancy_snapshot_sha256": snapshot_sha,
    }
    return row, dossier, dossier_bytes, object_bytes, root


def _verify(tmp_path: Path, row: dict, dossier: dict, dossier_bytes: bytes, *, url=FLAT_URL, now=None):
    return _research_evidence(
        tmp_path, row, profile_id=PROFILE_ID, source_job_key=JOB_KEY, canonical_url=url,
        dossier_bytes=dossier_bytes, dossier_document=dossier,
        promotion_receipt_sha256=PROMOTION_SHA, source_content_sha256=SOURCE_SHA,
        now=now or datetime(2026, 8, 21, 0, 1, tzinfo=timezone.utc),
        maximum_age_seconds=21_600,
        expected_archive_root_identity="state/public-employer-research-v2",
    )


def _rebind_dossier_receipt(row: dict, dossier_bytes: bytes, root: Path) -> None:
    old_path = root / row["receipt_relative_path"]
    receipt = json.loads(old_path.read_bytes())
    receipt.pop("semantic_receipt_sha256")
    receipt["dossier_sha256"] = _sha(dossier_bytes)
    semantic = _sha(canonical_json_bytes(receipt))
    exact = canonical_json_bytes({**receipt, "semantic_receipt_sha256": semantic})
    old_path.unlink()
    new_path = root / "receipts" / f"{semantic}.json"
    new_path.write_bytes(exact)
    new_path.chmod(0o600)
    row.update({
        "dossier_hash": _sha(dossier_bytes),
        "semantic_receipt_sha256": semantic,
        "receipt_file_sha256": _sha(exact),
        "receipt_relative_path": f"receipts/{semantic}.json",
    })


@pytest.mark.parametrize("url,expected", [(FLAT_URL, (None, "847CFBC5F4")), (TENANT_URL, ("cogna", "847CFBC5F4"))])
def test_workable_flat_and_tenant_routes(url: str, expected: tuple[str | None, str]) -> None:
    assert _workable_identity(url) == expected


@pytest.mark.parametrize("url", [
    "https://apply.workable.com/wrong/j/847CFBC5F4/extra",
    "https://evil.test/j/847CFBC5F4", "https://apply.workable.com/j/WRONG",
    "https://apply.workable.com:bad/j/847CFBC5F4",
])
def test_workable_rejects_ambiguous_identity(url: str) -> None:
    with pytest.raises(ProductionHandoffError):
        _workable_identity(url)


def test_v2_revalidates_flat_route_and_exact_support(tmp_path: Path) -> None:
    row, dossier, dossier_bytes, object_bytes, _ = _archive(tmp_path)
    first = _verify(tmp_path, row, dossier, dossier_bytes)
    second = _verify(tmp_path, row, dossier, dossier_bytes)
    assert first == second and first[1] == object_bytes


def test_research_accepts_exact_refresh_bridge_v2_object(tmp_path: Path) -> None:
    row, dossier, dossier_bytes, object_bytes, _ = _archive(
        tmp_path, object_schema="market-aligner.canonical-collector-vacancy.v2"
    )
    assert _verify(tmp_path, row, dossier, dossier_bytes)[1] == object_bytes


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "market-aligner.canonical-collector-vacancy.v3"),
        ("collection_refresh_event_id", "22"),
        ("collection_refresh_id", "not-a-digest"),
        ("promotion_receipt_sha256", "f" * 64),
        ("collection_refresh_operation_id", ""),
    ],
)
def test_research_rejects_refresh_bridge_v2_schema_and_field_substitution(
    tmp_path: Path, field: str, value: object
) -> None:
    row, dossier, dossier_bytes, object_bytes, root = _archive(
        tmp_path, object_schema="market-aligner.canonical-collector-vacancy.v2"
    )
    envelope = json.loads(object_bytes)
    envelope[field] = value
    replacement = canonical_json_bytes(envelope)
    replacement_sha = _sha(replacement)
    old_sha = row["canonical_vacancy_object_sha256"]
    (root / "objects" / old_sha).unlink()
    (root / "objects" / replacement_sha).write_bytes(replacement)
    (root / "objects" / replacement_sha).chmod(0o600)
    dossier["canonical_vacancy_object_sha256"] = replacement_sha
    dossier["citations"][0]["content_sha256"] = replacement_sha
    dossier_bytes = json.dumps(dossier, ensure_ascii=False, sort_keys=True).encode()
    row["canonical_vacancy_object_sha256"] = replacement_sha
    receipt_path = root / row["receipt_relative_path"]
    receipt = json.loads(receipt_path.read_bytes())
    receipt.pop("semantic_receipt_sha256")
    old_metadata_sha = receipt["entries"][0]["metadata_sha256"]
    old_metadata_path = root / "metadata" / f"{old_metadata_sha}.json"
    metadata = json.loads(old_metadata_path.read_bytes())
    metadata["content_sha256"] = replacement_sha
    metadata_bytes = canonical_json_bytes(metadata)
    metadata_sha = _sha(metadata_bytes)
    old_metadata_path.unlink()
    new_metadata_path = root / "metadata" / f"{metadata_sha}.json"
    new_metadata_path.write_bytes(metadata_bytes)
    new_metadata_path.chmod(0o600)
    receipt["canonical_vacancy_object_sha256"] = replacement_sha
    receipt["entries"][0]["object_sha256"] = replacement_sha
    receipt["entries"][0]["metadata_sha256"] = metadata_sha
    receipt["dossier_sha256"] = _sha(dossier_bytes)
    semantic = _sha(canonical_json_bytes(receipt))
    exact = canonical_json_bytes({**receipt, "semantic_receipt_sha256": semantic})
    receipt_path.unlink()
    new_path = root / "receipts" / f"{semantic}.json"
    new_path.write_bytes(exact)
    new_path.chmod(0o600)
    row.update({
        "dossier_hash": _sha(dossier_bytes),
        "semantic_receipt_sha256": semantic,
        "receipt_file_sha256": _sha(exact),
        "receipt_relative_path": f"receipts/{semantic}.json",
    })
    with pytest.raises(ProductionHandoffError, match="research_object"):
        _verify(tmp_path, row, dossier, dossier_bytes)


@pytest.mark.parametrize("field", [
    "canonical_vacancy_object_sha256", "semantic_receipt_sha256", "receipt_file_sha256",
    "vacancy_snapshot_sha256", "promotion_receipt_sha256", "dossier_hash",
])
def test_v2_rejects_every_binding_substitution(tmp_path: Path, field: str) -> None:
    row, dossier, dossier_bytes, _, _ = _archive(tmp_path)
    row[field] = "f" * 64
    with pytest.raises(ProductionHandoffError):
        _verify(tmp_path, row, dossier, dossier_bytes)


@pytest.mark.parametrize("mutation", ["selector", "excerpt", "hash", "claim", "canonical"])
def test_v2_rejects_unsupported_claims_and_canonical_substitution(tmp_path: Path, mutation: str) -> None:
    row, dossier, dossier_bytes, _, root = _archive(tmp_path)
    if mutation == "selector": dossier["claims"][0]["supports"][0]["selector"] = "bytes:0-1"
    elif mutation == "excerpt": dossier["claims"][0]["supports"][0]["excerpt"] = "invented"
    elif mutation == "hash": dossier["claims"][0]["supports"][0]["excerpt_sha256"] = "f" * 64
    elif mutation == "claim": dossier["claims"][0]["claim"] = "unsupported paraphrase"
    else: dossier["canonical_vacancy_object_sha256"] = "f" * 64
    dossier_bytes = json.dumps(dossier, ensure_ascii=False, sort_keys=True).encode()
    _rebind_dossier_receipt(row, dossier_bytes, root)
    expected = "research_dossier" if mutation == "canonical" else "research_support"
    with pytest.raises(ProductionHandoffError, match=expected):
        _verify(tmp_path, row, dossier, dossier_bytes)


def test_v2_rejects_traversal_and_symlink_components(tmp_path: Path) -> None:
    row, dossier, dossier_bytes, _, root = _archive(tmp_path)
    row["receipt_relative_path"] = f"../../receipts/{row['semantic_receipt_sha256']}.json"
    with pytest.raises(ProductionHandoffError, match="research_contract_v2_required"):
        _verify(tmp_path, row, dossier, dossier_bytes)
    row["receipt_relative_path"] = f"receipts/{row['semantic_receipt_sha256']}.json"
    real = root.rename(root.with_name("real-archive"))
    root.symlink_to(real, target_is_directory=True)
    with pytest.raises((ProductionHandoffError, OSError)):
        _verify(tmp_path, row, dossier, dossier_bytes)


def test_v2_rejects_writable_archive_category(tmp_path: Path) -> None:
    row, dossier, dossier_bytes, _, root = _archive(tmp_path)
    (root / "receipts").chmod(0o770)
    with pytest.raises(ProductionHandoffError, match="archive category is not private"):
        _verify(tmp_path, row, dossier, dossier_bytes)


def test_v2_rejects_alternate_private_archive_identity_before_read(tmp_path: Path) -> None:
    row, dossier, dossier_bytes, _, root = _archive(tmp_path)
    alternate = root.with_name("alternate-private-archive")
    root.rename(alternate)
    row["archive_root_identity"] = "state/alternate-private-archive"
    with pytest.raises(ProductionHandoffError, match="research_archive_authority"):
        _verify(tmp_path, row, dossier, dossier_bytes)


def test_execution_receipt_is_private_create_or_exact_and_rejects_symlink(tmp_path: Path) -> None:
    root = tmp_path / "execution"
    root.mkdir()
    _private_tree(tmp_path)
    exact = canonical_json_bytes({"schema_version": "receipt.v1"})
    semantic = _sha(exact)
    path = _persist_execution_receipt(root, semantic, exact)
    assert path.read_bytes() == exact and path.stat().st_mode & 0o777 == 0o600
    assert _persist_execution_receipt(root, semantic, exact) == path
    path.unlink()
    path.symlink_to(tmp_path / "escape")
    with pytest.raises((ProductionHandoffError, OSError)):
        _persist_execution_receipt(root, semantic, exact)


def test_candidate_authority_is_deployment_owned_not_a_build_argument(tmp_path: Path) -> None:
    parameters = inspect.signature(_build_production_handoff_from_authenticated_time).parameters
    assert "candidate_authority_path" not in parameters
    assert "candidate_authority_sha256" not in parameters
    assert PRODUCTION_CANDIDATE_AUTHORITY_PATH.is_absolute()
    assert PRODUCTION_CANDIDATE_AUTHORITY_SHA256 == "85234a4fa0fbfc96d6c6af85a4c169d149de42b4835c1f13d94cf418723470f9"
    authority = {"candidate_projection": {"projection_sha256": "a" * 64},
                 "schema_version": "jaa.production-candidate-authority.v2"}
    path = tmp_path / "candidate-authority.json"
    path.write_bytes(canonical_json_bytes(authority))
    _private_tree(tmp_path)
    assert _protected_candidate_authority(path, {"authority_projection_sha256": "a" * 64}, _sha(path.read_bytes()))


def test_producer_identity_requires_exact_clean_executing_head(monkeypatch, tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    source = repository / "src" / "market_aligner" / "applications"
    source.mkdir(parents=True)
    executing = source / "production_handoff.py"
    executing.write_text("# exact executing source\n")
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repository, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repository, check=True)
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repository, check=True)
    monkeypatch.setattr(production_module, "__file__", str(executing))
    expected = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repository, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    assert _git_commit(repository) == expected
    (repository / "untracked-authority.txt").write_text("not allowed")
    with pytest.raises(ProductionHandoffError, match="producer_dirty"):
        _git_commit(repository)
