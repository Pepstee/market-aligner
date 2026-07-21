#!/usr/bin/env python3
"""Fail-closed validation and revision-bound certification of JAA-04 bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.employer_research import RawResponseCache, content_hash, load_frozen_dossiers  # noqa: E402
from career_automation.corpus_publication import sha256_file, validate_inventory  # noqa: E402
from career_automation.opportunity1 import reassess_opportunity1  # noqa: E402
from tracked_source_revision import source_content_revision  # noqa: E402

FORMAT = "jaa04-revision-certification/v2"


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def revision() -> str:
    result = subprocess.run(("git", "rev-parse", "HEAD^{commit}"), cwd=ROOT,
                            text=True, capture_output=True, check=True)
    return result.stdout.strip()


def certify(capture: Path, destination: Path) -> Path:
    receipt_path = capture / "capture_receipt.json"
    manifest_path = capture / "research_manifest.json"
    dossiers_path = capture / "frozen_dossiers.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if receipt.get("schema_version") != "jaa04.capture-receipt.v4" or receipt.get("status") != "SUCCESS":
        raise ValueError("capture has no authentic acquisition receipt")
    if (receipt.get("manifest_sha256") != sha(manifest_path)
            or receipt.get("dossiers_sha256") != sha(dossiers_path)):
        raise ValueError("capture metadata or dossier bytes were modified")
    inventory_path = capture / "corpus_inventory.json"
    validate_inventory(capture)
    if receipt.get("inventory_sha256") != sha256_file(inventory_path):
        raise ValueError("capture inventory is not bound to the acquisition receipt")
    if (manifest.get("schema_version") != "jaa04.research-manifest.v4"
            or manifest.get("opportunity0_queue_size", 0) < 30
            or len(manifest.get("records", [])) != 30
            or manifest.get("records_hash") != content_hash(manifest["records"])):
        raise ValueError("manifest is not bound to the frozen admitted queue")
    dossiers = load_frozen_dossiers(dossiers_path, RawResponseCache(capture / "raw"), strict_corpus=True)
    dossier_by_key = {row["job_key"]: row for row in dossiers}
    record_keys = [row.get("job_key") for row in manifest["records"]]
    if (len(record_keys) != len(set(record_keys))
            or set(record_keys) != set(dossier_by_key)):
        raise ValueError("vacancy-to-dossier linkage is incomplete")
    for record in manifest["records"]:
        dossier = dossier_by_key[record["job_key"]]
        reassessment = record.get("opportunity1_reassessment")
        if (record.get("dossier_hash") != content_hash(dossier)
                or record.get("source_ids") != [source["id"] for source in dossier["sources"]]
                or record.get("capture_identities") != [
                    {"url": source["url"], "sha256": source["content_sha256"]}
                    for source in dossier["sources"]
                ]
                or not isinstance(reassessment, dict)
                or reassessment.get("dossier_hash") != record.get("dossier_hash")
                or reassessment.get("opportunity0_score_bp") is None
                or reassessment.get("score_bp") is None
                or reassessment.get("decision") not in {"pass", "reject"}
                or not isinstance(reassessment.get("changes"), list)
                or not isinstance(reassessment.get("policy_hash"), str)
                or not reassessment["policy_hash"]):
            raise ValueError("manifest dossier or capture identity binding is invalid")
        claim_ids = {str(claim.get("id")) for claim in dossier.get("claims", [])}
        changes = reassessment["changes"]
        if any(not isinstance(change, dict)
               or str(change.get("claim_id")) not in claim_ids for change in changes):
            raise ValueError("Opportunity-1 changes do not match the bound dossier")
        expected = reassess_opportunity1(reassessment["opportunity0_score_bp"], changes)
        if (expected.score_bp != reassessment["score_bp"]
                or expected.decision != reassessment["decision"]
                or expected.policy_hash != reassessment["policy_hash"]
                or [vars(change) for change in expected.changes] != changes):
            raise ValueError("Opportunity-1 reassessment is inconsistent")
    raw_files = sorted(path for path in (capture / "raw").rglob("*") if path.is_file())
    raw_hash = hashlib.sha256(b"".join(
        path.relative_to(capture).as_posix().encode() + b"\0" + path.read_bytes()
        for path in raw_files)).hexdigest()
    if raw_hash != receipt.get("raw_corpus_sha256"):
        raise ValueError("raw authority cache was modified")
    current_revision = revision()
    current_content_revision = source_content_revision(ROOT)
    if (receipt.get("source_revision") != current_revision
            or receipt.get("source_content_revision") != current_content_revision):
        raise ValueError("capture is not bound to the current source revision")
    certificate = canonical({
        "format": FORMAT, "status": "SUCCESS", "source_revision": current_revision,
        "source_content_revision": current_content_revision,
        "capture_receipt_sha256": sha(receipt_path),
        "manifest_sha256": sha(manifest_path), "dossiers_sha256": sha(dossiers_path),
        "raw_corpus_sha256": raw_hash,
    })
    if destination.suffix != ".json":
        destination = destination / f"sha256-{hashlib.sha256(certificate).hexdigest()}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.read_bytes() != certificate:
        raise ValueError("existing certification receipt conflicts with validated bytes")
    if not destination.exists():
        temporary = destination.with_suffix(".tmp")
        temporary.write_bytes(certificate)
        os.replace(temporary, destination)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, required=True,
                        help="external published corpus pointer or release path")
    parser.add_argument("--receipt", type=Path,
                        default=ROOT / "runtime_evidence/jaa04")
    args = parser.parse_args()
    try:
        receipt = certify(args.capture.resolve(), args.receipt.resolve())
    except Exception as exc:
        print(f"JAA-04 acceptance: ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"JAA-04 acceptance: PASS ({receipt})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
