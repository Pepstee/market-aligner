#!/usr/bin/env python3
"""Fail-closed validation and revision-bound certification of JAA-04 bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.employer_research import RawResponseCache, content_hash, load_frozen_dossiers  # noqa: E402
from career_automation.admission_evidence import (  # noqa: E402
    raw_evidence_hash,
    validate_admission_evidence,
)
from career_automation.corpus_publication import sha256_file, validate_inventory  # noqa: E402
from career_automation.opportunity1 import reassess_opportunity1  # noqa: E402
from career_automation.public_access import PublicAccessPolicy  # noqa: E402
from scripts.capture_jaa_04 import load_admitted_input  # noqa: E402
from tracked_source_revision import source_content_revision  # noqa: E402

FORMAT = "jaa04-revision-certification/v4"


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _external(path: Path, *, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return resolved
    raise ValueError(f"{label} must be outside the product repository")


def revision() -> str:
    result = subprocess.run(("git", "rev-parse", "HEAD^{commit}"), cwd=ROOT,
                            text=True, capture_output=True, check=True)
    return result.stdout.strip()


def _load_access_policy(capture: Path, path: Path) -> PublicAccessPolicy:
    # Certification is a new authority decision, not merely a replay at the
    # historical capture clock.  Load against the certifier's current UTC
    # time so an expired attestation cannot be made fresh by an old (or
    # attacker-future-dated) dossier timestamp.
    policy = PublicAccessPolicy.load(path)
    envelope = json.loads((capture / "frozen_dossiers.json").read_text(encoding="utf-8"))
    retrieved: list[datetime] = []
    for dossier in envelope.get("dossiers", []):
        for source in dossier.get("sources", []):
            value = datetime.fromisoformat(str(source.get("retrieved_at", "")).replace("Z", "+00:00"))
            if value.tzinfo is None:
                raise ValueError("capture retrieval timestamps must include a timezone")
            retrieved.append(value.astimezone(timezone.utc))
    if not retrieved:
        raise ValueError("capture has no retrieval time for access-policy replay")
    if max(retrieved) > policy.now:
        raise ValueError("capture retrieval time is future-dated")
    return policy


def _replay_official_admission(
    capture: Path,
    admission: dict[str, object],
    manifest_records: list[dict[str, object]],
    access_policies: dict[str, PublicAccessPolicy],
) -> None:
    """Independently replay official-v2 semantics from published bytes."""
    if admission.get("mode") != "official-json-v2":
        return
    if admission.get("snapshot_path") != "admission/queue_snapshot.json":
        raise ValueError("official admission replay requires its exact portable snapshot")
    snapshot = capture / "admission/queue_snapshot.json"
    raw_root = capture / "admission/raw"
    admitted = load_admitted_input(
        snapshot,
        access_policies=access_policies,
        raw_root_override=raw_root,
    )
    manifest_keys = {str(record.get("job_key", "")) for record in manifest_records}
    if set(admitted) != manifest_keys:
        raise ValueError("official admission replay differs from manifest identities")


def certify(capture: Path, destination: Path, access_policy_path: Path) -> Path:
    capture = _external(capture, label="capture")
    destination = _external(destination, label="certification receipt")
    access_policy_path = _external(access_policy_path, label="access policy")
    receipt_path = capture / "capture_receipt.json"
    manifest_path = capture / "research_manifest.json"
    dossiers_path = capture / "frozen_dossiers.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if receipt.get("schema_version") != "jaa04.capture-receipt.v6" or receipt.get("status") != "SUCCESS":
        raise ValueError("capture has no authentic acquisition receipt")
    access_policy = _load_access_policy(capture, access_policy_path)
    if receipt.get("access_policy_sha256") != access_policy.policy_sha256:
        raise ValueError("capture is not bound to the operator-presented access policy")
    access_policies = {access_policy.policy_sha256: access_policy}
    if (receipt.get("manifest_sha256") != sha(manifest_path)
            or receipt.get("dossiers_sha256") != sha(dossiers_path)):
        raise ValueError("capture metadata or dossier bytes were modified")
    inventory_path = capture / "corpus_inventory.json"
    validate_inventory(capture)
    if receipt.get("inventory_sha256") != sha256_file(inventory_path):
        raise ValueError("capture inventory is not bound to the acquisition receipt")
    if (manifest.get("schema_version") != "jaa04.research-manifest.v6"
            or manifest.get("opportunity0_queue_size", 0) < 30
            or len(manifest.get("records", [])) != 30
            or manifest.get("records_hash") != content_hash(manifest["records"])):
        raise ValueError("manifest is not bound to the frozen admitted queue")
    admission = manifest.get("admission_evidence")
    if not isinstance(admission, dict):
        raise ValueError("manifest has no portable Opportunity-0 evidence")
    validate_admission_evidence(
        capture,
        admission,
        manifest["records"],
        expected_snapshot_sha256=str(receipt.get("queue_snapshot_sha256", "")),
        access_policies=access_policies,
    )
    _replay_official_admission(
        capture,
        admission,
        manifest["records"],
        access_policies,
    )
    if (receipt.get("queue_input_sha256") != admission.get("source_snapshot_sha256")
            or receipt.get("queue_snapshot_sha256") != admission.get("snapshot_sha256")):
        raise ValueError("capture receipt does not bind the admission snapshot")
    dossiers = load_frozen_dossiers(
        dossiers_path,
        RawResponseCache(capture / "raw"),
        strict_corpus=True,
        access_policies=access_policies,
    )
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
    raw_hash = raw_evidence_hash(capture)
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
        "queue_snapshot_sha256": admission["snapshot_sha256"],
        "raw_corpus_sha256": raw_hash,
        "access_policy_sha256": access_policy.policy_sha256,
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
    parser.add_argument("--access-policy", type=Path, required=True,
                        help="operator-presented human terms-review policy used by acquisition")
    parser.add_argument("--receipt", type=Path, required=True,
                        help="external content-addressed certification receipt path")
    args = parser.parse_args()
    try:
        receipt = certify(
            args.capture.resolve(),
            args.receipt.resolve(),
            args.access_policy.resolve(),
        )
    except Exception as exc:
        print(f"JAA-04 acceptance: ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"JAA-04 acceptance: PASS ({receipt})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
