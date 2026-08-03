"""Evidence-bound JAA-05/06/07/08 preparation for the CloudCops canary.

This module performs local, deterministic preparation only.  It reads exact,
hash-bound inputs, writes the existing JAA lifecycle database and publishes the
artifacts rendered by JAA-07.  It has no browser, HTTP, form-fill or submit
capability.  A JAA-08 release is issued only when the caller explicitly arms
the operation and supplies the exact operator-authority bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .application_artifacts import PublishedArtifactReceipt, publish_application_artifacts
from .application_compiler import CandidateContact, ProductionApplicationCompiler
from .application_strategy import ApplicationStrategyStore
from .candidate_graph import CandidateGraph
from .database import CareerDatabase
from .employer_research import (
    Citation,
    EmployerResearchWorker,
    FRESHNESS_DAYS,
    IntelligenceKind,
    Opportunity1Coordinator,
    RawResponseCache,
)
from .engine import OpportunityGate, scored_job_from_payload
from .evidence_matching import (
    InferenceReceipt,
    MatchProposal,
    MatchingPolicy,
    Requirement,
    candidate_graph_evidence,
    evidence_projection_hash,
    matching_input_hash,
)
from .gap_optimizer import FitAssessmentReceipt, FitAssessmentStore
from .personio_live_adapter import (
    ADAPTER_ID,
    ADAPTER_VERSION,
    APPLICATION_URL,
    EMPLOYER_KEY,
    FORM_SCHEMA_SHA256,
    FROZEN_KEY,
    PERSONIO_ALIAS,
    VACANCY_ID,
    ContactProfileBinding,
    DuplicateCheck,
    PersonioApplication,
)
from .release_gate import (
    ApplicationCompilation,
    ApplicationCompilationStore,
    IssuedRelease,
    OfficialRouteBinding,
    ReleaseGateStore,
)
from .rendering import ApplicationArtifacts, render_pdf_artifacts


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_VACANCY_URL = "https://cloudcops.jobs.personio.com/job/2183016?language=en"
CANONICAL_SOURCE_URL = "https://cloudcops.jobs.personio.com/job/2183016"
ROLE_TITLE = "Junior DevOps / Cloud Engineer"
COMPANY_NAME = "CloudCops"
POLICY = MatchingPolicy()
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_REQUIREMENT_KEYS = (
    "cloud_automation",
    "major_cloud",
    "git",
    "linux",
    "shell",
    "learning_curiosity",
    "team_communication",
)
PROOF_CLASS_BY_KIND = {
    "credential": "credential",
    "portfolio_artifact": "portfolio_artifact",
    "employment_record": "employment_record",
    "test_result": "test_result",
    "work_artifact": "work_artifact",
    "external_outcome": "external_outcome",
}


class CloudCopsReleaseError(RuntimeError):
    """The release preparation failed an exact authority boundary."""


@dataclass(frozen=True)
class BoundFile:
    path: Path
    sha256: str

    def __post_init__(self) -> None:
        if HEX_64.fullmatch(self.sha256) is None:
            raise ValueError("bound file hash must be a lowercase SHA-256")


@dataclass(frozen=True)
class CloudCopsReleaseInputs:
    ranked_snapshot: BoundFile
    raw_vacancy: BoundFile
    official_role_capture: BoundFile
    approved_evidence_packet: BoundFile
    authoritative_contact_record: BoundFile
    work_right_evidence: BoundFile
    artifact_root: Path
    runtime_database: Path
    operator_authority: BoundFile | None = None
    arm_release: bool = False

    def __post_init__(self) -> None:
        if self.arm_release and self.operator_authority is None:
            raise ValueError("armed release requires hash-bound operator authority")


@dataclass(frozen=True)
class CloudCopsReleasePreparation:
    status: str
    fit: FitAssessmentReceipt
    blocker_codes: tuple[str, ...]
    matched_evidence: Mapping[str, str]
    publication: PublishedArtifactReceipt | None = None
    compilation: ApplicationCompilation | None = None
    personio_application: PersonioApplication | None = field(default=None, repr=False)
    gate: ReleaseGateStore | None = field(default=None, repr=False)
    source: object | None = field(default=None, repr=False)
    artifacts: ApplicationArtifacts | None = field(default=None, repr=False)
    contact: CandidateContact | None = field(default=None, repr=False)
    questions: dict[str, tuple[str, str]] | None = field(default=None, repr=False)
    issued: IssuedRelease | None = field(default=None, repr=False)

    @property
    def token_sha256(self) -> str | None:
        return None if self.issued is None else self.issued.token_sha256

    def public_document(self) -> dict[str, object]:
        """Return a hash-only status view; raw release authority is omitted."""

        return {
            "schema": "jaa11.cloudcops-release-preparation.v1",
            "status": self.status,
            "fit_run_id": self.fit.run_id,
            "fit_status": self.fit.status,
            "blocker_codes": list(self.blocker_codes),
            "matched_evidence": dict(sorted(self.matched_evidence.items())),
            "artifact_set_sha256": (
                None if self.publication is None else self.publication.artifact_set_sha256
            ),
            "artifact_receipt_sha256": (
                None if self.publication is None else self.publication.receipt_sha256
            ),
            "compilation_id": (
                None if self.compilation is None else self.compilation.compilation_id
            ),
            "release_manifest_sha256": (
                None
                if self.issued is None
                else self.issued.manifest.release_manifest_sha256
            ),
            "release_token_sha256": self.token_sha256,
            "external_action_capability": False,
        }


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_bound_file(bound: BoundFile, label: str) -> bytes:
    path = Path(bound.path)
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CloudCopsReleaseError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise CloudCopsReleaseError(f"{label} must be a regular non-symlink file")
    data = resolved.read_bytes()
    after = path.lstat()
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    )
    if identity_before != identity_after or hashlib.sha256(data).hexdigest() != bound.sha256:
        raise CloudCopsReleaseError(f"{label} differs from its approved bytes")
    return data


def _object(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CloudCopsReleaseError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CloudCopsReleaseError(f"{label} must be a JSON object")
    return value


def _exact_rank_entry(snapshot: Mapping[str, Any], raw_bytes: bytes) -> dict[str, Any]:
    if snapshot.get("schema_version") != "jaa11.live-ranked-vacancy-snapshot.v1":
        raise CloudCopsReleaseError("ranked snapshot schema is unsupported")
    expected_snapshot = dict(snapshot)
    stored_snapshot_hash = expected_snapshot.pop("snapshot_sha256", None)
    if stored_snapshot_hash != _hash(expected_snapshot):
        raise CloudCopsReleaseError("ranked snapshot internal hash is invalid")
    entries = snapshot.get("entries")
    if not isinstance(entries, list):
        raise CloudCopsReleaseError("ranked snapshot entries are missing")
    matches = [row for row in entries if isinstance(row, dict) and row.get("rank") == 32]
    if len(matches) != 1:
        raise CloudCopsReleaseError("ranked snapshot has no unique rank-32 entry")
    entry = matches[0]
    expected = {
        "key": FROZEN_KEY,
        "board": "himalayas",
        "company": COMPANY_NAME,
        "job_title": ROLE_TITLE,
        "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }
    if any(entry.get(key) != value for key, value in expected.items()):
        raise CloudCopsReleaseError("rank-32 identity differs from CloudCops authority")
    if entry.get("url") != FROZEN_KEY.removeprefix("himalayas:"):
        raise CloudCopsReleaseError("rank-32 source URL differs from frozen identity")
    return entry


def _official_capture(value: Mapping[str, Any], capture_bytes: bytes) -> dict[str, Any]:
    if value.get("schema_version") != "jaa11.cloudcops-official-role-capture.v1":
        raise CloudCopsReleaseError("official-role capture schema is unsupported")
    for key, expected in (
        ("employer", COMPANY_NAME),
        ("title", ROLE_TITLE),
        ("vacancy_url", OFFICIAL_VACANCY_URL),
        ("application_url", APPLICATION_URL),
        ("canonical_source_url", CANONICAL_SOURCE_URL),
        ("ats", "personio"),
        ("job_id", VACANCY_ID),
    ):
        if value.get(key) != expected:
            raise CloudCopsReleaseError(f"official-role capture has different {key}")
    captured_at = value.get("captured_at")
    published_at = value.get("datePublished")
    if not isinstance(captured_at, str):
        raise CloudCopsReleaseError("official-role capture time is missing")
    try:
        stamp = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CloudCopsReleaseError("official-role capture time is invalid") from exc
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise CloudCopsReleaseError("official-role capture time must include timezone")
    if not isinstance(published_at, str):
        raise CloudCopsReleaseError("official-role publisher time is missing")
    try:
        published = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CloudCopsReleaseError("official-role publisher time is invalid") from exc
    if published.tzinfo is None or published.utcoffset() is None or published > stamp:
        raise CloudCopsReleaseError("official-role publisher time is not applicable")
    body = value.get("body")
    requirements = value.get("requirements")
    remote_policy = value.get("remote_policy")
    role_excerpt = value.get("role_excerpt")
    if not isinstance(body, str) or not body.strip():
        raise CloudCopsReleaseError("official-role body is missing")
    if not isinstance(requirements, list) or len(requirements) < len(REQUIRED_REQUIREMENT_KEYS):
        raise CloudCopsReleaseError("official-role requirements are incomplete")
    keyed = {
        str(row.get("key")): row
        for row in requirements
        if isinstance(row, dict) and isinstance(row.get("key"), str)
    }
    if set(keyed) != set(REQUIRED_REQUIREMENT_KEYS):
        raise CloudCopsReleaseError("official-role requirement inventory changed")
    for key in REQUIRED_REQUIREMENT_KEYS:
        row = keyed[key]
        text = row.get("text")
        if row.get("essential") is not True or not isinstance(text, str) or not text.strip():
            raise CloudCopsReleaseError(f"official-role requirement {key} is invalid")
        if body.count(text) != 1:
            raise CloudCopsReleaseError(
                f"official-role requirement {key} does not bind one exact excerpt"
            )
    if not isinstance(remote_policy, str) or body.count(remote_policy) != 1:
        raise CloudCopsReleaseError("official remote policy has no exact source excerpt")
    if "work from anywhere" not in remote_policy.casefold():
        raise CloudCopsReleaseError("official role does not authorise work from anywhere")
    if remote_policy.encode("utf-8") not in capture_bytes:
        raise CloudCopsReleaseError("remote policy is absent from official capture bytes")
    if not isinstance(role_excerpt, str) or body.count(role_excerpt) != 1:
        raise CloudCopsReleaseError("official role fact has no exact source excerpt")
    if role_excerpt.encode("utf-8") not in capture_bytes:
        raise CloudCopsReleaseError("official role fact is absent from capture bytes")
    return dict(value)


def _approved_statements(packet: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    if packet.get("schema_version") != "jaa05.operator-approved-statements.v1":
        raise CloudCopsReleaseError("approved evidence packet schema is unsupported")
    if not isinstance(packet.get("human_authority"), str) or not packet["human_authority"]:
        raise CloudCopsReleaseError("approved evidence packet has no human authority")
    statements = packet.get("statements")
    if not isinstance(statements, list) or not statements:
        raise CloudCopsReleaseError("approved evidence packet has no statements")
    result: dict[str, dict[str, str]] = {}
    for row in statements:
        if not isinstance(row, dict):
            raise CloudCopsReleaseError("approved evidence statement is invalid")
        identity = row.get("id")
        statement = row.get("statement")
        kind = row.get("kind")
        if (
            not isinstance(identity, str)
            or not identity
            or identity in result
            or not isinstance(statement, str)
            or statement.strip() != statement
            or not isinstance(kind, str)
            or kind not in PROOF_CLASS_BY_KIND
        ):
            raise CloudCopsReleaseError("approved evidence statement is not exact")
        result[identity] = {"statement": statement, "kind": kind}
    return result


def _contact_record(record: Mapping[str, Any]) -> tuple[dict[str, str], str]:
    candidate: object
    if record.get("schema") == "jaa.authoritative-contact-profile.v1":
        candidate = record
        city_key = "city"
    else:
        candidate = record.get("candidate")
        city_key = "current_location"
    if not isinstance(candidate, dict):
        raise CloudCopsReleaseError("authoritative contact record is missing")
    values: dict[str, str] = {}
    for key in ("first_name", "last_name", "email", "phone", city_key):
        value = candidate.get(key)
        if not isinstance(value, str) or value.strip() != value or not value:
            raise CloudCopsReleaseError(f"authoritative contact value is missing: {key}")
        values[key] = value
    if "@" not in values["email"]:
        raise CloudCopsReleaseError("authoritative contact email is invalid")
    if values[city_key].count(",") > 1:
        raise CloudCopsReleaseError("authoritative contact location is ambiguous")
    city = values[city_key].split(",", 1)[0].strip()
    if not city or "\n" in city:
        raise CloudCopsReleaseError("authoritative contact city is invalid")
    normalized = {
        "first_name": values["first_name"],
        "last_name": values["last_name"],
        "email": values["email"],
        "phone": values["phone"],
        "city": city,
    }
    profile_document = {
        "schema": "jaa.authoritative-contact-profile.v1",
        "first_name": normalized["first_name"],
        "last_name": normalized["last_name"],
        "email": normalized["email"],
        "phone": normalized["phone"],
    }
    return normalized, _hash(profile_document)


def _work_right(value: Mapping[str, Any], *, as_of: date) -> dict[str, Any]:
    if value.get("schema_version") != "jaa.work-right-evidence.v1":
        raise CloudCopsReleaseError("work-right evidence schema is unsupported")
    required = {
        "jurisdiction": "GB",
        "contract_type": "employee",
        "permitted": True,
    }
    if any(value.get(key) != expected for key, expected in required.items()):
        raise CloudCopsReleaseError("work-right evidence does not permit GB employment")
    if not isinstance(value.get("human_authority"), str) or not value["human_authority"]:
        raise CloudCopsReleaseError("work-right evidence has no human authority")
    if not isinstance(value.get("statement"), str) or not value["statement"].strip():
        raise CloudCopsReleaseError("work-right evidence statement is missing")
    try:
        valid_from = date.fromisoformat(str(value["valid_from"]))
        valid_until = date.fromisoformat(str(value["valid_until"]))
    except (KeyError, ValueError) as exc:
        raise CloudCopsReleaseError("work-right validity interval is invalid") from exc
    if not valid_from <= as_of <= valid_until:
        raise CloudCopsReleaseError("work-right evidence is not current")
    return {**value, "valid_from": valid_from, "valid_until": valid_until}


def _support(requirement_key: str, statement: str) -> bool:
    text = statement.casefold()
    if requirement_key == "cloud_automation":
        return ("aws" in text or "gcp" in text or "azure" in text) and (
            "automation" in text or "lambda" in text
        )
    if requirement_key == "major_cloud":
        return any(token in text for token in ("aws lambda", "amazon web services", "gcp", "azure"))
    if requirement_key == "git":
        return re.search(r"\bgit\b", text) is not None
    if requirement_key == "linux":
        return re.search(r"\blinux\b", text) is not None
    if requirement_key == "shell":
        return re.search(r"\bshell\b", text) is not None
    if requirement_key == "learning_curiosity":
        return (
            re.search(r"\bi\b", text) is not None
            and re.search(r"\b(?:curiosity|curious|learned|learning)\b", text) is not None
        )
    if requirement_key == "team_communication":
        return (
            "english lessons" in text
            or "communication" in text
            or "team" in text
        )
    raise AssertionError(requirement_key)


def _requirements(capture: Mapping[str, Any], job_key: str, payload_hash: str) -> tuple[Requirement, ...]:
    body = str(capture["body"])
    rows = {str(row["key"]): row for row in capture["requirements"]}
    return tuple(
        Requirement(
            f"cloudcops-{key.replace('_', '-')}",
            f"cloudcops-{key.replace('_', '-')}-claim",
            str(rows[key]["text"]),
            True,
            "structural",
            "fatal",
            tuple(sorted(set(PROOF_CLASS_BY_KIND.values()))),
            9000,
            f"vacancy:{job_key}:{payload_hash}",
            (
                body.index(str(rows[key]["text"])),
                body.index(str(rows[key]["text"])) + len(str(rows[key]["text"])),
            ),
        )
        for key in REQUIRED_REQUIREMENT_KEYS
    )


class _OfficialCaptureResearch:
    def __init__(self, cache: RawResponseCache, capture_bytes: bytes, capture: Mapping[str, Any]):
        self.cache = cache
        self.capture_bytes = capture_bytes
        self.capture = capture

    def retrieve_plan(self, task: object) -> tuple[list[Citation], list[dict[str, object]]]:
        if (
            getattr(task, "job_key", None) != FROZEN_KEY
            or getattr(task, "company", None) != COMPANY_NAME
            or getattr(task, "title", None) != ROLE_TITLE
        ):
            raise CloudCopsReleaseError("research task differs from CloudCops authority")
        digest, reference = self.cache.store(self.capture_bytes)
        captured_at = str(self.capture["captured_at"])
        citation = Citation(
            id="official-role-capture",
            url=CANONICAL_SOURCE_URL,
            captured_at=captured_at,
            retrieved_at=captured_at,
            content_sha256=digest,
            raw_response_ref=reference,
            status_code=200,
            published_at=str(self.capture["datePublished"]),
            source_kind="official_vacancy",
            canonical_publisher="cloudcops.jobs.personio.com",
            canonical_article=CANONICAL_SOURCE_URL,
            retrieval_engine="local-approved-capture",
            publisher_date_evidence=(
                f'"datePublished":"{self.capture["datePublished"]}"'
            ),
        )
        excerpt = str(self.capture["role_excerpt"]).encode("utf-8")
        start = self.capture_bytes.find(excerpt)
        if start < 0:
            raise CloudCopsReleaseError("official role excerpt is absent from capture bytes")
        plan: list[dict[str, object]] = []
        for kind in ("company", "role", "product", "hiring", "operational_health"):
            freshness_days = FRESHNESS_DAYS[IntelligenceKind(kind)]
            if kind == "role":
                plan.append(
                    {
                        "id": "plan:role",
                        "kind": "role",
                        "outcome": "supported",
                        "source_id": citation.id,
                        "source_type": "official_vacancy",
                        "permitted_purposes": ["role"],
                        "freshness_days": freshness_days,
                        "excerpt_sha256": hashlib.sha256(excerpt).hexdigest(),
                        "excerpt_byte_start": start,
                        "excerpt_byte_length": len(excerpt),
                    }
                )
            else:
                plan.append(
                    {
                        "id": f"plan:{kind}",
                        "kind": kind,
                        "outcome": "unknown",
                        "permitted_purposes": [kind],
                        "freshness_days": freshness_days,
                        "reason": "no separate approved public authority supplied",
                    }
                )
        return [citation], plan


def _seed_candidate_graph(
    database: CareerDatabase,
    *,
    statements: Mapping[str, Mapping[str, str]],
    packet_sha256: str,
    contact: Mapping[str, str],
    contact_sha256: str,
    work_right: Mapping[str, Any],
    work_right_sha256: str,
    requirements: tuple[Requirement, ...],
    as_of: date,
) -> tuple[CandidateContact, tuple[MatchProposal, ...], dict[str, str]]:
    graph = CandidateGraph(database.path)
    policy_hash = packet_sha256
    key_by_requirement = dict(zip(requirements, REQUIRED_REQUIREMENT_KEYS, strict=True))
    matched: dict[str, str] = {}
    evidence_added: set[str] = set()
    for requirement, key in key_by_requirement.items():
        candidates = [
            (identity, row)
            for identity, row in sorted(statements.items())
            if _support(key, str(row["statement"]))
        ]
        if not candidates:
            continue
        evidence_id, row = candidates[0]
        if evidence_id not in evidence_added:
            graph.add_evidence(
                evidence_id,
                statement=str(row["statement"]),
                source_identity=f"approved-packet:sha256:{packet_sha256}",
                state="evidence",
                evidence_kind=str(row["kind"]),
            )
            graph.verify_evidence(
                evidence_id,
                1,
                decision="approved",
                verifier_kind="configured",
                policy_id="jaa05.operator-approved-statements",
                policy_version="1",
                policy_hash=policy_hash,
                reason="verbatim statement in the hash-bound operator-approved packet",
                source_identity=f"operator-approval:sha256:{packet_sha256}",
            )
            evidence_added.add(evidence_id)
        graph.add_claim(
            requirement.criterion,
            statement=str(row["statement"]),
            claim_type=(
                "education"
                if str(row["kind"]) == "credential"
                else "skill"
                if key in {"major_cloud", "git", "linux", "shell"}
                else "capability"
            ),
            state="evidence",
            source_identity=f"approved-packet:sha256:{packet_sha256}:{evidence_id}",
        )
        graph.link_claim_evidence(
            requirement.criterion,
            evidence_id,
            source_identity=f"approved-packet-edge:sha256:{packet_sha256}",
            edge_type="demonstrated_by",
        )
        graph.approve_claim(requirement.criterion)
        matched[requirement.requirement_id] = evidence_id

    contact_value = {
        "full_name": f"{contact['first_name']} {contact['last_name']}",
        "email": contact["email"],
        "phone": contact["phone"],
        "city": contact["city"],
    }
    graph.add_record(
        "cloudcops-contact-primary",
        kind="fact",
        subject="contact",
        value=contact_value,
        state="fact",
        source_identity=f"authoritative-contact:sha256:{contact_sha256}",
    )
    graph.verify_record(
        "cloudcops-contact-primary",
        1,
        decision="approved",
        verifier_kind="configured",
        policy_id="jaa.authoritative-contact-profile",
        policy_version="1",
        policy_hash=contact_sha256,
        reason="exact contact projection from hash-bound authoritative record",
        source_identity=f"contact-verification:sha256:{contact_sha256}",
    )
    with database.connection() as connection:
        contact_provenance = str(
            connection.execute(
                """SELECT provenance.source_hash
                   FROM candidate_records record
                   JOIN candidate_provenance provenance
                     ON provenance.provenance_id=record.provenance_id
                   WHERE record.record_id='cloudcops-contact-primary'"""
            ).fetchone()[0]
        )
    candidate_contact = CandidateContact(
        record_id="cloudcops-contact-primary",
        record_version=1,
        provenance_sha256=contact_provenance,
        **contact_value,
    )

    graph.add_record(
        "cloudcops-work-right-gb",
        kind="work_right",
        subject="permission",
        value={"permitted": True},
        state="fact",
        source_identity=f"work-right-evidence:sha256:{work_right_sha256}",
        jurisdiction="GB",
        contract_type="employee",
        valid_from=work_right["valid_from"].isoformat(),
        valid_until=work_right["valid_until"].isoformat(),
    )
    graph.verify_record(
        "cloudcops-work-right-gb",
        1,
        decision="approved",
        verifier_kind="configured",
        policy_id="jaa.work-right-evidence",
        policy_version="1",
        policy_hash=work_right_sha256,
        reason=str(work_right["statement"]),
        source_identity=f"work-right-verification:sha256:{work_right_sha256}",
    )

    evidence = candidate_graph_evidence(database.path, as_of=as_of)
    profile_hash = evidence_projection_hash(evidence)
    proposals: list[MatchProposal] = []
    for requirement in requirements:
        evidence_id = matched.get(requirement.requirement_id)
        receipt = InferenceReceipt(
            "deterministic",
            "cloudcops-verbatim-evidence-v1",
            hashlib.sha256(b"cloudcops-verbatim-evidence-v1").hexdigest(),
            POLICY.policy_hash,
            profile_hash,
            matching_input_hash(
                requirement,
                candidate_profile_sha256=profile_hash,
                as_of=as_of,
            ),
        )
        proposals.append(
            MatchProposal(
                requirement.requirement_id,
                () if evidence_id is None else (evidence_id,),
                0 if evidence_id is None else 10_000,
                "none" if evidence_id is None else "direct",
                (
                    "no approved verbatim evidence satisfies the mandatory requirement"
                    if evidence_id is None
                    else "exact operator-approved statement satisfies the configured criterion"
                ),
                receipt,
                ()
                if evidence_id is None
                else ((evidence_id, requirement.criterion),),
            )
        )
    return candidate_contact, tuple(proposals), matched


def _duplicate_check(database: CareerDatabase, *, checked_at: datetime) -> DuplicateCheck:
    with database.connection() as connection:
        release_rows = [
            tuple(row)
            for row in connection.execute(
                """SELECT release_manifest_hash,job_key,artifact_set_hash
                   FROM release_manifests WHERE job_key=?
                   ORDER BY release_manifest_hash""",
                (FROZEN_KEY,),
            ).fetchall()
        ]
        personio_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='personio_receipt'"
        ).fetchone() is not None
        personio_rows = (
            [tuple(row) for row in connection.execute(
                "SELECT receipt_sha256,release_manifest_sha256 FROM personio_receipt ORDER BY singleton"
            ).fetchall()]
            if personio_exists
            else []
        )
    document = {
        "aliases": [FROZEN_KEY, PERSONIO_ALIAS],
        "release_rows": release_rows,
        "personio_rows": personio_rows,
    }
    provisional = {
        "schema": "jaa11.duplicate-check.v1",
        "employer_key": EMPLOYER_KEY,
        "vacancy_id": VACANCY_ID,
        "official_url": APPLICATION_URL,
        "checked_aliases": [FROZEN_KEY, PERSONIO_ALIAS],
        "duplicate_found": bool(release_rows or personio_rows),
        "ledger_snapshot_sha256": _hash(document),
        "checked_at": checked_at.isoformat(),
    }
    return DuplicateCheck(
        EMPLOYER_KEY,
        VACANCY_ID,
        APPLICATION_URL,
        (FROZEN_KEY, PERSONIO_ALIAS),
        bool(release_rows or personio_rows),
        str(provisional["ledger_snapshot_sha256"]),
        checked_at,
        _hash(provisional),
    )


def _operator_authority(bound: BoundFile) -> None:
    text = _read_bound_file(bound, "operator canary authority").decode("utf-8", "strict")
    normalized = text.casefold()
    if "one real jaa-11 application canary" not in normalized:
        raise CloudCopsReleaseError("operator authority does not authorise one JAA-11 canary")
    if "captcha" not in normalized or "top 20" not in normalized:
        raise CloudCopsReleaseError("operator authority lacks the bounded canary restrictions")


def prepare_cloudcops_release(
    inputs: CloudCopsReleaseInputs,
    *,
    evaluated_at: date | None = None,
) -> CloudCopsReleasePreparation:
    """Prepare through JAA-07 and optionally issue one real JAA-08 token.

    No network or browser operation occurs.  With ``arm_release=False`` the
    function stops after exact artifact, compilation, route and Personio upload
    binding preparation.
    """

    as_of = evaluated_at or datetime.now(timezone.utc).date()
    snapshot_bytes = _read_bound_file(inputs.ranked_snapshot, "ranked snapshot")
    raw_bytes = _read_bound_file(inputs.raw_vacancy, "raw vacancy")
    capture_bytes = _read_bound_file(inputs.official_role_capture, "official-role capture")
    packet_bytes = _read_bound_file(inputs.approved_evidence_packet, "approved evidence packet")
    contact_bytes = _read_bound_file(inputs.authoritative_contact_record, "contact record")
    work_right_bytes = _read_bound_file(inputs.work_right_evidence, "work-right evidence")

    snapshot = _object(snapshot_bytes, "ranked snapshot")
    entry = _exact_rank_entry(snapshot, raw_bytes)
    capture = _official_capture(_object(capture_bytes, "official-role capture"), capture_bytes)
    statements = _approved_statements(_object(packet_bytes, "approved evidence packet"))
    contact_values, contact_profile_sha256 = _contact_record(
        _object(contact_bytes, "contact record")
    )
    work_right = _work_right(_object(work_right_bytes, "work-right evidence"), as_of=as_of)

    database = CareerDatabase(inputs.runtime_database)
    payload = {
        "board": "himalayas",
        "job_id": entry["job_id"],
        "url": entry["url"],
        "job_title": ROLE_TITLE,
        "company": COMPANY_NAME,
        "fit": float(entry["fit"]),
        "opportunity": float(entry["opportunity"]),
        "final": float(entry["final"]),
        "extraction_confidence": 1.0,
        "body": capture["body"],
        "frozen_rank": 32,
        "frozen_snapshot_sha256": inputs.ranked_snapshot.sha256,
        "raw_vacancy_sha256": inputs.raw_vacancy.sha256,
        "official_role_capture_sha256": inputs.official_role_capture.sha256,
        "official_application_url": APPLICATION_URL,
    }
    job = scored_job_from_payload(payload)
    if job.key != FROZEN_KEY:
        raise CloudCopsReleaseError("scored job differs from frozen CloudCops identity")
    gate_summary = OpportunityGate(database).bootstrap([job])
    if gate_summary.queued != 1:
        raise CloudCopsReleaseError("CloudCops opportunity was not queued exactly once")

    cache = RawResponseCache(inputs.runtime_database.parent / "cloudcops-public-cache")
    coordinator = Opportunity1Coordinator(
        database,
        EmployerResearchWorker(
            database,
            "cloudcops-approved-capture-worker",
            cache,
            retriever=_OfficialCaptureResearch(cache, capture_bytes, capture),
        ),
        signal_deriver=lambda _dossier: [],
    )
    opportunity = coordinator.run_once()
    if opportunity is None or opportunity.get("decision") != "pass":
        raise CloudCopsReleaseError("CloudCops Opportunity-1 did not pass")

    requirements = _requirements(capture, job.key, job.payload_hash)
    candidate_contact, proposals, matched = _seed_candidate_graph(
        database,
        statements=statements,
        packet_sha256=inputs.approved_evidence_packet.sha256,
        contact=contact_values,
        contact_sha256=inputs.authoritative_contact_record.sha256,
        work_right=work_right,
        work_right_sha256=inputs.work_right_evidence.sha256,
        requirements=requirements,
        as_of=as_of,
    )
    fit = FitAssessmentStore(database.path).assess(
        job_key=job.key,
        requirements=requirements,
        proposals=proposals,
        as_of=as_of,
    )
    blockers = tuple(
        row.requirement_id
        for row in requirements
        if row.requirement_id not in matched
    )
    if fit.status != "ready":
        return CloudCopsReleasePreparation(
            "blocked_unmatched_mandatory_requirements",
            fit,
            blockers,
            matched,
        )

    strategy = ApplicationStrategyStore(database.path).compile_and_record(
        fit_run_id=fit.run_id,
        as_of=as_of,
    )
    questions: dict[str, tuple[str, str]] = {}
    source = ProductionApplicationCompiler(database.path).compile(
        strategy.strategy_id,
        as_of=as_of,
        contact=candidate_contact,
        questions=questions,
    )
    if source.job_key != FROZEN_KEY or source.role_title != ROLE_TITLE:
        raise CloudCopsReleaseError("JAA-07 source differs from CloudCops authority")
    artifacts = render_pdf_artifacts(source)
    publication = publish_application_artifacts(
        source,
        artifacts,
        root=inputs.artifact_root,
        repository_root=REPOSITORY_ROOT,
    )
    compilation = ApplicationCompilationStore(database.path).register(
        source=source,
        artifacts=artifacts,
        contact=candidate_contact,
        questions=questions,
        artifact_root=inputs.artifact_root,
        repository_root=REPOSITORY_ROOT,
        as_of=as_of,
    )

    release_gate = ReleaseGateStore(database.path)
    capture_date = datetime.fromisoformat(
        str(capture["captured_at"]).replace("Z", "+00:00")
    ).date()
    route_policy = _hash(
        {
            "adapter_id": ADAPTER_ID,
            "adapter_version": ADAPTER_VERSION,
            "application_url": APPLICATION_URL,
            "official_role_capture_sha256": inputs.official_role_capture.sha256,
            "form_schema_sha256": FORM_SCHEMA_SHA256,
            "aliases": [FROZEN_KEY, PERSONIO_ALIAS],
        }
    )
    release_gate.register_official_route(
        job_key=source.job_key,
        route=OfficialRouteBinding(
            f"route:personio:{VACANCY_ID}:{inputs.official_role_capture.sha256}",
            ADAPTER_ID,
            ADAPTER_VERSION,
            f"official-role-capture:sha256:{inputs.official_role_capture.sha256}",
            route_policy,
            capture_date,
            capture_date + timedelta(days=30),
            True,
        ),
    )

    checked_at = datetime.combine(as_of, datetime.min.time(), tzinfo=timezone.utc)
    duplicate = _duplicate_check(database, checked_at=checked_at)
    if duplicate.duplicate_found:
        raise CloudCopsReleaseError("duplicate application identity blocks release")
    profile = ContactProfileBinding(
        contact_values["first_name"],
        contact_values["last_name"],
        contact_values["email"],
        contact_values["phone"],
        contact_profile_sha256,
    )
    cv_receipt = next(row for row in publication.files if row.filename == "cv.pdf")
    cv_path = inputs.artifact_root / publication.relative_directory / "cv.pdf"
    if cv_receipt.sha256 != artifacts.cv_pdf.pdf_sha256:
        raise CloudCopsReleaseError("Personio CV differs from JAA-rendered artifact bytes")
    application = PersonioApplication(profile, cv_path, cv_receipt.sha256, duplicate)

    if not inputs.arm_release:
        return CloudCopsReleasePreparation(
            "prepared_not_issued",
            fit,
            (),
            matched,
            publication,
            compilation,
            application,
            release_gate,
            source,
            artifacts,
            candidate_contact,
            questions,
        )

    assert inputs.operator_authority is not None
    _operator_authority(inputs.operator_authority)
    issued = release_gate.evaluate_and_issue(
        compilation_id=compilation.compilation_id,
        source=source,
        artifacts=artifacts,
        contact=candidate_contact,
        questions=questions,
        artifact_root=inputs.artifact_root,
        repository_root=REPOSITORY_ROOT,
        jurisdiction="GB",
        contract_type="employee",
        evaluated_at=as_of,
    )
    return CloudCopsReleasePreparation(
        "issued_not_consumed",
        fit,
        (),
        matched,
        publication,
        compilation,
        application,
        release_gate,
        source,
        artifacts,
        candidate_contact,
        questions,
        issued,
    )


def _bound(value: str) -> BoundFile:
    path, separator, digest = value.rpartition("@sha256:")
    if not separator:
        raise argparse.ArgumentTypeError("bound file must be PATH@sha256:DIGEST")
    return BoundFile(Path(path), digest)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare the CloudCops JAA release locally")
    parser.add_argument("--ranked-snapshot", type=_bound, required=True)
    parser.add_argument("--raw-vacancy", type=_bound, required=True)
    parser.add_argument("--official-role-capture", type=_bound, required=True)
    parser.add_argument("--approved-evidence-packet", type=_bound, required=True)
    parser.add_argument("--authoritative-contact-record", type=_bound, required=True)
    parser.add_argument("--work-right-evidence", type=_bound, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--runtime-database", type=Path, required=True)
    parser.add_argument("--operator-authority", type=_bound)
    parser.add_argument("--arm-release", action="store_true")
    arguments = parser.parse_args(argv)
    result = prepare_cloudcops_release(
        CloudCopsReleaseInputs(
            arguments.ranked_snapshot,
            arguments.raw_vacancy,
            arguments.official_role_capture,
            arguments.approved_evidence_packet,
            arguments.authoritative_contact_record,
            arguments.work_right_evidence,
            arguments.artifact_root,
            arguments.runtime_database,
            arguments.operator_authority,
            arguments.arm_release,
        )
    )
    print(_canonical_json(result.public_document()))
    return 0 if result.status != "blocked_unmatched_mandatory_requirements" else 2


if __name__ == "__main__":
    raise SystemExit(main())
