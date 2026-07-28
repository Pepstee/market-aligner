"""Fail-closed contamination controls for a fresh JAA-05 holdout.

The failed holdout index is an exclusion list only.  This module deliberately
does not expose labels, decisions, prompts, thresholds, or scoring behavior.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


INDEX_SCHEMA = "jaa05.failed-holdout-quarantine-index.v1"
ACQUISITION_INDEX_SCHEMA = "jaa05.failed-cycle-acquisition-quarantine-index.v1"
BUNDLE_SCHEMA = "jaa05.combined-quarantine-bundle.v1"
FIREWALL_SCHEMA = "jaa05.post-acquisition-firewall.v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
INDEX_FIELDS = frozenset({
    "schema_version",
    "authority",
    "failed_holdout_sha256",
    "failed_queue_sha256",
    "decision_fields_included",
    "rationales_included",
    "source_text_included",
    "entry_count",
    "job_keys",
    "payload_hashes",
    "source_text_sha256",
    "source_identity_sha256",
    "entries",
    "purpose",
})
AUTHORITY_FIELDS = frozenset({
    "corrected_terminal_ruling_wrapper_sha256",
    "verdict",
})
ENTRY_FIELDS = frozenset({
    "requirement_id",
    "job_key",
    "payload_hash",
    "source_span",
    "source_text_sha256",
    "source_identity_sha256",
})
REQUIREMENT_FIELDS = frozenset({
    "requirement_id",
    "job_key",
    "payload_hash",
    "source_span",
    "text",
})
ACQUISITION_INDEX_FIELDS = frozenset({
    "schema_version",
    "decision_fields_included",
    "source_text_included",
    "derived_from",
    "derivation_rule",
    "entry_count",
    "disposition_counts_crosscheck",
    "job_keys",
    "payload_hashes",
    "content_hashes",
    "canonical_url_hashes",
    "entries",
})
ACQUISITION_ENTRY_FIELDS = frozenset({
    "job_key",
    "payload_hash",
    "content_sha256",
    "canonical_url_sha256",
})
BUNDLE_FIELDS = frozenset({
    "schema_version",
    "members",
    "runtime_exclusion_semantics",
    "post_extraction_disjointness_semantics",
    "binds_failure_trees",
})


class HoldoutFirewallFailure(ValueError):
    """A terminal quarantine or disjointness validation failure."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise HoldoutFirewallFailure(message)


def _digest(value: Any, label: str) -> str:
    _require(
        isinstance(value, str) and HEX64.fullmatch(value) is not None,
        f"{label} must be a lowercase SHA-256 digest",
    )
    return value


def _canonical_pretty(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _identity_hash(
    job_key: str,
    payload_hash: str,
    source_span: tuple[int, int],
    source_text_sha256: str,
) -> str:
    document = {
        "job_key": job_key,
        "payload_hash": payload_hash,
        "source_span": list(source_span),
        "source_text_sha256": source_text_sha256,
    }
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _string_list(value: Any, label: str, *, hashes: bool = False) -> tuple[str, ...]:
    _require(isinstance(value, list), f"{label} must be a list")
    rows = tuple(value)
    _require(
        all(isinstance(row, str) and bool(row.strip()) for row in rows),
        f"{label} entries must be non-empty strings",
    )
    if hashes:
        for row in rows:
            _digest(row, label)
    _require(
        list(rows) == sorted(set(rows)),
        f"{label} must be sorted and unique",
    )
    return rows


@dataclass(frozen=True)
class QuarantineIndex:
    """Strictly validated, content-addressed failed-holdout exclusions."""

    path: Path
    sha256: str
    entry_count: int
    job_keys: frozenset[str]
    payload_hashes: frozenset[str]
    requirement_ids: frozenset[str]
    source_text_sha256: frozenset[str]
    source_identity_sha256: frozenset[str]

    def binding(self) -> dict[str, Any]:
        return {
            "schema_version": "jaa05.failed-holdout-quarantine-binding.v1",
            "path": str(self.path),
            "sha256": self.sha256,
            "entry_count": self.entry_count,
            "job_key_count": len(self.job_keys),
            "selection_use": "exclusion_only",
        }


@dataclass(frozen=True)
class AcquisitionQuarantineIndex:
    path: Path
    sha256: str
    entry_count: int
    job_keys: frozenset[str]
    payload_hashes: frozenset[str]
    content_hashes: frozenset[str]
    canonical_url_hashes: frozenset[str]


@dataclass(frozen=True)
class QuarantineBundle:
    path: Path
    sha256: str
    requirement_index: QuarantineIndex
    acquisition_index: AcquisitionQuarantineIndex

    @property
    def job_keys(self) -> frozenset[str]:
        return self.requirement_index.job_keys | self.acquisition_index.job_keys

    @property
    def payload_hashes(self) -> frozenset[str]:
        return (
            self.requirement_index.payload_hashes
            | self.acquisition_index.payload_hashes
        )

    @property
    def content_hashes(self) -> frozenset[str]:
        return self.acquisition_index.content_hashes

    @property
    def canonical_url_hashes(self) -> frozenset[str]:
        return self.acquisition_index.canonical_url_hashes

    @property
    def requirement_ids(self) -> frozenset[str]:
        return self.requirement_index.requirement_ids

    @property
    def source_text_sha256(self) -> frozenset[str]:
        return self.requirement_index.source_text_sha256

    @property
    def source_identity_sha256(self) -> frozenset[str]:
        return self.requirement_index.source_identity_sha256

    def binding(self) -> dict[str, Any]:
        return {
            "schema_version": "jaa05.combined-quarantine-binding.v1",
            "path": str(self.path),
            "sha256": self.sha256,
            "members": [
                {
                    "schema_version": INDEX_SCHEMA,
                    "path": str(self.requirement_index.path),
                    "sha256": self.requirement_index.sha256,
                },
                {
                    "schema_version": ACQUISITION_INDEX_SCHEMA,
                    "path": str(self.acquisition_index.path),
                    "sha256": self.acquisition_index.sha256,
                },
            ],
            "runtime_exclusion_use": "union",
            "post_extraction_use": "requirement_index_only",
        }


def load_quarantine_index(path: Path, expected_sha256: str) -> QuarantineIndex:
    """Load one exact decision-free index before any acquisition can start."""
    expected = _digest(expected_sha256, "expected quarantine index")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise HoldoutFirewallFailure("quarantine index is missing or unreadable") from exc
    actual = hashlib.sha256(raw).hexdigest()
    _require(actual == expected, "quarantine index SHA-256 mismatch")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HoldoutFirewallFailure("quarantine index is not valid JSON") from exc
    _require(isinstance(document, dict), "quarantine index must be an object")
    _require(
        set(document) == INDEX_FIELDS,
        "quarantine index top-level schema differs",
    )
    _require(
        raw == _canonical_pretty(document),
        "quarantine index bytes are not canonical",
    )
    _require(document["schema_version"] == INDEX_SCHEMA, "quarantine index schema differs")
    authority = document["authority"]
    _require(
        isinstance(authority, dict) and set(authority) == AUTHORITY_FIELDS,
        "quarantine authority schema differs",
    )
    _digest(
        authority["corrected_terminal_ruling_wrapper_sha256"],
        "terminal ruling wrapper",
    )
    _require(
        authority["verdict"] == "REJECT_JAA05_CALIBRATION",
        "quarantine authority verdict differs",
    )
    _digest(document["failed_holdout_sha256"], "failed holdout")
    _digest(document["failed_queue_sha256"], "failed queue")
    _require(
        document["decision_fields_included"] is False,
        "quarantine index contains decision fields",
    )
    _require(
        document["rationales_included"] is False,
        "quarantine index contains rationales",
    )
    _require(
        document["source_text_included"] is False,
        "quarantine index contains source text",
    )
    _require(
        isinstance(document["purpose"], str)
        and "Disjointness enforcement only" in document["purpose"],
        "quarantine index purpose differs",
    )

    job_keys = _string_list(document["job_keys"], "quarantine job keys")
    payload_hashes = _string_list(
        document["payload_hashes"],
        "quarantine payload hashes",
        hashes=True,
    )
    text_hashes = _string_list(
        document["source_text_sha256"],
        "quarantine source-text hashes",
        hashes=True,
    )
    identity_hashes = _string_list(
        document["source_identity_sha256"],
        "quarantine source-identity hashes",
        hashes=True,
    )
    entries = document["entries"]
    _require(isinstance(entries, list), "quarantine entries must be a list")
    _require(
        isinstance(document["entry_count"], int)
        and document["entry_count"] == len(entries),
        "quarantine entry count differs",
    )

    seen_requirements: set[str] = set()
    derived_jobs: set[str] = set()
    derived_payloads: set[str] = set()
    derived_texts: set[str] = set()
    derived_identities: set[str] = set()
    for entry in entries:
        _require(
            isinstance(entry, dict) and set(entry) == ENTRY_FIELDS,
            "quarantine entry schema differs",
        )
        requirement_id = entry["requirement_id"]
        job_key = entry["job_key"]
        _require(
            isinstance(requirement_id, str)
            and bool(requirement_id.strip())
            and requirement_id not in seen_requirements,
            "quarantine requirement IDs must be non-empty and unique",
        )
        _require(
            isinstance(job_key, str) and bool(job_key.strip()),
            "quarantine job key is invalid",
        )
        payload_hash = _digest(entry["payload_hash"], "quarantine payload")
        text_hash = _digest(entry["source_text_sha256"], "quarantine source text")
        identity = _digest(
            entry["source_identity_sha256"],
            "quarantine source identity",
        )
        span = entry["source_span"]
        _require(
            isinstance(span, list)
            and len(span) == 2
            and all(isinstance(value, int) and not isinstance(value, bool) for value in span)
            and 0 <= span[0] < span[1],
            "quarantine source span is invalid",
        )
        expected_identity = _identity_hash(
            job_key,
            payload_hash,
            (span[0], span[1]),
            text_hash,
        )
        _require(identity == expected_identity, "quarantine source identity differs")
        seen_requirements.add(requirement_id)
        derived_jobs.add(job_key)
        derived_payloads.add(payload_hash)
        derived_texts.add(text_hash)
        derived_identities.add(identity)

    _require(set(job_keys) == derived_jobs, "quarantine job-key summary differs")
    _require(set(payload_hashes) == derived_payloads, "quarantine payload summary differs")
    _require(set(text_hashes) == derived_texts, "quarantine source-text summary differs")
    _require(
        set(identity_hashes) == derived_identities,
        "quarantine source-identity summary differs",
    )
    return QuarantineIndex(
        path=path.resolve(),
        sha256=actual,
        entry_count=len(entries),
        job_keys=frozenset(job_keys),
        payload_hashes=frozenset(payload_hashes),
        requirement_ids=frozenset(seen_requirements),
        source_text_sha256=frozenset(text_hashes),
        source_identity_sha256=frozenset(identity_hashes),
    )


def load_acquisition_quarantine_index(
    path: Path,
    expected_sha256: str,
) -> AcquisitionQuarantineIndex:
    expected = _digest(expected_sha256, "expected acquisition index")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise HoldoutFirewallFailure(
            "acquisition quarantine index is missing or unreadable"
        ) from exc
    actual = hashlib.sha256(raw).hexdigest()
    _require(actual == expected, "acquisition quarantine index SHA-256 mismatch")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HoldoutFirewallFailure(
            "acquisition quarantine index is not valid JSON"
        ) from exc
    _require(
        isinstance(document, dict)
        and set(document) == ACQUISITION_INDEX_FIELDS,
        "acquisition quarantine index schema differs",
    )
    _require(
        raw == _canonical_pretty(document),
        "acquisition quarantine index bytes are not canonical",
    )
    _require(
        document["schema_version"] == ACQUISITION_INDEX_SCHEMA,
        "acquisition quarantine index schema differs",
    )
    _require(
        document["decision_fields_included"] is False
        and document["source_text_included"] is False,
        "acquisition quarantine index contains forbidden data",
    )
    forbidden = {
        "requirement_id",
        "source_span",
        "source_text_sha256",
        "source_identity_sha256",
        "disposition",
        "decision",
        "rationale",
        "label",
        "score_bp",
        "source_text",
    }
    def reject_forbidden(value: Any) -> None:
        if isinstance(value, dict):
            _require(
                not forbidden.intersection(value),
                "acquisition quarantine index contains forbidden fields",
            )
            for child in value.values():
                reject_forbidden(child)
        elif isinstance(value, list):
            for child in value:
                reject_forbidden(child)
    reject_forbidden(document)
    _require(
        document["derived_from"] == {
            "failure_record_sha256": (
                "a76ca48dc4c3d502385ffad979979ae8510b22b8fea6fab967044e337ffa643d"
            ),
            "capture_evidence_file_sha256": (
                "b1e0c5de0af3419f0ae2085476d3afe19c86b5e0cb11fb0cdc6f488b57979217"
            ),
            "capture_evidence_self_sha256": (
                "7481b33baa077af31b84089db78da3c11f06fd5f5feccdd9ad51ee0ff7ab3c49"
            ),
            "sealed_root": (
                "/home/gutua/software-factory/.control/"
                "resumed-dual-lane-20260728/jaa/runtime/"
                "fresh-jaa05-holdout-v1-0c90c73"
            ),
        },
        "acquisition quarantine derivation binding differs",
    )
    entries = document["entries"]
    _require(
        isinstance(entries, list)
        and document["entry_count"] == len(entries) == 57,
        "acquisition quarantine entry count differs",
    )
    jobs: set[str] = set()
    payloads: set[str] = set()
    contents: set[str] = set()
    urls: set[str] = set()
    for entry in entries:
        _require(
            isinstance(entry, dict)
            and set(entry) == ACQUISITION_ENTRY_FIELDS,
            "acquisition quarantine entry schema differs",
        )
        job_key = entry["job_key"]
        _require(
            isinstance(job_key, str) and bool(job_key.strip()),
            "acquisition quarantine job key differs",
        )
        jobs.add(job_key)
        payloads.add(_digest(entry["payload_hash"], "acquisition payload"))
        contents.add(_digest(entry["content_sha256"], "acquisition content"))
        urls.add(_digest(entry["canonical_url_sha256"], "acquisition URL"))
    for field, actual_values in (
        ("job_keys", jobs),
        ("payload_hashes", payloads),
        ("content_hashes", contents),
        ("canonical_url_hashes", urls),
    ):
        expected_values = _string_list(
            document[field],
            f"acquisition {field}",
            hashes=field != "job_keys",
        )
        _require(
            set(expected_values) == actual_values,
            f"acquisition {field} summary differs",
        )
    _require(
        document["disposition_counts_crosscheck"] == {
            "selected": 25,
            "quarantined_job_key": 25,
            "duplicate_content": 4,
            "duplicate_url": 3,
        },
        "acquisition disposition count cross-check differs",
    )
    return AcquisitionQuarantineIndex(
        path=path.resolve(),
        sha256=actual,
        entry_count=len(entries),
        job_keys=frozenset(jobs),
        payload_hashes=frozenset(payloads),
        content_hashes=frozenset(contents),
        canonical_url_hashes=frozenset(urls),
    )


def load_quarantine_bundle(
    path: Path,
    expected_sha256: str,
) -> QuarantineBundle:
    expected = _digest(expected_sha256, "expected quarantine bundle")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise HoldoutFirewallFailure(
            "quarantine bundle is missing or unreadable"
        ) from exc
    actual = hashlib.sha256(raw).hexdigest()
    _require(actual == expected, "quarantine bundle SHA-256 mismatch")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HoldoutFirewallFailure("quarantine bundle is not valid JSON") from exc
    _require(
        isinstance(document, dict) and set(document) == BUNDLE_FIELDS,
        "quarantine bundle schema differs",
    )
    _require(raw == _canonical_pretty(document), "quarantine bundle bytes are not canonical")
    _require(document["schema_version"] == BUNDLE_SCHEMA, "quarantine bundle schema differs")
    _require(
        document["binds_failure_trees"] == [
            "a76ca48dc4c3d502385ffad979979ae8510b22b8fea6fab967044e337ffa643d",
            "00352f85941456d0ca3893b9e6855f3806e6e4ae5031d6ac7a42b615dfbc76b0",
        ],
        "quarantine bundle failure bindings differ",
    )
    members = document["members"]
    _require(
        isinstance(members, list)
        and len(members) == 2
        and [row.get("schema_version") for row in members] == [
            INDEX_SCHEMA,
            ACQUISITION_INDEX_SCHEMA,
        ],
        "quarantine bundle members differ",
    )
    expected_roles = [
        ["runtime_exclusion", "post_extraction_disjointness"],
        ["runtime_exclusion"],
    ]
    loaded: list[Any] = []
    for number, member in enumerate(members):
        _require(
            isinstance(member, dict)
            and set(member) == {"schema_version", "path", "sha256", "roles"}
            and member["roles"] == expected_roles[number],
            "quarantine bundle member schema differs",
        )
        relative = Path(member["path"])
        _require(
            not relative.is_absolute()
            and relative.name == str(relative)
            and relative.name in {
                "failed-holdout-quarantine-index.json",
                "failed-cycle-acquisition-quarantine-index.json",
            },
            "quarantine bundle member path differs",
        )
        member_path = path.parent / relative
        loader = (
            load_quarantine_index
            if number == 0
            else load_acquisition_quarantine_index
        )
        loaded.append(loader(member_path, member["sha256"]))
    return QuarantineBundle(
        path=path.resolve(),
        sha256=actual,
        requirement_index=loaded[0],
        acquisition_index=loaded[1],
    )


def validate_quarantine_binding(
    document: Mapping[str, Any],
    quarantine: QuarantineIndex | QuarantineBundle,
    *,
    label: str,
) -> None:
    """Reject output or evidence that omits or changes the exclusion binding."""
    key = (
        "failed_holdout_quarantine_bundle"
        if isinstance(quarantine, QuarantineBundle)
        else "failed_holdout_quarantine"
    )
    _require(
        document.get(key) == quarantine.binding(),
        f"{label} omits or changes the quarantine-index binding",
    )


def validate_post_acquisition_holdout(
    queue_records: Iterable[Mapping[str, Any]],
    requirements: Iterable[Mapping[str, Any]],
    quarantine: QuarantineIndex | QuarantineBundle,
    *,
    required_dossiers: int = 30,
) -> dict[str, Any]:
    """Validate exact dossier and extracted-requirement disjointness.

    The caller supplies normal production extraction rows.  Each row's text
    must resolve exactly against its queue payload body and source span.
    """
    rows = tuple(queue_records)
    _require(
        len(rows) == required_dossiers,
        f"fresh holdout requires exactly {required_dossiers} dossiers",
    )
    by_job: dict[str, Mapping[str, Any]] = {}
    seen_payloads: set[str] = set()
    seen_content: set[str] = set()
    for row in rows:
        _require(isinstance(row, Mapping), "holdout dossier must be an object")
        job_key = row.get("job_key")
        payload_hash = _digest(row.get("payload_hash"), "holdout dossier payload")
        content_hash = _digest(row.get("content_sha256"), "holdout dossier content")
        _require(
            isinstance(job_key, str)
            and bool(job_key.strip())
            and job_key not in by_job,
            "holdout dossier job keys must be non-empty and unique",
        )
        _require(payload_hash not in seen_payloads, "holdout dossier payload duplicated")
        _require(content_hash not in seen_content, "holdout dossier content duplicated")
        _require(job_key not in quarantine.job_keys, "failed holdout job key reused")
        _require(
            payload_hash not in quarantine.payload_hashes,
            "failed holdout payload reused",
        )
        if isinstance(quarantine, QuarantineBundle):
            _require(
                content_hash not in quarantine.content_hashes,
                "failed cycle content reused",
            )
            canonical_url = row.get("canonical_url")
            if isinstance(canonical_url, str):
                url_hash = hashlib.sha256(
                    canonical_url.encode("utf-8")
                ).hexdigest()
                _require(
                    url_hash not in quarantine.canonical_url_hashes,
                    "failed cycle canonical URL reused",
                )
        viability = row.get("viability_decision")
        opportunity = row.get("opportunity0_decision")
        temporal = row.get("temporal_admission")
        _require(
            isinstance(viability, Mapping)
            and viability.get("decision") == "include",
            "holdout dossier is not viability-eligible",
        )
        _require(
            isinstance(opportunity, Mapping)
            and opportunity.get("decision") == "pass",
            "holdout dossier did not pass Opportunity-0",
        )
        _require(
            isinstance(temporal, Mapping)
            and temporal.get("admitted") is True,
            "holdout dossier is not temporally eligible",
        )
        payload = row.get("payload")
        _require(isinstance(payload, Mapping), "holdout dossier payload is missing")
        source = payload.get("body")
        if not isinstance(source, str):
            source = payload.get("raw_text")
        _require(isinstance(source, str) and bool(source), "holdout dossier source text missing")
        by_job[job_key] = row
        seen_payloads.add(payload_hash)
        seen_content.add(content_hash)

    extracted = tuple(requirements)
    _require(bool(extracted), "fresh holdout requirements are empty")
    seen_requirement_ids: set[str] = set()
    seen_source_identities: set[str] = set()
    per_job: dict[str, int] = {job_key: 0 for job_key in by_job}
    for requirement in extracted:
        _require(
            isinstance(requirement, Mapping)
            and set(requirement) == REQUIREMENT_FIELDS,
            "holdout requirement schema differs",
        )
        requirement_id = requirement["requirement_id"]
        job_key = requirement["job_key"]
        _require(
            isinstance(requirement_id, str)
            and bool(requirement_id.strip())
            and requirement_id not in seen_requirement_ids,
            "holdout requirement IDs must be non-empty and unique",
        )
        _require(
            requirement_id not in quarantine.requirement_ids,
            "failed holdout requirement ID reused",
        )
        _require(job_key in by_job, "holdout requirement references an unknown dossier")
        payload_hash = _digest(requirement["payload_hash"], "holdout requirement payload")
        row = by_job[job_key]
        _require(payload_hash == row["payload_hash"], "requirement payload binding differs")
        span = requirement["source_span"]
        _require(
            isinstance(span, (list, tuple))
            and len(span) == 2
            and all(isinstance(value, int) and not isinstance(value, bool) for value in span)
            and 0 <= span[0] < span[1],
            "holdout requirement source span is invalid",
        )
        text = requirement["text"]
        _require(
            isinstance(text, str) and bool(text),
            "holdout requirement source text is missing",
        )
        payload = row["payload"]
        source = payload.get("body")
        if not isinstance(source, str):
            source = payload.get("raw_text")
        _require(
            span[1] <= len(source) and source[span[0]:span[1]] == text,
            "holdout requirement source binding differs",
        )
        text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        identity = _identity_hash(
            job_key,
            payload_hash,
            (span[0], span[1]),
            text_hash,
        )
        _require(
            text_hash not in quarantine.source_text_sha256,
            "failed holdout source text reused",
        )
        _require(
            identity not in quarantine.source_identity_sha256,
            "failed holdout source identity reused",
        )
        _require(
            identity not in seen_source_identities,
            "fresh holdout source identity duplicated",
        )
        seen_requirement_ids.add(requirement_id)
        seen_source_identities.add(identity)
        per_job[job_key] += 1

    _require(
        all(count > 0 for count in per_job.values()),
        "every holdout dossier must have extracted requirements",
    )
    dossier_rows = [
        {
            "job_key": job_key,
            "payload_hash": by_job[job_key]["payload_hash"],
            "content_sha256": by_job[job_key]["content_sha256"],
            "requirement_count": per_job[job_key],
            "disjoint": True,
        }
        for job_key in sorted(by_job)
    ]
    receipt = {
        "schema_version": FIREWALL_SCHEMA,
        "result": "PASS",
        (
            "failed_holdout_quarantine_bundle"
            if isinstance(quarantine, QuarantineBundle)
            else "failed_holdout_quarantine"
        ): quarantine.binding(),
        "dossier_count": len(rows),
        "requirement_count": len(extracted),
        "per_dossier": dossier_rows,
    }
    receipt["receipt_sha256"] = hashlib.sha256(
        json.dumps(
            receipt,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return receipt
