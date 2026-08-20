"""Explicit, loss-minimising importers for audited legacy profile shapes."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

import yaml

from .schema import (
    CandidateProfile,
    CanonicalProfileProjectionReceipt,
    EvidenceItem,
    ProjectionDecision,
    TrackProfile,
    new_profile_id,
)
from .store import ProfileStore


def _document(path: str | Path) -> dict[str, Any]:
    value = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(value, dict):
        raise ValueError("profile document must be a mapping")
    return value


def import_evidence_led(path: str | Path, profile_id: str | None = None) -> tuple[CandidateProfile, list[EvidenceItem]]:
    """Import the audited combined evidence/profile document without weakening claims."""

    source = _document(path)
    meta = dict(source.get("meta") or {})
    raw_tracks = dict(source.get("career_tracks") or {})
    evidence = [
        EvidenceItem(
            evidence_id=str(item.get("id") or "").strip(),
            kind=str(item.get("kind") or "").strip(),
            claim=str(item.get("claim") or "").strip(),
            source_ref=str(item.get("source") or "").strip(),
            status=str(item.get("status") or "").strip(),
            confidence=float(item.get("confidence")),
        )
        for item in (source.get("evidence") or [])
    ]
    tracks = {
        str(name): TrackProfile(
            interest=float(raw.get("interest")),
            demonstrated_skill=float(raw.get("skill")),
            confidence=float(raw.get("confidence")),
            market_readiness=float(raw.get("market_readiness")),
            evidence_ids=tuple(str(item) for item in (raw.get("evidence") or ())),
            rationale=str(raw.get("rationale") or "").strip(),
            gaps=tuple(str(item) for item in (raw.get("gaps") or ())),
        )
        for name, raw in raw_tracks.items()
    }
    profile = CandidateProfile(
        profile_id=profile_id or new_profile_id(),
        version=str(meta.get("version") or "legacy-import"),
        display_label=str(meta.get("subject") or "").strip() or None,
        tracks=tracks,
        capabilities=dict(source.get("capabilities") or {}),
        constraints=dict(source.get("constraints") or {}),
        blind_spots=tuple(str(item) for item in (source.get("blind_spots") or ())),
        unknowns=tuple(str(item) for item in (source.get("unknowns") or ())),
        exclusions=tuple(str(item) for item in (source.get("exclusions") or ())),
    )
    profile.validate_evidence({item.evidence_id: item for item in evidence})
    return profile, evidence


def import_guided_profile(
    path: str | Path,
    profile_id: str | None = None,
    *,
    profile_key: str = "profile",
) -> tuple[CandidateProfile, list[EvidenceItem]]:
    """Import a legacy guided profile while retaining its lack of claim evidence.

    Numeric self-assessment/probe summaries are not converted into fabricated
    evidence records.  Empty evidence references and an explicit unknown remain.
    """

    source = _document(path)
    meta = dict(source.get("meta") or {})
    block = dict(source.get(profile_key) or {})
    blind_spots = tuple(str(item) for item in (block.pop("blind_spots", ()) or ()))
    constraints = dict(source.get("constraints") or {})
    tracks = {
        str(name): TrackProfile(
            interest=float(raw.get("interest")),
            demonstrated_skill=float(raw.get("skill")),
            confidence=float(raw.get("confidence")),
            market_readiness=float(raw.get("market_readiness", 0.0)),
            evidence_ids=(),
            rationale="Imported legacy guided/probe score; requires evidence-led verification.",
            gaps=(
                "No itemised evidence ledger in the legacy source.",
                "Market readiness was not measured in the legacy source.",
            ),
        )
        for name, raw in block.items()
        if isinstance(raw, dict) and {"interest", "skill", "confidence"}.issubset(raw)
    }
    profile = CandidateProfile(
        profile_id=profile_id or new_profile_id(),
        version=str(meta.get("version") or "legacy-guided-import"),
        display_label=str(meta.get("subject") or "").strip() or None,
        tracks=tracks,
        constraints=constraints,
        blind_spots=blind_spots,
        unknowns=("Legacy profile has no itemised evidence ledger; all skills require verification.",),
    )
    return profile, []


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _value_sha256(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _json_document(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def _legacy_version(source: dict[str, Any]) -> str:
    version = str((source.get("meta") or {}).get("version") or "").strip()
    if version not in {"v1.4", "1.4"}:
        raise ValueError("canonical projection requires legacy profile v1.4")
    return version


def project_canonical_authority(
    *,
    authority_path: str | Path,
    evidence_packet_path: str | Path,
    legacy_profile_path: str | Path,
    data_home: str | Path,
) -> tuple[CandidateProfile, list[EvidenceItem], CanonicalProfileProjectionReceipt]:
    """Project JAA authority into one immutable external Market Aligner profile.

    The legacy profile contributes only track taxonomy and numeric priors.  All
    outward claims and current constraints come from the exact JAA authority
    and approved evidence packet.  Unbound legacy prose is recorded as omitted,
    never promoted into candidate evidence.
    """

    authority_file = Path(authority_path).resolve(strict=True)
    packet_file = Path(evidence_packet_path).resolve(strict=True)
    legacy_file = Path(legacy_profile_path).resolve(strict=True)
    authority_sha256 = _file_sha256(authority_file)
    packet_sha256 = _file_sha256(packet_file)
    legacy_sha256 = _file_sha256(legacy_file)
    authority = _json_document(authority_file)
    packet = _json_document(packet_file)
    legacy = _document(legacy_file)
    legacy_version = _legacy_version(legacy)

    if authority.get("schema_version") != "jaa.production-candidate-authority.v2":
        raise ValueError("unsupported canonical candidate authority")
    projection = dict(authority.get("candidate_projection") or {})
    if projection.get("schema_version") != "jaa.candidate-authority-projection.v1":
        raise ValueError("unsupported candidate-authority projection")
    projection_sha256 = str(projection.get("projection_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", projection_sha256):
        raise ValueError("candidate-authority projection hash is invalid")
    if (projection.get("source_hashes") or {}).get("approved_evidence") != packet_sha256:
        raise ValueError("candidate authority does not bind the supplied evidence packet")
    if packet.get("schema_version") != "jaa05.operator-approved-statements.v1":
        raise ValueError("unsupported approved evidence packet")

    statements = tuple(packet.get("statements") or ())
    approved = tuple(projection.get("approved_evidence") or ())
    if len(statements) != len(approved) or not statements:
        raise ValueError("candidate authority and evidence packet differ")
    canonical: dict[str, dict[str, Any]] = {}
    for statement, binding in zip(statements, approved, strict=True):
        if not isinstance(statement, dict) or not isinstance(binding, dict):
            raise ValueError("candidate evidence entries must be objects")
        statement_id = str(statement.get("id") or "")
        statement_text = str(statement.get("statement") or "")
        statement_sha256 = hashlib.sha256(statement_text.encode()).hexdigest()
        expected = {
            "id": statement_id,
            "kind": statement.get("kind"),
            "proof_class": statement.get("proof_class"),
            "statement_sha256": statement_sha256,
        }
        if binding != expected or not statement_id or not statement_text:
            raise ValueError("candidate authority evidence binding is invalid")
        if statement_id in canonical:
            raise ValueError("approved evidence IDs are not unique")
        canonical[statement_id] = statement

    legacy_profile = dict(legacy.get("candidate_profile") or {})
    raw_tracks = dict(legacy.get("career_tracks") or legacy_profile.get("tracks") or {})
    if not raw_tracks:
        raise ValueError("legacy profile v1.4 has no career tracks")
    raw_legacy_evidence = tuple(legacy.get("evidence") or ())
    legacy_claims = {
        str(item.get("id") or item.get("evidence_id") or ""): str(
            item.get("claim") or item.get("statement") or ""
        )
        for item in raw_legacy_evidence
        if isinstance(item, dict)
    }

    mappings: list[ProjectionDecision] = []
    omissions: list[ProjectionDecision] = []
    conflicts: list[ProjectionDecision] = []
    tracks: dict[str, TrackProfile] = {}
    used_ids: set[str] = set()
    for name, raw_value in sorted(raw_tracks.items()):
        raw = dict(raw_value or {})
        references = tuple(str(item) for item in (raw.get("evidence") or raw.get("evidence_ids") or ()))
        admitted: list[str] = []
        for evidence_id in references:
            item = canonical.get(evidence_id)
            if item is None:
                omissions.append(
                    ProjectionDecision(
                        target=f"tracks.{name}.evidence_ids",
                        source=f"legacy.evidence.{evidence_id}",
                        reason_code="absent_from_canonical_authority",
                        evidence_ids=(evidence_id,),
                    )
                )
                continue
            legacy_claim = legacy_claims.get(evidence_id)
            if legacy_claim and legacy_claim != item["statement"]:
                conflicts.append(
                    ProjectionDecision(
                        target=f"tracks.{name}.evidence_ids",
                        source=f"legacy.evidence.{evidence_id}",
                        reason_code="legacy_claim_differs_from_canonical_statement",
                        evidence_ids=(evidence_id,),
                        authority_value_sha256=hashlib.sha256(item["statement"].encode()).hexdigest(),
                        legacy_value_sha256=hashlib.sha256(legacy_claim.encode()).hexdigest(),
                    )
                )
                continue
            admitted.append(evidence_id)
        if not admitted:
            omissions.append(
                ProjectionDecision(
                    target=f"tracks.{name}",
                    source=f"legacy.tracks.{name}",
                    reason_code="no_canonical_evidence",
                )
            )
            continue
        used_ids.update(admitted)
        skill = raw.get("skill", raw.get("demonstrated_skill"))
        tracks[str(name)] = TrackProfile(
            interest=float(raw.get("interest")),
            demonstrated_skill=float(skill),
            confidence=float(raw.get("confidence")),
            market_readiness=float(raw.get("market_readiness")),
            evidence_ids=tuple(admitted),
            rationale=f"Projected from {len(admitted)} canonical approved evidence record(s).",
            gaps=(),
        )
        mappings.append(
            ProjectionDecision(
                target=f"tracks.{name}",
                source=f"legacy.tracks.{name}+canonical.evidence",
                reason_code="taxonomy_and_priors_with_canonical_evidence",
                evidence_ids=tuple(admitted),
            )
        )
        if raw.get("rationale") or raw.get("gaps"):
            omissions.append(
                ProjectionDecision(
                    target=f"tracks.{name}.legacy_prose",
                    source=f"legacy.tracks.{name}",
                    reason_code="unbound_legacy_prose",
                )
            )

    if not tracks:
        raise ValueError("legacy profile has no track backed by canonical evidence")
    evidence = [
        EvidenceItem(
            evidence_id=evidence_id,
            kind=str(canonical[evidence_id].get("kind") or "approved_statement"),
            claim=str(canonical[evidence_id]["statement"]),
            source_ref=f"authority://approved-evidence/{evidence_id}",
            status="explicit",
            confidence=1.0,
            content_sha256=hashlib.sha256(canonical[evidence_id]["statement"].encode()).hexdigest(),
        )
        for evidence_id in sorted(used_ids)
    ]

    legacy_constraints = dict(legacy.get("constraints") or legacy_profile.get("constraints") or {})
    authority_constraints = dict(projection.get("availability") or {})
    for key, authority_value in sorted(authority_constraints.items()):
        legacy_value = legacy_constraints.get(key)
        mappings.append(
            ProjectionDecision(
                target=f"constraints.{key}",
                source="candidate_authority.availability",
                reason_code="canonical_authority_wins",
                authority_value_sha256=_value_sha256(authority_value),
            )
        )
        if key in legacy_constraints and legacy_value != authority_value:
            conflicts.append(
                ProjectionDecision(
                    target=f"constraints.{key}",
                    source=f"legacy.constraints.{key}",
                    reason_code="legacy_constraint_differs_from_canonical_authority",
                    authority_value_sha256=_value_sha256(authority_value),
                    legacy_value_sha256=_value_sha256(legacy_value),
                )
            )
    for key, value in sorted(legacy_constraints.items()):
        if key not in authority_constraints:
            omissions.append(
                ProjectionDecision(
                    target=f"constraints.{key}",
                    source=f"legacy.constraints.{key}",
                    reason_code="not_present_in_canonical_authority",
                    legacy_value_sha256=_value_sha256(value),
                )
            )
    capabilities = legacy.get("capabilities") or legacy_profile.get("capabilities")
    if capabilities:
        omissions.append(
            ProjectionDecision(
                target="capabilities",
                source="legacy.capabilities",
                reason_code="unbound_legacy_capability_prose",
                legacy_value_sha256=_value_sha256(capabilities),
            )
        )
    if (legacy.get("meta") or {}).get("subject"):
        omissions.append(
            ProjectionDecision(
                target="display_label",
                source="legacy.meta.subject",
                reason_code="identity_not_required_for_market_alignment",
            )
        )

    profile_id = "prf_" + hashlib.sha256(
        f"{authority_sha256}:{packet_sha256}:{legacy_sha256}".encode()
    ).hexdigest()[:32]
    profile = CandidateProfile(
        profile_id=profile_id,
        version=f"{legacy_version}+authority-{projection_sha256[:12]}",
        tracks=tracks,
        capabilities={},
        constraints=authority_constraints,
        unknowns=tuple(
            sorted(
                {
                    "Legacy fields omitted unless bound to canonical candidate authority.",
                    *("A legacy/canonical conflict is recorded in the projection receipt." for _ in conflicts),
                }
            )
        ),
    )
    profile.validate_evidence({item.evidence_id: item for item in evidence})
    profile_sha256 = _value_sha256(asdict(profile))
    evidence_sha256 = _value_sha256([asdict(item) for item in evidence])
    receipt_values = {
        "schema": "market-aligner.canonical-profile-projection.v1",
        "profile_id": profile_id,
        "authority_sha256": authority_sha256,
        "authority_projection_sha256": projection_sha256,
        "evidence_packet_sha256": packet_sha256,
        "legacy_profile_sha256": legacy_sha256,
        "profile_sha256": profile_sha256,
        "evidence_ledger_sha256": evidence_sha256,
        "mappings": [asdict(item) for item in mappings],
        "omissions": [asdict(item) for item in omissions],
        "conflicts": [asdict(item) for item in conflicts],
        "release_authority": False,
    }
    receipt = CanonicalProfileProjectionReceipt(
        profile_id=profile_id,
        authority_sha256=authority_sha256,
        authority_projection_sha256=projection_sha256,
        evidence_packet_sha256=packet_sha256,
        legacy_profile_sha256=legacy_sha256,
        profile_sha256=profile_sha256,
        evidence_ledger_sha256=evidence_sha256,
        mappings=tuple(mappings),
        omissions=tuple(omissions),
        conflicts=tuple(conflicts),
        receipt_sha256=_value_sha256(receipt_values),
    )
    ProfileStore(data_home).save_projection(profile, evidence, receipt)
    return profile, evidence, receipt
