"""Evidence-gated atomic requirement matching for JAA-05.

A probabilistic worker may propose a relationship, but this module owns the
deterministic authority boundary.  It never infers evidence from prose and
never upgrades pending, stale, unverifiable or proof-class-incompatible
material into a match.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Mapping


MATCH_DECISIONS = frozenset({"matched", "no_match", "abstain"})
GAP_KINDS = frozenset({
    "presentation", "retrieval", "knowledge", "execution",
    "evidence", "experience", "credential", "structural",
})
BRIDGE_POLICIES = frozenset({
    "present", "retrieve", "learn_and_test", "execute_and_verify",
    "build_evidence", "gain_experience", "earn_credential",
    "fatal", "unbridgeable",
})
GAP_BRIDGE_POLICIES = {
    "presentation": frozenset({"present"}),
    "retrieval": frozenset({"retrieve"}),
    "knowledge": frozenset({"learn_and_test"}),
    "execution": frozenset({"execute_and_verify"}),
    "evidence": frozenset({"build_evidence"}),
    "experience": frozenset({"gain_experience"}),
    "credential": frozenset({"earn_credential"}),
    "structural": frozenset({"fatal", "unbridgeable"}),
}
PROOF_CLASSES = frozenset({
    "verified_claim", "work_artifact", "test_result", "external_outcome",
    "employment_record", "credential", "portfolio_artifact",
})
EVIDENCE_KIND_PROOF_CLASS = {
    "document": "verified_claim",
    "work_artifact": "work_artifact",
    "test_result": "test_result",
    "external_outcome": "external_outcome",
    "employment_record": "employment_record",
    "credential": "credential",
    "portfolio_artifact": "portfolio_artifact",
}
FACTUAL_STATES = frozenset({"fact", "evidence"})
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _identifier(label: str, value: str) -> None:
    if not value or value.strip() != value or any(character.isspace() for character in value):
        raise ValueError(f"{label} must be a non-empty whitespace-free identifier")


def _digest(label: str, value: str) -> None:
    if not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


@dataclass(frozen=True)
class MatchingPolicy:
    """Versioned deterministic decision thresholds."""

    identity: str = "jaa05.evidence-match-policy.v1"
    match_confidence_bp: int = 8000
    abstain_confidence_bp: int = 5000

    def __post_init__(self) -> None:
        _identifier("policy identity", self.identity)
        if not 0 <= self.abstain_confidence_bp <= self.match_confidence_bp <= 10_000:
            raise ValueError("matching thresholds must be ordered basis points")

    @property
    def policy_hash(self) -> str:
        return content_hash({
            "identity": self.identity,
            "match_confidence_bp": self.match_confidence_bp,
            "abstain_confidence_bp": self.abstain_confidence_bp,
        })


@dataclass(frozen=True)
class Requirement:
    """One source-bound, atomic vacancy requirement."""

    requirement_id: str
    criterion: str
    text: str
    essential: bool
    gap_kind: str
    bridge_policy: str
    accepted_proof_classes: tuple[str, ...]
    opportunity_weight_bp: int
    source_identity: str
    source_span: tuple[int, int]

    def __post_init__(self) -> None:
        _identifier("requirement_id", self.requirement_id)
        _identifier("criterion", self.criterion)
        if not self.text.strip():
            raise ValueError("requirement text is required")
        if self.gap_kind not in GAP_KINDS:
            raise ValueError("unknown gap kind")
        if self.bridge_policy not in BRIDGE_POLICIES:
            raise ValueError("unknown bridge policy")
        if self.bridge_policy not in GAP_BRIDGE_POLICIES[self.gap_kind]:
            raise ValueError("gap kind and bridge policy are inconsistent")
        if self.bridge_policy in {"fatal", "unbridgeable"} and not self.essential:
            raise ValueError("only essential requirements may block candidacy")
        if (
            not self.accepted_proof_classes
            or len(set(self.accepted_proof_classes)) != len(self.accepted_proof_classes)
            or not set(self.accepted_proof_classes).issubset(PROOF_CLASSES)
        ):
            raise ValueError("requirement must declare unique supported proof classes")
        if not 1 <= self.opportunity_weight_bp <= 10_000:
            raise ValueError("opportunity weight must be positive basis points")
        if not self.source_identity.strip():
            raise ValueError("requirement source identity is required")
        start, end = self.source_span
        if start < 0 or end <= start:
            raise ValueError("requirement must bind to a non-empty source span")


@dataclass(frozen=True)
class Evidence:
    """A candidate-evidence projection whose authority remains in JAA-02."""

    evidence_id: str
    version: int
    statement: str
    demonstrates: tuple[str, ...]
    proof_class: str
    approval_state: str
    epistemic_state: str
    verification_decision: str
    verification_method: str
    content_sha256: str
    valid_until: date | None = None
    negative: bool = False
    claim_lineage: tuple[tuple[str, int, str], ...] = ()
    evidence_provenance: tuple[str, str] | None = None

    def __post_init__(self) -> None:
        _identifier("evidence_id", self.evidence_id)
        if self.version < 1:
            raise ValueError("evidence version must be positive")
        if not self.statement.strip():
            raise ValueError("evidence statement is required")
        if (
            not self.demonstrates
            or len(set(self.demonstrates)) != len(self.demonstrates)
        ):
            raise ValueError("evidence must declare unique verified criteria")
        for criterion in self.demonstrates:
            _identifier("demonstrated criterion", criterion)
        if self.proof_class not in PROOF_CLASSES:
            raise ValueError("unknown evidence proof class")
        if not self.verification_method.strip():
            raise ValueError("evidence verification method is required")
        _digest("evidence content hash", self.content_sha256)
        if hashlib.sha256(self.statement.encode("utf-8")).hexdigest() != self.content_sha256:
            raise ValueError("evidence content hash does not bind its exact statement")
        claim_ids: set[str] = set()
        for claim_id, version, claim_sha256 in self.claim_lineage:
            _identifier("evidence claim-lineage ID", claim_id)
            if version < 1:
                raise ValueError("evidence claim-lineage version must be positive")
            _digest("evidence exact claim-lineage hash", claim_sha256)
            claim_ids.add(claim_id)
        if (
            len(claim_ids) != len(self.claim_lineage)
            or claim_ids.difference(self.demonstrates)
        ):
            raise ValueError(
                "evidence claim lineage must uniquely bind demonstrated claims"
            )
        if self.evidence_provenance is not None:
            provenance_id, source_sha256 = self.evidence_provenance
            _identifier("evidence provenance ID", provenance_id)
            _digest("evidence provenance source hash", source_sha256)

    def is_releasable(self, *, as_of: date) -> bool:
        return (
            self.approval_state == "approved"
            and self.epistemic_state in FACTUAL_STATES
            and self.verification_decision == "approved"
            and not self.negative
            and (self.valid_until is None or self.valid_until >= as_of)
        )


@dataclass(frozen=True)
class InferenceReceipt:
    """Complete provenance for a probabilistic match proposal."""

    provider: str
    model: str
    prompt_sha256: str
    policy_sha256: str
    candidate_profile_sha256: str
    input_sha256: str

    def __post_init__(self) -> None:
        if not self.provider.strip() or not self.model.strip():
            raise ValueError("proposal provider and model are required")
        for label, digest in (
            ("prompt", self.prompt_sha256),
            ("policy", self.policy_sha256),
            ("candidate profile", self.candidate_profile_sha256),
            ("input", self.input_sha256),
        ):
            _digest(f"{label} hash", digest)


@dataclass(frozen=True)
class MatchProposal:
    requirement_id: str
    evidence_ids: tuple[str, ...]
    confidence_bp: int
    basis: str
    rationale: str
    receipt: InferenceReceipt
    # Explicit (evidence_id, claim_id) bindings into Evidence.claim_lineage.
    # When present, evaluate_match uses the citation path (candidate-claim namespace).
    # When absent, the deprecated criterion-in-demonstrates path is used (vacancy namespace).
    citations: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _identifier("proposal requirement_id", self.requirement_id)
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("proposal evidence IDs must be unique")
        if not 0 <= self.confidence_bp <= 10_000:
            raise ValueError("proposal confidence must be basis points")
        if self.basis not in {"direct", "contradicts", "none"}:
            raise ValueError("unsupported match basis")
        if self.basis == "none" and self.evidence_ids:
            raise ValueError("a no-evidence proposal cannot cite evidence")
        if self.basis != "none" and not self.evidence_ids:
            raise ValueError("a relationship proposal must cite evidence")
        if not self.rationale.strip():
            raise ValueError("proposal rationale is required")
        if self.citations:
            unknown_ev = {ev_id for ev_id, _ in self.citations}.difference(self.evidence_ids)
            if unknown_ev:
                raise ValueError(
                    f"citations reference evidence IDs not in evidence_ids: "
                    f"{sorted(unknown_ev)}"
                )
            if len(set(self.citations)) != len(self.citations):
                raise ValueError("citation (evidence_id, claim_id) pairs must be unique")
            for ev_id, claim_id in self.citations:
                _identifier("citation evidence_id", ev_id)
                _identifier("citation claim_id", claim_id)


@dataclass(frozen=True)
class MatchResult:
    requirement_id: str
    decision: str
    evidence_ids: tuple[str, ...]
    confidence_bp: int
    reason: str
    policy_sha256: str
    proposal_sha256: str | None
    receipt: InferenceReceipt | None = None

    def __post_init__(self) -> None:
        if self.decision not in MATCH_DECISIONS:
            raise ValueError("unknown match decision")
        if (self.proposal_sha256 is None) != (self.receipt is None):
            raise ValueError("proposal hash and inference receipt must appear together")


@dataclass(frozen=True)
class CandidateMatchBatch:
    results: tuple[MatchResult, ...]
    candidate_profile_sha256: str
    policy_sha256: str
    as_of: date

    def __post_init__(self) -> None:
        _digest("candidate profile hash", self.candidate_profile_sha256)
        _digest("matching policy hash", self.policy_sha256)
        if any(result.policy_sha256 != self.policy_sha256 for result in self.results):
            raise ValueError("batch contains mixed matching policies")
        for result in self.results:
            if (
                result.receipt is not None
                and result.receipt.candidate_profile_sha256
                != self.candidate_profile_sha256
            ):
                raise ValueError("batch contains mixed candidate profiles")


def _proposal_hash(proposal: MatchProposal) -> str:
    payload: dict[str, Any] = {
        "requirement_id": proposal.requirement_id,
        "evidence_ids": proposal.evidence_ids,
        "confidence_bp": proposal.confidence_bp,
        "basis": proposal.basis,
        "rationale": proposal.rationale,
        "receipt": vars(proposal.receipt),
    }
    if proposal.citations:
        payload["citations"] = proposal.citations
    return content_hash(payload)


def _requirement_payload(requirement: Requirement) -> dict[str, Any]:
    return {
        "requirement_id": requirement.requirement_id,
        "criterion": requirement.criterion,
        "text": requirement.text,
        "essential": requirement.essential,
        "gap_kind": requirement.gap_kind,
        "bridge_policy": requirement.bridge_policy,
        "accepted_proof_classes": requirement.accepted_proof_classes,
        "opportunity_weight_bp": requirement.opportunity_weight_bp,
        "source_identity": requirement.source_identity,
        "source_span": requirement.source_span,
    }


def _evidence_payload(evidence: Evidence) -> dict[str, Any]:
    result = {
        "evidence_id": evidence.evidence_id,
        "version": evidence.version,
        "statement": evidence.statement,
        "demonstrates": evidence.demonstrates,
        "proof_class": evidence.proof_class,
        "approval_state": evidence.approval_state,
        "epistemic_state": evidence.epistemic_state,
        "verification_decision": evidence.verification_decision,
        "verification_method": evidence.verification_method,
        "content_sha256": evidence.content_sha256,
        "valid_until": evidence.valid_until.isoformat() if evidence.valid_until else None,
        "negative": evidence.negative,
    }
    # Synthetic/offline Evidence values predate exact JAA-02 claim lineage.
    # Production graph projections always populate this field; omitting the
    # empty value preserves the locked software-vector identity.
    if evidence.claim_lineage:
        result["claim_lineage"] = evidence.claim_lineage
    if evidence.evidence_provenance is not None:
        result["evidence_provenance"] = evidence.evidence_provenance
    return result


def evidence_projection_hash(evidence: Iterable[Evidence]) -> str:
    rows = tuple(evidence)
    if len({row.evidence_id for row in rows}) != len(rows):
        raise ValueError("evidence IDs must be unique")
    return content_hash([
        _evidence_payload(row)
        for row in sorted(rows, key=lambda item: (item.evidence_id, item.version))
    ])


def matching_input_hash(
    requirement: Requirement,
    *,
    candidate_profile_sha256: str,
    as_of: date,
) -> str:
    _digest("candidate profile hash", candidate_profile_sha256)
    return content_hash({
        "requirement": _requirement_payload(requirement),
        "candidate_profile_sha256": candidate_profile_sha256,
        "as_of": as_of.isoformat(),
    })


def requirement_from_mapping(value: Mapping[str, Any]) -> Requirement:
    span = value.get("source_span")
    if not isinstance(span, list) or len(span) != 2:
        raise ValueError("requirement source_span must contain two integers")
    if not isinstance(value.get("essential"), bool):
        raise ValueError("requirement essential must be boolean")
    return Requirement(
        requirement_id=str(value.get("requirement_id", "")),
        criterion=str(value.get("criterion", "")),
        text=str(value.get("text", "")),
        essential=value.get("essential") is True,
        gap_kind=str(value.get("gap_kind", "")),
        bridge_policy=str(value.get("bridge_policy", "")),
        accepted_proof_classes=tuple(value.get("accepted_proof_classes") or ()),
        opportunity_weight_bp=int(value.get("opportunity_weight_bp", 0)),
        source_identity=str(value.get("source_identity", "")),
        source_span=(int(span[0]), int(span[1])),
    )


def evidence_from_mapping(value: Mapping[str, Any]) -> Evidence:
    valid_until = value.get("valid_until")
    raw_lineage = value.get("claim_lineage") or ()
    raw_provenance = value.get("evidence_provenance")
    if not isinstance(raw_lineage, (list, tuple)) or any(
        not isinstance(row, (list, tuple)) or len(row) != 3
        for row in raw_lineage
    ):
        raise ValueError("evidence claim_lineage must contain claim bindings")
    if raw_provenance is not None and (
        not isinstance(raw_provenance, (list, tuple))
        or len(raw_provenance) != 2
    ):
        raise ValueError(
            "evidence_provenance must contain provenance ID and source hash"
        )
    if not isinstance(value.get("negative"), bool):
        raise ValueError("evidence negative must be boolean")
    return Evidence(
        evidence_id=str(value.get("evidence_id", "")),
        version=int(value.get("version", 0)),
        statement=str(value.get("statement", "")),
        demonstrates=tuple(value.get("demonstrates") or ()),
        proof_class=str(value.get("proof_class", "")),
        approval_state=str(value.get("approval_state", "")),
        epistemic_state=str(value.get("epistemic_state", "")),
        verification_decision=str(value.get("verification_decision", "")),
        verification_method=str(value.get("verification_method", "")),
        content_sha256=str(value.get("content_sha256", "")),
        valid_until=date.fromisoformat(str(valid_until)) if valid_until else None,
        negative=value.get("negative") is True,
        claim_lineage=tuple(
            (str(row[0]), int(row[1]), str(row[2]))
            for row in raw_lineage
        ),
        evidence_provenance=(
            None
            if raw_provenance is None
            else (str(raw_provenance[0]), str(raw_provenance[1]))
        ),
    )


def proposal_from_mapping(value: Mapping[str, Any]) -> MatchProposal:
    receipt = value.get("receipt")
    if not isinstance(receipt, Mapping):
        raise ValueError("proposal inference receipt is required")
    raw_citations = value.get("citations") or ()
    if not isinstance(raw_citations, (list, tuple)) or any(
        not isinstance(row, (list, tuple)) or len(row) != 2
        for row in raw_citations
    ):
        raise ValueError("proposal citations must be (evidence_id, claim_id) pairs")
    return MatchProposal(
        requirement_id=str(value.get("requirement_id", "")),
        evidence_ids=tuple(value.get("evidence_ids") or ()),
        confidence_bp=int(value.get("confidence_bp", -1)),
        basis=str(value.get("basis", "")),
        rationale=str(value.get("rationale", "")),
        receipt=InferenceReceipt(
            provider=str(receipt.get("provider", "")),
            model=str(receipt.get("model", "")),
            prompt_sha256=str(receipt.get("prompt_sha256", "")),
            policy_sha256=str(receipt.get("policy_sha256", "")),
            candidate_profile_sha256=str(receipt.get("candidate_profile_sha256", "")),
            input_sha256=str(receipt.get("input_sha256", "")),
        ),
        citations=tuple((str(row[0]), str(row[1])) for row in raw_citations),
    )


def evaluate_match(
    requirement: Requirement,
    proposal: MatchProposal | None,
    evidence: Mapping[str, Evidence],
    *,
    as_of: date,
    policy: MatchingPolicy = MatchingPolicy(),
) -> MatchResult:
    """Apply the deterministic authority gate to one proposed relationship."""
    if proposal is None:
        return MatchResult(
            requirement.requirement_id,
            "abstain",
            (),
            0,
            "no match proposal was supplied",
            policy.policy_hash,
            None,
            None,
        )
    if proposal.requirement_id != requirement.requirement_id:
        raise ValueError("proposal requirement identity mismatch")
    if proposal.receipt.policy_sha256 != policy.policy_hash:
        raise ValueError("proposal policy hash mismatch")
    profile_sha256 = evidence_projection_hash(evidence.values())
    if proposal.receipt.candidate_profile_sha256 != profile_sha256:
        raise ValueError("proposal candidate profile hash mismatch")
    expected_input = matching_input_hash(
        requirement,
        candidate_profile_sha256=profile_sha256,
        as_of=as_of,
    )
    if proposal.receipt.input_sha256 != expected_input:
        raise ValueError("proposal input hash mismatch")
    unknown = set(proposal.evidence_ids).difference(evidence)
    if unknown:
        raise ValueError(f"proposal cites unknown evidence IDs: {sorted(unknown)}")
    proposal_sha256 = _proposal_hash(proposal)
    if proposal.confidence_bp < policy.abstain_confidence_bp:
        return MatchResult(
            requirement.requirement_id, "abstain", (), proposal.confidence_bp,
            "proposal confidence is below the reviewable floor",
            policy.policy_hash, proposal_sha256,
            proposal.receipt,
        )
    if proposal.basis == "none":
        decision = (
            "no_match"
            if proposal.confidence_bp >= policy.match_confidence_bp
            else "abstain"
        )
        return MatchResult(
            requirement.requirement_id, decision, (), proposal.confidence_bp,
            "review found no candidate evidence" if decision == "no_match"
            else "absence assessment is not confident enough",
            policy.policy_hash, proposal_sha256,
            proposal.receipt,
        )
    cited = tuple(evidence[evidence_id] for evidence_id in proposal.evidence_ids)
    if proposal.basis == "contradicts":
        return MatchResult(
            requirement.requirement_id,
            "no_match" if proposal.confidence_bp >= policy.match_confidence_bp else "abstain",
            proposal.evidence_ids,
            proposal.confidence_bp,
            "candidate evidence contradicts the requirement",
            policy.policy_hash,
            proposal_sha256,
            proposal.receipt,
        )
    if proposal.citations:
        # Citation path: each (evidence_id, claim_id) must bind into Evidence.claim_lineage,
        # AND every cited pair must be releasable with an accepted proof class.
        # Vacancy criteria and candidate claim IDs are separate namespaces; this path
        # operates entirely within the candidate-claim namespace.
        lineage_failures: list[tuple[str, str]] = []
        ineligible_pairs: list[tuple[str, str]] = []
        eligible_ids: list[str] = []
        for ev_id, claim_id in proposal.citations:
            ev = evidence[ev_id]  # existence guaranteed by __post_init__ + prior unknown check
            lineage_claim_ids = {cl[0] for cl in ev.claim_lineage}
            if claim_id not in lineage_claim_ids:
                lineage_failures.append((ev_id, claim_id))
            elif ev.is_releasable(as_of=as_of) and ev.proof_class in requirement.accepted_proof_classes:
                if ev_id not in eligible_ids:
                    eligible_ids.append(ev_id)
            else:
                ineligible_pairs.append((ev_id, claim_id))
        if lineage_failures:
            return MatchResult(
                requirement.requirement_id, "no_match", (), proposal.confidence_bp,
                f"cited claim_id not in evidence claim_lineage: {lineage_failures[0]}",
                policy.policy_hash, proposal_sha256, proposal.receipt,
            )
        if ineligible_pairs:
            return MatchResult(
                requirement.requirement_id, "no_match", (), proposal.confidence_bp,
                f"cited (evidence, claim) pair resolves lineage but is not releasable "
                f"with an accepted proof class: {ineligible_pairs[0]}",
                policy.policy_hash, proposal_sha256, proposal.receipt,
            )
        if not eligible_ids:
            return MatchResult(
                requirement.requirement_id, "no_match", (), proposal.confidence_bp,
                "no cited (evidence, claim) pair is releasable with an accepted proof class",
                policy.policy_hash, proposal_sha256, proposal.receipt,
            )
        if proposal.confidence_bp < policy.match_confidence_bp:
            return MatchResult(
                requirement.requirement_id, "abstain",
                tuple(eligible_ids), proposal.confidence_bp,
                "citation-bound relationship confidence is below the match threshold",
                policy.policy_hash, proposal_sha256, proposal.receipt,
            )
        return MatchResult(
            requirement.requirement_id, "matched",
            tuple(eligible_ids), proposal.confidence_bp,
            "citation-bound evidence demonstrates requirement through approved claim lineage",
            policy.policy_hash, proposal_sha256, proposal.receipt,
        )
    # DEPRECATED: criterion-in-demonstrates fallback when no explicit citations are supplied.
    # The requirement criterion (vacancy namespace) is matched against Evidence.demonstrates
    # (candidate-claim namespace), which crosses the namespace boundary. Preserved only for
    # backward compatibility with proposals that predate explicit citation binding.
    eligible = tuple(
        item for item in cited
        if item.is_releasable(as_of=as_of)
        and requirement.criterion in item.demonstrates
        and item.proof_class in requirement.accepted_proof_classes
    )
    if not eligible:
        return MatchResult(
            requirement.requirement_id, "no_match", (), proposal.confidence_bp,
            "cited material is not current approved evidence of an accepted proof class",
            policy.policy_hash, proposal_sha256,
            proposal.receipt,
        )
    if proposal.confidence_bp < policy.match_confidence_bp:
        return MatchResult(
            requirement.requirement_id, "abstain",
            tuple(item.evidence_id for item in eligible), proposal.confidence_bp,
            "direct relationship confidence is below the match threshold",
            policy.policy_hash, proposal_sha256,
            proposal.receipt,
        )
    return MatchResult(
        requirement.requirement_id, "matched",
        tuple(item.evidence_id for item in eligible), proposal.confidence_bp,
        "current approved evidence directly demonstrates the atomic criterion",
        policy.policy_hash, proposal_sha256,
        proposal.receipt,
    )


def match_requirements(
    requirements: Iterable[Requirement],
    proposals: Iterable[MatchProposal],
    evidence: Iterable[Evidence],
    *,
    as_of: date,
    policy: MatchingPolicy = MatchingPolicy(),
) -> tuple[MatchResult, ...]:
    requirement_rows = tuple(requirements)
    proposal_rows = tuple(proposals)
    evidence_rows = tuple(evidence)
    requirement_ids = [row.requirement_id for row in requirement_rows]
    proposal_ids = [row.requirement_id for row in proposal_rows]
    evidence_ids = [row.evidence_id for row in evidence_rows]
    if len(set(requirement_ids)) != len(requirement_ids):
        raise ValueError("requirement IDs must be unique")
    if len(set(proposal_ids)) != len(proposal_ids):
        raise ValueError("at most one proposal is permitted per requirement")
    if len(set(evidence_ids)) != len(evidence_ids):
        raise ValueError("evidence IDs must be unique")
    extra = set(proposal_ids).difference(requirement_ids)
    if extra:
        raise ValueError(f"proposals cite unknown requirement IDs: {sorted(extra)}")
    by_proposal = {row.requirement_id: row for row in proposal_rows}
    by_evidence = {row.evidence_id: row for row in evidence_rows}
    return tuple(
        evaluate_match(
            requirement,
            by_proposal.get(requirement.requirement_id),
            by_evidence,
            as_of=as_of,
            policy=policy,
        )
        for requirement in requirement_rows
    )


def candidate_graph_evidence(
    path: str | Path,
    *,
    as_of: date,
) -> tuple[Evidence, ...]:
    """Build the only production evidence projection from JAA-02 authority.

    Demonstrated criteria are approved JAA-02 claim IDs joined through
    supporting edges.  A newer evidence version suppresses every older one,
    even if the newer version has not been approved.  Approved negative
    evidence remains in the hashed projection so a proposal cannot hide a
    contradiction, but ``Evidence.is_releasable`` prevents it from supporting
    a positive match.
    """
    database = Path(path).resolve()
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """SELECT evidence.evidence_id,evidence.version,evidence.statement,
                      evidence.evidence_kind,evidence.approval_state,
                      evidence.epistemic_state,evidence.negative,
                      evidence.valid_until,evidence.content_hash,
                      evidence.provenance_id AS evidence_provenance_id,
                      evidence_provenance.source_hash AS evidence_source_hash,
                      claim.claim_id,claim.version AS claim_version,
                      claim.statement AS claim_statement,
                      claim.claim_type AS claim_type,
                      claim.epistemic_state AS claim_epistemic_state,
                      claim.approval_state AS claim_approval_state,
                      claim.valid_until AS claim_valid_until,
                      claim.provenance_id AS claim_provenance_id,
                      claim_provenance.source_hash AS claim_source_hash,
                      decision.decision_id,decision.verifier_kind,decision.policy_id,
                      decision.policy_version,decision.policy_hash,decision.reason,
                      decision.provenance_id AS decision_provenance_id,
                      decision_provenance.source_hash AS decision_source_hash
               FROM candidate_evidence evidence
               JOIN candidate_provenance evidence_provenance
                 ON evidence_provenance.provenance_id=evidence.provenance_id
               JOIN candidate_claim_edges edge
                 ON edge.evidence_id=evidence.evidence_id
                AND edge.evidence_version=evidence.version
                AND edge.edge_type IN ('supports','demonstrated_by')
               JOIN candidate_claims claim
                 ON claim.claim_id=edge.claim_id
                AND claim.version=edge.claim_version
               JOIN candidate_provenance claim_provenance
                 ON claim_provenance.provenance_id=claim.provenance_id
               JOIN candidate_verification_decisions decision
                 ON decision.target_kind='evidence'
                AND decision.target_id=evidence.evidence_id
                AND decision.target_version=evidence.version
                AND decision.decision='approved'
               JOIN candidate_provenance decision_provenance
                 ON decision_provenance.provenance_id=decision.provenance_id
               WHERE evidence.approval_state='approved'
                 AND evidence.epistemic_state IN ('fact','evidence')
                 AND (evidence.valid_until IS NULL OR evidence.valid_until>=?)
                 AND claim.approval_state='approved'
                 AND claim.epistemic_state IN ('fact','evidence')
                 AND (claim.valid_until IS NULL OR claim.valid_until>=?)
                 AND NOT EXISTS(
                   SELECT 1 FROM candidate_claims newer_claim
                   WHERE newer_claim.claim_id=claim.claim_id
                     AND newer_claim.version>claim.version
                 )
                 AND NOT EXISTS(
                   SELECT 1 FROM candidate_evidence newer
                   WHERE newer.evidence_id=evidence.evidence_id
                     AND newer.version>evidence.version
                 )
               ORDER BY evidence.evidence_id,evidence.version,claim.claim_id,
                        decision.decision_id""",
            (as_of.isoformat(), as_of.isoformat()),
        ).fetchall()
    except sqlite3.DatabaseError as exc:
        raise ValueError("candidate graph does not provide the JAA-02 evidence contract") from exc
    finally:
        connection.close()
    grouped: dict[tuple[str, int], list[sqlite3.Row]] = {}
    for row in rows:
        grouped.setdefault((str(row["evidence_id"]), int(row["version"])), []).append(row)
    result: list[Evidence] = []
    for (evidence_id, version), group in grouped.items():
        proof_class = EVIDENCE_KIND_PROOF_CLASS.get(str(group[0]["evidence_kind"]))
        if proof_class is None:
            continue
        decisions = {
            (
                str(row["decision_id"]),
                str(row["verifier_kind"]),
                str(row["policy_id"]),
                str(row["policy_version"]),
                str(row["policy_hash"]),
            )
            for row in group
        }
        if len(decisions) != 1:
            raise ValueError("candidate evidence has ambiguous approval decisions")
        decision_id, verifier_kind, policy_id, policy_version, policy_hash = (
            decisions.pop()
        )
        _digest("candidate verification policy hash", policy_hash)
        decision_row = group[0]
        if str(decision_row["decision_source_hash"]) != content_hash({
            "policy_hash": policy_hash,
            "reason": str(decision_row["reason"]),
        }):
            raise ValueError(
                "candidate verification provenance does not bind its decision"
            )
        valid_until = group[0]["valid_until"]
        result.append(Evidence(
            evidence_id=evidence_id,
            version=version,
            statement=str(group[0]["statement"]),
            demonstrates=tuple(sorted({str(row["claim_id"]) for row in group})),
            proof_class=proof_class,
            approval_state=str(group[0]["approval_state"]),
            epistemic_state=str(group[0]["epistemic_state"]),
            verification_decision="approved",
            verification_method=(
                f"{decision_id}:{verifier_kind}:{policy_id}:"
                f"{policy_version}:{policy_hash}:"
                f"{decision_row['decision_provenance_id']}:"
                f"{decision_row['decision_source_hash']}"
            ),
            content_sha256=str(group[0]["content_hash"]),
            valid_until=date.fromisoformat(str(valid_until)) if valid_until else None,
            negative=bool(group[0]["negative"]),
            claim_lineage=tuple(sorted({
                (
                    str(row["claim_id"]),
                    int(row["claim_version"]),
                    content_hash({
                        "claim_id": str(row["claim_id"]),
                        "version": int(row["claim_version"]),
                        "statement": str(row["claim_statement"]),
                        "claim_type": str(row["claim_type"]),
                        "epistemic_state": str(row["claim_epistemic_state"]),
                        "approval_state": str(row["claim_approval_state"]),
                        "valid_until": (
                            None
                            if row["claim_valid_until"] is None
                            else str(row["claim_valid_until"])
                        ),
                        "provenance_id": str(row["claim_provenance_id"]),
                        "provenance_sha256": str(row["claim_source_hash"]),
                    }),
                )
                for row in group
            })),
            evidence_provenance=(
                str(group[0]["evidence_provenance_id"]),
                str(group[0]["evidence_source_hash"]),
            ),
        ))
    return tuple(result)


def match_candidate_graph(
    requirements: Iterable[Requirement],
    proposals: Iterable[MatchProposal],
    candidate_graph_path: str | Path,
    *,
    as_of: date,
    policy: MatchingPolicy = MatchingPolicy(),
) -> CandidateMatchBatch:
    """Match through the authoritative JAA-02 graph rather than caller claims."""
    evidence = candidate_graph_evidence(candidate_graph_path, as_of=as_of)
    results = match_requirements(
        requirements,
        proposals,
        evidence,
        as_of=as_of,
        policy=policy,
    )
    return CandidateMatchBatch(
        results,
        evidence_projection_hash(evidence),
        policy.policy_hash,
        as_of,
    )


def score_locked_labels(
    results: Iterable[MatchResult],
    labels: Mapping[str, str],
) -> dict[str, int]:
    """Return integer calibration metrics without hiding undefined cases."""
    rows = tuple(results)
    by_id = {row.requirement_id: row.decision for row in rows}
    if len(by_id) != len(rows) or set(by_id) != set(labels):
        raise ValueError("locked labels and evaluated requirements must match exactly")
    if not set(labels.values()).issubset(MATCH_DECISIONS):
        raise ValueError("locked labels contain an invalid decision")
    true_matches = sum(by_id[key] == labels[key] == "matched" for key in labels)
    predicted_matches = sum(value == "matched" for value in by_id.values())
    labelled_matches = sum(value == "matched" for value in labels.values())
    labelled_abstentions = sum(value == "abstain" for value in labels.values())
    predicted_abstentions = sum(value == "abstain" for value in by_id.values())
    correct_abstentions = sum(by_id[key] == labels[key] == "abstain" for key in labels)

    def ratio(numerator: int, denominator: int, label: str) -> int:
        if denominator == 0:
            raise ValueError(f"{label} is undefined for this locked set")
        return numerator * 10_000 // denominator

    return {
        "precision_bp": ratio(true_matches, predicted_matches, "precision"),
        "recall_bp": ratio(true_matches, labelled_matches, "recall"),
        "abstention_precision_bp": ratio(
            correct_abstentions, predicted_abstentions, "abstention precision"
        ),
        "abstention_recall_bp": ratio(
            correct_abstentions, labelled_abstentions, "abstention accuracy"
        ),
        "exact_accuracy_bp": ratio(
            sum(by_id[key] == labels[key] for key in labels), len(labels), "accuracy"
        ),
        "examples": len(labels),
    }
