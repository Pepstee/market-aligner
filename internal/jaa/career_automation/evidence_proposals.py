"""Create-only, non-authoritative candidate evidence proposals from Git sources.

Approved candidate authority is intentionally outside this boundary. A packet
can only prove that proposed wording is traceable to immutable repository
content and tests; a separate evidence admission gate must accept it.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping

from .evidence_matching import content_hash


PACKET_SCHEMA = "jaa.candidate-evidence-proposal-packet.v1"
_SHA = re.compile(r"^[0-9a-f]{40,64}$")


class EvidenceProposalError(ValueError):
    """A proposal is unbound, malformed, or attempts to grant authority."""


def _required(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise EvidenceProposalError(f"{label} must be a trimmed non-empty string")
    return value


def _sha(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise EvidenceProposalError(f"{label} must be a lowercase Git/SHA-256 digest")
    return value


@dataclass(frozen=True)
class RepositoryEvidence:
    repository_id: str
    commit: str
    source_path: str
    source_sha256: str
    test_path: str
    test_sha256: str
    test_command_sha256: str
    observed_test_result_sha256: str

    def __post_init__(self) -> None:
        _required(self.repository_id, "repository ID")
        _required(self.source_path, "source path")
        _required(self.test_path, "test path")
        if Path(self.source_path).is_absolute() or Path(self.test_path).is_absolute():
            raise EvidenceProposalError("evidence paths must be repository-relative")
        for value, label in (
            (self.commit, "repository commit"),
            (self.source_sha256, "source hash"),
            (self.test_sha256, "test hash"),
            (self.test_command_sha256, "test command hash"),
            (self.observed_test_result_sha256, "test result hash"),
        ):
            _sha(value, label)


@dataclass(frozen=True)
class CandidateEvidenceProposal:
    proposal_id: str
    capability_group: str
    disposition: str
    candidate_statement: str | None
    evidence: tuple[RepositoryEvidence, ...]
    reason_code: str

    def __post_init__(self) -> None:
        _required(self.proposal_id, "proposal ID")
        _required(self.capability_group, "capability group")
        _required(self.reason_code, "proposal reason")
        if self.disposition not in {"proposed", "rejected"}:
            raise EvidenceProposalError("proposal disposition is unsupported")
        if self.disposition == "proposed":
            _required(self.candidate_statement or "", "candidate statement")
            if not self.evidence:
                raise EvidenceProposalError("proposed statements require repository evidence")
        elif self.candidate_statement is not None or self.evidence:
            raise EvidenceProposalError("rejected statements cannot carry outward claims")
        for item in self.evidence:
            item.__post_init__()


@dataclass(frozen=True)
class CandidateEvidenceProposalPacket:
    proposals: tuple[CandidateEvidenceProposal, ...]
    packet_sha256: str
    release_authority: bool = False
    authority_mutation: bool = False
    schema_version: str = PACKET_SCHEMA

    def __post_init__(self) -> None:
        if self.schema_version != PACKET_SCHEMA or not self.proposals:
            raise EvidenceProposalError("proposal packet is unsupported or empty")
        if len({item.proposal_id for item in self.proposals}) != len(self.proposals):
            raise EvidenceProposalError("proposal packet repeats an identity")
        for item in self.proposals:
            item.__post_init__()
        if self.release_authority is not False or self.authority_mutation is not False:
            raise EvidenceProposalError("evidence proposals cannot mutate or release authority")
        if self.packet_sha256 != content_hash(self.document(include_identity=False)):
            raise EvidenceProposalError("proposal packet identity is invalid")

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "authority_mutation": False,
            "proposals": [asdict(item) for item in self.proposals],
            "release_authority": False,
            "schema_version": self.schema_version,
        }
        if include_identity:
            value["packet_sha256"] = self.packet_sha256
        return value


def build_evidence_proposal_packet(proposals: tuple[CandidateEvidenceProposal, ...]) -> CandidateEvidenceProposalPacket:
    values = {
        "authority_mutation": False,
        "proposals": [asdict(item) for item in proposals],
        "release_authority": False,
        "schema_version": PACKET_SCHEMA,
    }
    return CandidateEvidenceProposalPacket(proposals, content_hash(values))


def load_evidence_proposal_packet(path: str | Path) -> CandidateEvidenceProposalPacket:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    proposals = []
    for raw in payload.get("proposals", ()):
        evidence = tuple(RepositoryEvidence(**item) for item in raw.get("evidence", ()))
        proposals.append(CandidateEvidenceProposal(
            proposal_id=raw.get("proposal_id"),
            capability_group=raw.get("capability_group"),
            disposition=raw.get("disposition"),
            candidate_statement=raw.get("candidate_statement"),
            evidence=evidence,
            reason_code=raw.get("reason_code"),
        ))
    return CandidateEvidenceProposalPacket(
        proposals=tuple(proposals),
        packet_sha256=payload.get("packet_sha256"),
        release_authority=payload.get("release_authority"),
        authority_mutation=payload.get("authority_mutation"),
        schema_version=payload.get("schema_version"),
    )


def _git_bytes(root: Path, commit: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), "show", f"{commit}:{path}"],
        check=False, capture_output=True,
    )
    if result.returncode:
        raise EvidenceProposalError("repository evidence is absent at the cited commit")
    return result.stdout


def verify_evidence_proposal_packet(
    packet: CandidateEvidenceProposalPacket,
    repository_roots: Mapping[str, str | Path],
) -> None:
    packet.__post_init__()
    for proposal in packet.proposals:
        for item in proposal.evidence:
            root_value = repository_roots.get(item.repository_id)
            if root_value is None:
                raise EvidenceProposalError("proposal repository is not mounted")
            root = Path(root_value).resolve(strict=True)
            resolved = subprocess.run(
                ["git", "-C", str(root), "rev-parse", item.commit],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            if resolved != item.commit:
                raise EvidenceProposalError("proposal commit is not exact")
            for path, expected in (
                (item.source_path, item.source_sha256),
                (item.test_path, item.test_sha256),
            ):
                actual = hashlib.sha256(_git_bytes(root, item.commit, path)).hexdigest()
                if actual != expected:
                    raise EvidenceProposalError("proposal repository content drifted")


def write_evidence_proposal_packet(path: str | Path, packet: CandidateEvidenceProposalPacket) -> None:
    target = Path(path)
    content = json.dumps(packet.document(), sort_keys=True, separators=(",", ":")) + "\n"
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("x", encoding="utf-8") as handle:
            handle.write(content)
    except FileExistsError:
        if target.read_text(encoding="utf-8") != content:
            raise EvidenceProposalError("proposal packet destination drifted")


__all__ = [
    "CandidateEvidenceProposal", "CandidateEvidenceProposalPacket",
    "EvidenceProposalError", "RepositoryEvidence",
    "build_evidence_proposal_packet", "verify_evidence_proposal_packet",
    "load_evidence_proposal_packet", "write_evidence_proposal_packet",
]
