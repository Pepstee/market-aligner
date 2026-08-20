"""Canonical, versioned candidate fact, evidence and claim graph (JAA-02)."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

from .migrations import apply_jaa_02_migrations


RELEASE_STATES = frozenset({"fact", "evidence"})
ALL_STATES = frozenset(
    {"fact", "evidence", "inference", "unknown", "expired", "disputed", "unverified"}
)
DEFAULT_SECRET_PATTERNS = (
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"(?i)\b(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*\S+",
    r"\bgh[opsu]_[A-Za-z0-9]{20,}\b",
    r"\bAKIA[0-9A-Z]{16}\b",
)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _hash(value: Any) -> str:
    payload = value if isinstance(value, str) else _canonical(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _identifier(prefix: str, *parts: Any) -> str:
    return f"{prefix}-{_hash(parts)[:24]}"


def _state(value: Any, *, default: str = "unverified") -> str:
    raw = str(value or default).strip().casefold()
    aliases = {"verified": "evidence", "explicit": "fact", "unverified_current": "unverified"}
    result = aliases.get(raw, raw)
    if result not in ALL_STATES:
        return "unverified"
    return result


@dataclass(frozen=True)
class WorkRightResolution:
    decision: str
    jurisdiction: str
    contract_type: str
    value: Any = None
    record_id: str | None = None
    reason: str = ""


class CandidateGraph:
    """Production service over the checksummed JAA-02 SQLite schema."""

    def __init__(
        self,
        path: str | Path,
        *,
        secret_patterns: Sequence[str] = DEFAULT_SECRET_PATTERNS,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        apply_jaa_02_migrations(self.path)
        self._secret_patterns = tuple(re.compile(pattern) for pattern in secret_patterns)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _provenance(
        self,
        connection: sqlite3.Connection,
        *,
        source_identity: str,
        source_kind: str,
        source_locator: str | None,
        source_content: Any,
        observed_at: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        identity = source_identity.strip()
        if not identity:
            raise ValueError("source_identity is required; operator defaults are forbidden")
        source_hash = _hash(source_content)
        provenance_id = _identifier("prov", identity, source_hash)
        connection.execute(
            """INSERT OR IGNORE INTO candidate_provenance(
                 provenance_id,source_identity,source_kind,source_hash,source_locator,
                 observed_at,metadata_json) VALUES(?,?,?,?,?,?,?)""",
            (
                provenance_id, identity, source_kind, source_hash, source_locator,
                observed_at or datetime.now(timezone.utc).isoformat(), _canonical(metadata or {}),
            ),
        )
        return provenance_id

    def import_yaml(
        self,
        profile_path: str | Path,
        evidence_path: str | Path | None = None,
        *,
        source_identity: str | None = None,
    ) -> dict[str, int]:
        """Import the legacy profile and ledger while preserving each file identity."""
        paths = [Path(profile_path)]
        if evidence_path is not None and Path(evidence_path) != paths[0]:
            paths.append(Path(evidence_path))
        counts = {"records": 0, "evidence": 0, "claims": 0}
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for path in paths:
                raw_text = path.read_text(encoding="utf-8")
                document = yaml.safe_load(raw_text) or {}
                if not isinstance(document, dict):
                    raise ValueError(f"{path}: YAML root must be a mapping")
                meta = dict(document.get("meta") or {})
                identity = source_identity or str(meta.get("source_identity") or path.resolve())
                provenance = self._provenance(
                    connection, source_identity=identity, source_kind="yaml",
                    source_locator=str(path), source_content=raw_text,
                    observed_at=str(meta.get("generated_at") or "") or None,
                    metadata={"profile_version": meta.get("version")},
                )
                counts["records"] += self._import_profile_records(connection, document, provenance)
                evidence_map = self._import_evidence(connection, document, provenance, identity)
                counts["evidence"] += len(evidence_map)
                counts["claims"] += self._import_track_claims(
                    connection, document, provenance, evidence_map
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return counts

    def add_record(
        self,
        record_id: str,
        *,
        kind: str,
        subject: str,
        value: Any,
        state: str,
        source_identity: str,
        version: int = 1,
        jurisdiction: str | None = None,
        contract_type: str | None = None,
        valid_from: str | None = None,
        valid_until: str | None = None,
    ) -> None:
        connection = self.connect()
        try:
            provenance = self._provenance(
                connection, source_identity=source_identity, source_kind="domain_input",
                source_locator=None, source_content={"record_id": record_id, "value": value},
            )
            connection.execute(
                """INSERT INTO candidate_records(
                     record_id,version,record_kind,subject,value_json,epistemic_state,
                     jurisdiction,contract_type,valid_from,valid_until,provenance_id)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (record_id, version, kind, subject, _canonical(value), _state(state),
                 jurisdiction, contract_type, valid_from, valid_until, provenance),
            )
            connection.commit()
        finally:
            connection.close()

    def add_evidence(
        self,
        evidence_id: str,
        *,
        statement: str,
        source_identity: str,
        state: str = "unverified",
        evidence_kind: str = "document",
        version: int = 1,
        negative: bool = False,
        valid_until: str | None = None,
    ) -> str:
        connection = self.connect()
        try:
            provenance = self._provenance(
                connection, source_identity=source_identity, source_kind="domain_input",
                source_locator=None, source_content=statement,
            )
            matched = self._secret_match(statement)
            approval = "quarantined" if matched else "pending"
            connection.execute(
                """INSERT INTO candidate_evidence(
                     evidence_id,version,evidence_kind,statement,source_identity,epistemic_state,
                     approval_state,negative,valid_until,content_hash,provenance_id)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (evidence_id, version, evidence_kind, statement, source_identity, _state(state),
                 approval, int(negative), valid_until, _hash(statement), provenance),
            )
            if matched:
                self._quarantine(connection, evidence_id, version, matched, _hash(statement), provenance)
            connection.commit()
            return approval
        finally:
            connection.close()

    def add_claim(
        self,
        claim_id: str,
        *,
        statement: str,
        claim_type: str,
        state: str,
        source_identity: str,
        version: int = 1,
        valid_until: str | None = None,
    ) -> None:
        connection = self.connect()
        try:
            provenance = self._provenance(
                connection, source_identity=source_identity, source_kind="domain_input",
                source_locator=None, source_content=statement,
            )
            connection.execute(
                """INSERT INTO candidate_claims(
                     claim_id,version,claim_type,statement,epistemic_state,valid_until,provenance_id)
                     VALUES(?,?,?,?,?,?,?)""",
                (claim_id, version, claim_type, statement, _state(state), valid_until, provenance),
            )
            connection.commit()
        finally:
            connection.close()

    def add_artefact(
        self,
        artefact_id: str,
        *,
        artefact_type: str,
        source_identity: str,
        content_hash: str,
        version: int = 1,
    ) -> None:
        """Register content-addressed artefact metadata without approving a claim."""
        if (
            len(content_hash) != 64
            or any(character not in "0123456789abcdef" for character in content_hash)
        ):
            raise ValueError("artefact content_hash must be a lowercase SHA-256 digest")
        if not artefact_type.strip():
            raise ValueError("artefact_type is required")
        connection = self.connect()
        try:
            provenance = self._provenance(
                connection,
                source_identity=source_identity,
                source_kind="artefact",
                source_locator=None,
                source_content={"artefact_id": artefact_id, "content_hash": content_hash},
            )
            connection.execute(
                """INSERT INTO candidate_artefacts(
                     artefact_id,version,artefact_type,source_identity,
                     content_hash,provenance_id)
                   VALUES(?,?,?,?,?,?)""",
                (
                    artefact_id, version, artefact_type, source_identity,
                    content_hash, provenance,
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def link_claim_evidence(
        self,
        claim_id: str,
        evidence_id: str,
        *,
        source_identity: str,
        edge_type: str = "supports",
        claim_version: int = 1,
        evidence_version: int = 1,
    ) -> str:
        connection = self.connect()
        try:
            provenance = self._provenance(
                connection, source_identity=source_identity, source_kind="domain_input",
                source_locator=None,
                source_content={"claim": claim_id, "evidence": evidence_id, "type": edge_type},
            )
            edge_id = _identifier(
                "edge", claim_id, claim_version, evidence_id, evidence_version, edge_type
            )
            connection.execute(
                """INSERT INTO candidate_claim_edges(
                     edge_id,claim_id,claim_version,edge_type,evidence_id,
                     evidence_version,provenance_id) VALUES(?,?,?,?,?,?,?)""",
                (edge_id, claim_id, claim_version, edge_type, evidence_id,
                 evidence_version, provenance),
            )
            connection.commit()
            return edge_id
        finally:
            connection.close()

    def link_claim_artefact(
        self,
        claim_id: str,
        artefact_id: str,
        *,
        source_identity: str,
        edge_type: str = "documented_in",
        claim_version: int = 1,
        artefact_version: int = 1,
    ) -> str:
        """Bind an exact artefact to a claim; this never approves either."""
        if edge_type not in {"derived_from", "demonstrated_by", "documented_in"}:
            raise ValueError("unsupported claim-to-artefact edge type")
        connection = self.connect()
        try:
            provenance = self._provenance(
                connection,
                source_identity=source_identity,
                source_kind="domain_input",
                source_locator=None,
                source_content={
                    "claim": claim_id,
                    "artefact": artefact_id,
                    "type": edge_type,
                },
            )
            edge_id = _identifier(
                "edge", claim_id, claim_version,
                artefact_id, artefact_version, edge_type,
            )
            connection.execute(
                """INSERT INTO candidate_claim_edges(
                     edge_id,claim_id,claim_version,edge_type,artefact_id,
                     artefact_version,provenance_id) VALUES(?,?,?,?,?,?,?)""",
                (
                    edge_id, claim_id, claim_version, edge_type,
                    artefact_id, artefact_version, provenance,
                ),
            )
            connection.commit()
            return edge_id
        finally:
            connection.close()

    def verify_record(
        self,
        record_id: str,
        version: int,
        *,
        decision: str,
        verifier_kind: str,
        policy_id: str,
        policy_version: str,
        policy_hash: str,
        reason: str,
        source_identity: str,
    ) -> str:
        if decision not in {"approved", "rejected", "abstained"}:
            raise ValueError("invalid verification decision")
        connection = self.connect()
        try:
            if connection.execute(
                "SELECT 1 FROM candidate_records WHERE record_id=? AND version=?",
                (record_id, version),
            ).fetchone() is None:
                raise KeyError((record_id, version))
            provenance = self._provenance(
                connection, source_identity=source_identity, source_kind="verification",
                source_locator=None, source_content={"policy_hash": policy_hash, "reason": reason},
            )
            decision_id = _identifier("decision", record_id, version, policy_hash, decision)
            connection.execute(
                """INSERT OR IGNORE INTO candidate_verification_decisions(
                     decision_id,target_kind,target_id,target_version,decision,verifier_kind,
                     policy_id,policy_version,policy_hash,reason,provenance_id)
                     VALUES(?,'record',?,?,?,?,?,?,?,?,?)""",
                (decision_id, record_id, version, decision, verifier_kind, policy_id,
                 policy_version, policy_hash, reason, provenance),
            )
            connection.commit()
            return decision_id
        finally:
            connection.close()

    def _import_profile_records(
        self, connection: sqlite3.Connection, document: Mapping[str, Any], provenance: str
    ) -> int:
        profile = dict(document.get("candidate_profile") or {})
        sections = {
            "constraint": profile.get("constraints", document.get("constraints", {})),
            "preference": profile.get("preferences", document.get("preferences", {})),
            "fact": profile.get("capabilities", document.get("capabilities", {})),
            "work_right": profile.get("work_rights", document.get("work_rights", {})),
        }
        count = 0
        for kind, values in sections.items():
            if not isinstance(values, Mapping):
                continue
            for subject, raw in values.items():
                details = dict(raw) if isinstance(raw, Mapping) else {"value": raw}
                value = details.get("value", raw)
                record_id = str(details.get("id") or _identifier("record", provenance, kind, subject))
                version = int(details.get("version") or 1)
                connection.execute(
                    """INSERT OR IGNORE INTO candidate_records(
                         record_id,version,record_kind,subject,value_json,epistemic_state,
                         jurisdiction,contract_type,valid_from,valid_until,supersedes_version,
                         provenance_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        record_id, version, kind, str(subject), _canonical(value),
                        _state(details.get("state") or details.get("status")),
                        details.get("jurisdiction"), details.get("contract_type"),
                        details.get("valid_from"), details.get("valid_until"),
                        details.get("supersedes_version"), provenance,
                    ),
                )
                count += connection.execute("SELECT changes()").fetchone()[0]
        return count

    def _import_evidence(
        self,
        connection: sqlite3.Connection,
        document: Mapping[str, Any],
        provenance: str,
        document_identity: str,
    ) -> dict[str, tuple[str, int]]:
        imported: dict[str, tuple[str, int]] = {}
        for index, raw in enumerate(document.get("evidence") or []):
            if not isinstance(raw, Mapping):
                continue
            statement = str(raw.get("claim") or raw.get("statement") or "").strip()
            if not statement:
                continue
            evidence_id = str(raw.get("id") or _identifier("evidence", provenance, index, statement))
            version = int(raw.get("version") or 1)
            source = str(raw.get("source_identity") or raw.get("source") or document_identity)
            state = _state(raw.get("state") or raw.get("status"))
            negative = bool(raw.get("negative")) or str(raw.get("kind", "")).casefold() == "negative"
            approval = "pending"
            matched = self._secret_match(_canonical(raw))
            if matched:
                approval = "quarantined"
            connection.execute(
                """INSERT OR IGNORE INTO candidate_evidence(
                     evidence_id,version,evidence_kind,statement,source_identity,epistemic_state,
                     approval_state,negative,confidence,valid_until,content_hash,provenance_id)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    evidence_id, version, str(raw.get("kind") or "legacy"), statement,
                    source, state, approval, int(negative), raw.get("confidence"),
                    raw.get("valid_until"), _hash(raw), provenance,
                ),
            )
            if matched:
                self._quarantine(connection, evidence_id, version, matched, _hash(raw), provenance)
            imported[str(raw.get("id") or evidence_id)] = (evidence_id, version)
        return imported

    def _import_track_claims(
        self,
        connection: sqlite3.Connection,
        document: Mapping[str, Any],
        provenance: str,
        evidence: Mapping[str, tuple[str, int]],
    ) -> int:
        tracks = document.get("career_tracks") or (document.get("candidate_profile") or {}).get("tracks") or {}
        count = 0
        if not isinstance(tracks, Mapping):
            return count
        for name, raw in tracks.items():
            if not isinstance(raw, Mapping) or not str(raw.get("rationale") or "").strip():
                continue
            claim_id = str(raw.get("claim_id") or _identifier("claim", provenance, name))
            connection.execute(
                """INSERT OR IGNORE INTO candidate_claims(
                     claim_id,version,claim_type,statement,epistemic_state,approval_state,provenance_id)
                     VALUES(?,1,'career_track',?,'inference','pending',?)""",
                (claim_id, str(raw["rationale"]), provenance),
            )
            count += connection.execute("SELECT changes()").fetchone()[0]
            for ref in raw.get("evidence") or []:
                if str(ref) not in evidence:
                    continue
                evidence_id, version = evidence[str(ref)]
                edge_id = _identifier("edge", claim_id, 1, evidence_id, version)
                connection.execute(
                    """INSERT OR IGNORE INTO candidate_claim_edges(
                         edge_id,claim_id,claim_version,edge_type,evidence_id,
                         evidence_version,provenance_id) VALUES(?,?,1,'supports',?,?,?)""",
                    (edge_id, claim_id, evidence_id, version, provenance),
                )
        return count

    def discover_corpus(
        self,
        roots: Iterable[str | Path],
        *,
        source_identity: str,
        extensions: Sequence[str] = (".md", ".txt", ".py", ".json", ".yaml", ".yml"),
    ) -> dict[str, int]:
        """Register file evidence candidates as pending; discovery never approves."""
        discovered = quarantined = 0
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            for root_value in roots:
                root = Path(root_value).resolve()
                files = [root] if root.is_file() else sorted(path for path in root.rglob("*") if path.is_file())
                for path in files:
                    if path.suffix.casefold() not in {suffix.casefold() for suffix in extensions}:
                        continue
                    content = path.read_text(encoding="utf-8", errors="replace")
                    file_identity = f"{source_identity}:{path.relative_to(root) if root.is_dir() else path.name}"
                    provenance = self._provenance(
                        connection, source_identity=file_identity, source_kind="corpus",
                        source_locator=str(path), source_content=content,
                    )
                    evidence_id = _identifier("candidate", file_identity, _hash(content))
                    matched = self._secret_match(content)
                    approval = "quarantined" if matched else "pending"
                    connection.execute(
                        """INSERT OR IGNORE INTO candidate_evidence(
                             evidence_id,version,evidence_kind,statement,source_identity,
                             epistemic_state,approval_state,content_hash,provenance_id,discovered_by)
                             VALUES(?,1,'corpus_candidate',?,?,'unverified',?,?,?,'corpus-v1')""",
                        (evidence_id, f"Evidence candidate from {path.name}", file_identity,
                         approval, _hash(content), provenance),
                    )
                    changed = connection.execute("SELECT changes()").fetchone()[0]
                    discovered += changed
                    if matched:
                        self._quarantine(connection, evidence_id, 1, matched, _hash(content), provenance)
                        quarantined += changed
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return {"discovered": discovered, "quarantined": quarantined, "approved": 0}

    def verify_evidence(
        self,
        evidence_id: str,
        version: int,
        *,
        decision: str,
        verifier_kind: str,
        policy_id: str,
        policy_version: str,
        policy_hash: str,
        reason: str,
        source_identity: str,
    ) -> str:
        if decision not in {"approved", "rejected", "abstained"}:
            raise ValueError("invalid verification decision")
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            evidence = connection.execute(
                "SELECT * FROM candidate_evidence WHERE evidence_id=? AND version=?",
                (evidence_id, version),
            ).fetchone()
            if evidence is None:
                raise KeyError((evidence_id, version))
            if evidence["approval_state"] == "quarantined":
                raise ValueError("quarantined evidence cannot be approved")
            if decision == "approved" and evidence["epistemic_state"] not in RELEASE_STATES:
                raise ValueError("inferred, unknown, expired, disputed or unverified evidence cannot be approved")
            provenance = self._provenance(
                connection, source_identity=source_identity, source_kind="verification",
                source_locator=None, source_content={"policy_hash": policy_hash, "reason": reason},
            )
            decision_id = _identifier("decision", evidence_id, version, policy_hash, decision)
            connection.execute(
                """INSERT OR IGNORE INTO candidate_verification_decisions(
                     decision_id,target_kind,target_id,target_version,decision,verifier_kind,
                     policy_id,policy_version,policy_hash,reason,provenance_id)
                     VALUES(?,'evidence',?,?,?,?,?,?,?,?,?)""",
                (decision_id, evidence_id, version, decision, verifier_kind, policy_id,
                 policy_version, policy_hash, reason, provenance),
            )
            if decision != "abstained":
                connection.execute(
                    "UPDATE candidate_evidence SET approval_state=? WHERE evidence_id=? AND version=?",
                    (decision, evidence_id, version),
                )
            connection.commit()
            return decision_id
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def approve_claim(self, claim_id: str, version: int = 1) -> None:
        """Approve only a current fact claim backed by current approved evidence."""
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            claim = connection.execute(
                "SELECT * FROM candidate_claims WHERE claim_id=? AND version=?", (claim_id, version)
            ).fetchone()
            if claim is None:
                raise KeyError((claim_id, version))
            if claim["epistemic_state"] not in RELEASE_STATES:
                raise ValueError("non-factual claim cannot be approved")
            connection.execute(
                "UPDATE candidate_claims SET approval_state='approved' WHERE claim_id=? AND version=?",
                (claim_id, version),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def release_claims(self, *, as_of: date | None = None) -> list[dict[str, Any]]:
        today = (as_of or date.today()).isoformat()
        connection = self.connect()
        try:
            rows = connection.execute(
                """SELECT DISTINCT claim.* FROM candidate_claims claim
                   JOIN candidate_claim_edges edge ON edge.claim_id=claim.claim_id
                     AND edge.claim_version=claim.version
                   JOIN candidate_evidence evidence ON evidence.evidence_id=edge.evidence_id
                     AND evidence.version=edge.evidence_version
                   WHERE claim.approval_state='approved'
                     AND claim.epistemic_state IN ('fact','evidence')
                     AND (claim.valid_until IS NULL OR claim.valid_until>=?)
                     AND edge.edge_type IN ('supports','demonstrated_by')
                     AND evidence.approval_state='approved'
                     AND evidence.epistemic_state IN ('fact','evidence')
                     AND (evidence.valid_until IS NULL OR evidence.valid_until>=?)
                   ORDER BY claim.claim_id,claim.version""",
                (today, today),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def worker_projection(self, *, as_of: date | None = None) -> dict[str, Any]:
        """Return model-agnostic, career-only approved claims with no raw private text."""
        claims = self.release_claims(as_of=as_of)
        safe = []
        for claim in claims:
            if claim["claim_type"] in {"private_conversation", "secret", "unrelated_private"}:
                continue
            if self._secret_match(claim["statement"]):
                continue
            safe.append({
                "id": claim["claim_id"], "version": claim["version"],
                "type": claim["claim_type"], "statement": claim["statement"],
            })
        return {"schema": "candidate-worker-projection/v1", "claims": safe}

    def resolve_work_right(
        self, jurisdiction: str, contract_type: str, *, as_of: date | None = None
    ) -> WorkRightResolution:
        """Resolve the most-specific verified applicable rule or explicitly abstain."""
        today = (as_of or date.today()).isoformat()
        connection = self.connect()
        try:
            row = connection.execute(
                """SELECT record.* FROM candidate_records record
                   JOIN candidate_verification_decisions decision
                     ON decision.target_kind='record' AND decision.target_id=record.record_id
                    AND decision.target_version=record.version AND decision.decision='approved'
                   WHERE record.record_kind='work_right'
                     AND record.epistemic_state='fact'
                     AND record.jurisdiction IN (?, '*')
                     AND record.contract_type IN (?, '*')
                     AND (record.valid_from IS NULL OR record.valid_from<=?)
                     AND (record.valid_until IS NULL OR record.valid_until>=?)
                   ORDER BY (record.jurisdiction=?) DESC,(record.contract_type=?) DESC,
                            record.version DESC LIMIT 1""",
                (jurisdiction, contract_type, today, today, jurisdiction, contract_type),
            ).fetchone()
            if row is None:
                return WorkRightResolution(
                    "abstain", jurisdiction, contract_type,
                    reason="no verified applicable jurisdiction and contract rule",
                )
            return WorkRightResolution(
                "resolved", jurisdiction, contract_type, json.loads(row["value_json"]),
                row["record_id"], "verified applicable rule",
            )
        finally:
            connection.close()

    def _secret_match(self, text: str) -> str | None:
        for pattern in self._secret_patterns:
            if pattern.search(text):
                return pattern.pattern
        return None

    @staticmethod
    def _quarantine(
        connection: sqlite3.Connection,
        evidence_id: str,
        version: int,
        pattern: str,
        content_hash: str,
        provenance: str,
    ) -> None:
        connection.execute(
            """INSERT OR IGNORE INTO candidate_quarantine(
                 quarantine_id,target_kind,target_id,target_version,reason_code,
                 matched_pattern,content_hash,provenance_id) VALUES(?,'evidence',?,?,'secret_pattern',?,?,?)""",
            (_identifier("quarantine", evidence_id, version), evidence_id, version,
             pattern, content_hash, provenance),
        )
