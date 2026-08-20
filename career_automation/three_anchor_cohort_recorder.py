"""Pure, durable JAA-10 three-anchor cohort recording.

The recorder admits bytes that other, separately-authorised components have
already obtained.  It cannot acquire an observation or a time response.  It
uses no local clock as authority and never grants slice, submission, or live
execution authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping

from career_automation.external_time_attestation import (
    ExternalTimeAttestation,
    ExternalTimeStatus,
    verify_external_time_response,
)
from career_automation.hard_metrics_evaluation import (
    _domain_hash,
    _publish_canonical_receipt,
)
from career_automation.observation_route_manifest import (
    LEVER_LIST_ROUTE_CLASS,
    MINIMUM_DISTINCT_EMPLOYERS,
    MINIMUM_FULLY_VERIFIED_UNITS,
    REQUIRED_OBSERVATION_UNITS,
    ObservationRouteManifest,
)
from career_automation.public_access import policy_records_hash
from tracked_source_revision import source_content_revision, source_git_revision


COHORT_SCHEMA_VERSION = "jaa10.three-anchor-cohort.v1"
EVENT_SCHEMA_VERSION = "jaa10.three-anchor-event.v1"
FREEZE_SCHEMA_VERSION = "jaa10.three-anchor-freeze.v1"
ANCHOR_SCHEMA_VERSION = "jaa10.three-anchor-anchor.v1"
A2_TARGET_SCHEMA_VERSION = "jaa10.three-anchor-a2-target.v1"
REPLAY_SCHEMA_VERSION = "jaa10.three-anchor-replay.v1"
REPLAY_PAIR_SCHEMA_VERSION = "jaa10.three-anchor-replay-pair.v1"
READINESS_SCHEMA_VERSION = "jaa10.three-anchor-readiness.v1"
FROZEN_IDENTITY_SCHEMA_VERSION = "jaa10.three-anchor-frozen-identity.v1"
MINIMUM_AUTHENTICATED_SEPARATION_SECONDS = 86_400
ISSUER_CALLS_PER_COMPLETE_UNIT = 3
FAILED_DRILL_RESERVATION_COUNT = 2
FAILED_DRILL_LEDGER_SHA256 = (
    "e9994ae7fb081840c8e37ae8f81cc7c57c76109d0471bab771149b271ebcf761"
)
FAILED_DRILL_RECEIPT_SHA256 = (
    "535bee6625a19041624d25db23dd633e6032d2721bfbdd69bde07ff868063fc6"
)
FAILED_DRILL_ROBOTS_SHA256 = (
    "6aa3556bd611889c4480a143bb6186f9d0c5e919c6b4c9901f3a6a8141549a1b"
)
FAILED_DRILL_CONTENT_SHA256 = (
    "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
)
GENESIS_RECEIPT_SHA256 = "0" * 64
SQLITE_TIMEOUT_SECONDS = 10.0

EVENT_DOMAIN = b"jaa10-three-anchor-event-v1\0"
FREEZE_DOMAIN = b"jaa10-three-anchor-freeze-v1\0"
ANCHOR_DOMAINS = {
    "A1": b"jaa10-three-anchor-a1-v1\0",
    "A2": b"jaa10-three-anchor-a2-v1\0",
    "A3": b"jaa10-three-anchor-a3-v1\0",
}
A2_TARGET_DOMAIN = b"jaa10-three-anchor-a2-target-v1\0"
A2_TOKEN_DOMAIN = b"jaa10-three-anchor-a2-token-v1\0"
REPLAY_DOMAIN = b"jaa10-three-anchor-replay-v1\0"
REPLAY_PAIR_DOMAIN = b"jaa10-three-anchor-replay-pair-v1\0"
READINESS_DOMAIN = b"jaa10-three-anchor-readiness-v1\0"
SCHEMA_IDENTITY_DOMAIN = b"jaa10-three-anchor-schema-identity-v1\0"

_HEX_64 = re.compile(r"[0-9a-f]{64}")
_HEX_40 = re.compile(r"[0-9a-f]{40}")
_UNIT_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,127}")
_ARTIFACT_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,220}")

_OBSERVATION_REQUIRED_FIELDS = {
    "schema",
    "acquired_at",
    "route_class",
    "allowed_hosts",
    "request",
    "policy_sha256",
    "terms_attestation",
    "robots_binding",
    "reservation_binding",
    "pre_observation_anchor_sha256",
    "response",
    "certifies_slice",
    "submission_authority",
    "authenticated_external_time",
    "certifies_raw_header_order",
    "certifies_duplicate_header_preservation",
    "certifies_wire_transfer_cap",
    "body_size_enforced_post_transfer",
    "redirects_followed",
    "transport_impersonation",
    "stealth_headers",
    "proxy_used",
}
_OBSERVATION_LIMITATIONS = {
    "certifies_slice": False,
    "submission_authority": False,
    "authenticated_external_time": False,
    "certifies_raw_header_order": False,
    "certifies_duplicate_header_preservation": False,
    "certifies_wire_transfer_cap": False,
    "body_size_enforced_post_transfer": True,
    "redirects_followed": False,
    "transport_impersonation": False,
    "stealth_headers": False,
    "proxy_used": False,
}
_WITHHELD = {
    "live_execution": "not_proven_by_p2",
    "certifies_slice": False,
    "submission_authority": False,
    "authenticated_external_time": False,
    "external_action_capability": False,
    "real_applications_submitted": 0,
    "production_certification": "withheld",
}


class ThreeAnchorCohortError(RuntimeError):
    """Base error for the pure cohort recorder."""


class CohortJournalIntegrityError(ThreeAnchorCohortError):
    """The durable journal or a referenced artifact cannot be trusted."""


class CohortStateError(ThreeAnchorCohortError):
    """A requested transition violates the frozen cohort state machine."""


class FrozenIdentityDriftError(ThreeAnchorCohortError):
    """Current source, policy, or manifest bytes differ from the freeze."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: object, label: str, *, length: int = 64) -> str:
    pattern = _HEX_64 if length == 64 else _HEX_40
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{label} must be lowercase hexadecimal")
    return value


def _canonical_json_object(raw: bytes, label: str) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise CohortJournalIntegrityError(f"{label} must have one final newline")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        document = json.loads(
            raw,
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite value: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CohortJournalIntegrityError(f"{label} is not canonical JSON") from exc
    if not isinstance(document, dict) or raw != _canonical_json(document) + b"\n":
        raise CohortJournalIntegrityError(f"{label} is not canonical JSON")
    return document


def schema_identity_sha256() -> str:
    return _domain_hash(
        SCHEMA_IDENTITY_DOMAIN,
        {
            "schemas": [
                COHORT_SCHEMA_VERSION,
                EVENT_SCHEMA_VERSION,
                FREEZE_SCHEMA_VERSION,
                ANCHOR_SCHEMA_VERSION,
                A2_TARGET_SCHEMA_VERSION,
                REPLAY_SCHEMA_VERSION,
                REPLAY_PAIR_SCHEMA_VERSION,
                READINESS_SCHEMA_VERSION,
                FROZEN_IDENTITY_SCHEMA_VERSION,
            ],
            "required_units": REQUIRED_OBSERVATION_UNITS,
            "minimum_fully_verified": MINIMUM_FULLY_VERIFIED_UNITS,
            "minimum_distinct_employers": MINIMUM_DISTINCT_EMPLOYERS,
            "minimum_separation_seconds": MINIMUM_AUTHENTICATED_SEPARATION_SECONDS,
            "failed_drill_reservation_count": FAILED_DRILL_RESERVATION_COUNT,
            **_WITHHELD,
        },
    )


def _absolute_regular_path(value: str | Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"{label} must be an absolute non-symlink path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"{label} must be one regular file")
    return resolved


def _read_exact_file(
    path: Path,
    expected_sha256: str,
    label: str,
    *,
    expected_mode: int | None = None,
) -> bytes:
    _digest(expected_sha256, f"{label} hash")
    resolved = _absolute_regular_path(path, label)
    raw = resolved.read_bytes()
    if _sha256(raw) != expected_sha256:
        raise FrozenIdentityDriftError(f"{label} SHA-256 differs")
    if expected_mode is not None and stat.S_IMODE(resolved.stat().st_mode) != expected_mode:
        raise FrozenIdentityDriftError(f"{label} mode differs")
    return raw


@dataclass(frozen=True, slots=True)
class FrozenIdentity:
    repository_root: str
    source_git_revision: str
    source_tree: str
    source_content_revision: str
    acquirer_sha256: str
    external_time_sha256: str
    manifest_module_sha256: str
    route_manifest_path: str
    route_manifest_sha256: str
    policy_path: str
    policy_sha256: str
    policy_records_sha256: str
    recorder_sha256: str
    schema_identity_sha256: str

    def __post_init__(self) -> None:
        if not Path(self.repository_root).is_absolute():
            raise ValueError("repository root must be absolute")
        _digest(self.source_git_revision, "source Git revision", length=40)
        _digest(self.source_tree, "source tree", length=40)
        if re.fullmatch(r"sha256:[0-9a-f]{64}", self.source_content_revision) is None:
            raise ValueError("source-content revision is invalid")
        for value, label in (
            (self.acquirer_sha256, "acquirer hash"),
            (self.external_time_sha256, "external-time hash"),
            (self.manifest_module_sha256, "manifest-module hash"),
            (self.route_manifest_sha256, "route-manifest hash"),
            (self.policy_sha256, "policy hash"),
            (self.policy_records_sha256, "policy-records hash"),
            (self.recorder_sha256, "recorder hash"),
            (self.schema_identity_sha256, "schema identity"),
        ):
            _digest(value, label)
        for value, label in (
            (self.route_manifest_path, "route manifest path"),
            (self.policy_path, "policy path"),
        ):
            if not Path(value).is_absolute():
                raise ValueError(f"{label} must be absolute")

    def document(self) -> dict[str, str]:
        return {"schema_version": FROZEN_IDENTITY_SCHEMA_VERSION, **asdict(self)}

    @classmethod
    def from_document(cls, value: object) -> FrozenIdentity:
        if not isinstance(value, dict):
            raise CohortJournalIntegrityError("frozen identity is malformed")
        expected = {field.name for field in cls.__dataclass_fields__.values()}
        if set(value) != expected | {"schema_version"} or value.get(
            "schema_version"
        ) != FROZEN_IDENTITY_SCHEMA_VERSION:
            raise CohortJournalIntegrityError("frozen identity fields differ")
        return cls(**{key: value[key] for key in expected})


def _git(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        raise FrozenIdentityDriftError("Git identity cannot be reproduced")
    return completed.stdout


def _capture_actual_identity(expected: FrozenIdentity) -> FrozenIdentity:
    root = Path(expected.repository_root).resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise FrozenIdentityDriftError("repository root differs")
    revision = source_git_revision(root)
    tree = _git(root, "rev-parse", "--verify", f"{revision}^{{tree}}").strip().decode()
    if _git(root, "branch", "--show-current").strip() or _git(
        root, "status", "--porcelain=v1", "-z", "--untracked-files=all"
    ):
        raise FrozenIdentityDriftError("cohort source must be clean and detached")
    module_root = root / "career_automation"
    policy_path = _absolute_regular_path(expected.policy_path, "policy")
    if stat.S_IMODE(policy_path.stat().st_mode) != 0o600:
        raise FrozenIdentityDriftError("policy mode differs")
    policy_raw = policy_path.read_bytes()
    policy_document = _canonical_json_object(policy_raw, "policy")
    records = policy_document.get("hosts")
    if not isinstance(records, list):
        raise FrozenIdentityDriftError("policy records are malformed")
    return FrozenIdentity(
        repository_root=str(root),
        source_git_revision=revision,
        source_tree=tree,
        source_content_revision=source_content_revision(root),
        acquirer_sha256=_sha256(
            (module_root / "external_observation_acquisition.py").read_bytes()
        ),
        external_time_sha256=_sha256(
            (module_root / "external_time_attestation.py").read_bytes()
        ),
        manifest_module_sha256=_sha256(
            (module_root / "observation_route_manifest.py").read_bytes()
        ),
        route_manifest_path=str(
            _absolute_regular_path(expected.route_manifest_path, "route manifest")
        ),
        route_manifest_sha256=_sha256(
            Path(expected.route_manifest_path).read_bytes()
        ),
        policy_path=str(policy_path),
        policy_sha256=_sha256(policy_raw),
        policy_records_sha256=policy_records_hash(records),
        recorder_sha256=_sha256((module_root / Path(__file__).name).read_bytes()),
        schema_identity_sha256=schema_identity_sha256(),
    )


def capture_frozen_identity(
    repository_root: Path,
    *,
    route_manifest_path: Path,
    route_manifest_sha256: str,
    policy_path: Path,
    policy_sha256: str,
    policy_records_sha256: str,
) -> FrozenIdentity:
    """Capture the exact clean detached identity for a later cohort open."""
    seed = FrozenIdentity(
        repository_root=str(repository_root.resolve(strict=True)),
        source_git_revision="0" * 40,
        source_tree="0" * 40,
        source_content_revision="sha256:" + "0" * 64,
        acquirer_sha256="0" * 64,
        external_time_sha256="0" * 64,
        manifest_module_sha256="0" * 64,
        route_manifest_path=str(route_manifest_path.resolve(strict=True)),
        route_manifest_sha256=route_manifest_sha256,
        policy_path=str(policy_path.resolve(strict=True)),
        policy_sha256=policy_sha256,
        policy_records_sha256=policy_records_sha256,
        recorder_sha256="0" * 64,
        schema_identity_sha256=schema_identity_sha256(),
    )
    actual = _capture_actual_identity(seed)
    if (
        actual.route_manifest_sha256 != route_manifest_sha256
        or actual.policy_sha256 != policy_sha256
        or actual.policy_records_sha256 != policy_records_sha256
    ):
        raise FrozenIdentityDriftError("external frozen identity differs")
    return actual


@dataclass(frozen=True, slots=True)
class CohortPlan:
    failed_ledger_path: str
    failed_ledger_sha256: str
    failed_receipt_path: str
    failed_receipt_sha256: str
    failed_robots_path: str
    failed_robots_sha256: str
    failed_content_path: str
    failed_content_sha256: str
    reused_live_ledger_path: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.failed_ledger_sha256, "failed ledger hash"),
            (self.failed_receipt_sha256, "failed receipt hash"),
            (self.failed_robots_sha256, "failed robots hash"),
            (self.failed_content_sha256, "failed content hash"),
        ):
            _digest(value, label)
        for value in (
            self.failed_ledger_path,
            self.failed_receipt_path,
            self.failed_robots_path,
            self.failed_content_path,
            self.reused_live_ledger_path,
        ):
            if not Path(value).is_absolute():
                raise ValueError("cohort plan paths must be absolute")
        if Path(self.failed_ledger_path).resolve() != Path(
            self.reused_live_ledger_path
        ).resolve():
            raise ValueError("the failed ledger must be the single reused live ledger")


@dataclass(frozen=True, slots=True)
class P2Receipt:
    receipt_sha256: str
    document: Mapping[str, Any]

    def __post_init__(self) -> None:
        _digest(self.receipt_sha256, "P2 receipt hash")
        object.__setattr__(self, "document", MappingProxyType(dict(self.document)))

    def to_bytes(self) -> bytes:
        return _canonical_json(dict(self.document)) + b"\n"


@dataclass(frozen=True, slots=True)
class CohortFreezeReceipt(P2Receipt):
    pass


@dataclass(frozen=True, slots=True)
class ReplayReceipt(P2Receipt):
    pass


@dataclass(frozen=True, slots=True)
class ClosureReport(P2Receipt):
    @property
    def ready(self) -> bool:
        return bool(self.document.get("ready_for_later_live_metric_evaluation"))


def _journal_path(value: str | Path, *, must_exist: bool) -> Path:
    raw = os.fspath(value)
    if not isinstance(raw, str) or raw.startswith("file:") or raw == ":memory:" or "\0" in raw:
        raise ValueError("journal requires a plain filesystem path")
    supplied = Path(raw)
    if supplied.is_symlink():
        raise CohortJournalIntegrityError("journal path cannot be a symlink")
    path = supplied.resolve(strict=False)
    if must_exist:
        if not path.is_file() or path.is_symlink():
            raise CohortJournalIntegrityError("journal is missing or replaced")
    elif path.exists() or path.is_symlink():
        raise FileExistsError("journal path must be absent")
    return path


def _artifact_directory(journal_path: Path) -> Path:
    return journal_path.with_name(journal_path.name + ".artifacts")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _artifact_reference(name: str, raw: bytes) -> dict[str, object]:
    return {"artifact_name": name, "sha256": _sha256(raw), "size": len(raw)}


def _publish_raw_artifact(directory: Path, label: str, raw: bytes) -> dict[str, object]:
    digest = _sha256(raw)
    name = f"{label}-{digest}.bin"
    if _ARTIFACT_NAME.fullmatch(name) is None:
        raise CohortJournalIntegrityError("artifact name is unsafe")
    destination = directory / name
    temporary = directory / f".{name}.tmp-{os.getpid()}-{_sha256(os.urandom(32))}"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise CohortJournalIntegrityError("artifact staging target is not regular")
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise CohortJournalIntegrityError("artifact write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
        os.close(descriptor)
        descriptor = None
        os.link(temporary, destination, follow_symlinks=False)
        os.unlink(temporary)
        _fsync_directory(directory)
    except (FileExistsError, OSError) as exc:
        raise CohortJournalIntegrityError("artifact publication must be exclusive") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    metadata = destination.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o444
        or destination.read_bytes() != raw
    ):
        raise CohortJournalIntegrityError("published artifact differs")
    return _artifact_reference(name, raw)


def _publish_json_artifact(
    directory: Path,
    label: str,
    document: Mapping[str, object],
) -> dict[str, object]:
    raw = _canonical_json(dict(document)) + b"\n"
    name = f"{label}-{_sha256(raw)}.json"
    if _ARTIFACT_NAME.fullmatch(name) is None:
        raise CohortJournalIntegrityError("JSON artifact name is unsafe")
    try:
        published_sha256 = _publish_canonical_receipt(
            dict(document),
            directory / name,
        )
    except Exception as exc:
        raise CohortJournalIntegrityError(
            "canonical JSON artifact publication failed"
        ) from exc
    if published_sha256 != _sha256(raw):
        raise CohortJournalIntegrityError("canonical JSON artifact hash differs")
    _fsync_directory(directory)
    return _artifact_reference(name, raw)


def _walk_artifact_references(value: object) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    if isinstance(value, dict):
        if set(value) == {"artifact_name", "sha256", "size"}:
            found.append(value)
        else:
            for child in value.values():
                found.extend(_walk_artifact_references(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_walk_artifact_references(child))
    return found


def _event_hash(document: Mapping[str, Any]) -> str:
    return _domain_hash(EVENT_DOMAIN, dict(document))


def _event_document(
    *,
    cohort_id: str,
    event_type: str,
    sequence: int,
    previous_receipt_sha256: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "cohort_id": cohort_id,
        "event_type": event_type,
        "sequence": sequence,
        "previous_receipt_sha256": previous_receipt_sha256,
        "payload": dict(payload),
    }


class ThreeAnchorCohortRecorder:
    """Append-only, restart-recoverable, pure cohort state machine."""

    def __init__(
        self,
        journal_path: Path,
        *,
        cohort_id: str,
        frozen_identity: FrozenIdentity,
    ) -> None:
        self._journal_path = journal_path
        self._artifact_dir = _artifact_directory(journal_path)
        self.cohort_id = cohort_id
        self.frozen_identity = frozen_identity

    @classmethod
    def open(
        cls,
        journal_path: str | Path,
        *,
        cohort_id: str,
        frozen_identity: FrozenIdentity,
    ) -> ThreeAnchorCohortRecorder:
        if not isinstance(cohort_id, str) or _UNIT_ID.fullmatch(cohort_id) is None:
            raise ValueError("cohort_id must be a bounded lowercase identifier")
        if not isinstance(frozen_identity, FrozenIdentity):
            raise TypeError("cohort open requires a typed frozen identity")
        cls._assert_identity(frozen_identity)
        path = _journal_path(journal_path, must_exist=False)
        if not path.parent.is_dir() or path.parent.is_symlink():
            raise ValueError("journal parent must be one real existing directory")
        artifact_dir = _artifact_directory(path)
        artifact_dir.mkdir(mode=0o700, exist_ok=False)
        os.chmod(artifact_dir, 0o700)
        _fsync_directory(path.parent)
        connection = cls._new_connection(path)
        try:
            connection.executescript(
                """
                CREATE TABLE cohort_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version TEXT NOT NULL,
                    cohort_id TEXT NOT NULL,
                    frozen_identity_json TEXT NOT NULL,
                    frozen_identity_sha256 TEXT NOT NULL,
                    artifact_directory TEXT NOT NULL
                );
                CREATE TABLE cohort_event (
                    sequence INTEGER PRIMARY KEY CHECK (sequence >= 1),
                    event_type TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL UNIQUE,
                    previous_receipt_sha256 TEXT NOT NULL,
                    content_json TEXT NOT NULL
                );
                CREATE TRIGGER cohort_metadata_no_update BEFORE UPDATE ON cohort_metadata
                    BEGIN SELECT RAISE(ABORT, 'cohort metadata is append-only'); END;
                CREATE TRIGGER cohort_metadata_no_delete BEFORE DELETE ON cohort_metadata
                    BEGIN SELECT RAISE(ABORT, 'cohort metadata is append-only'); END;
                CREATE TRIGGER cohort_event_no_update BEFORE UPDATE ON cohort_event
                    BEGIN SELECT RAISE(ABORT, 'cohort events are append-only'); END;
                CREATE TRIGGER cohort_event_no_delete BEFORE DELETE ON cohort_event
                    BEGIN SELECT RAISE(ABORT, 'cohort events are append-only'); END;
                """
            )
            identity_document = frozen_identity.document()
            identity_json = _canonical_json(identity_document).decode()
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO cohort_metadata VALUES (1, ?, ?, ?, ?, ?)",
                (
                    COHORT_SCHEMA_VERSION,
                    cohort_id,
                    identity_json,
                    _domain_hash(SCHEMA_IDENTITY_DOMAIN, identity_document),
                    str(artifact_dir),
                ),
            )
            genesis = _event_document(
                cohort_id=cohort_id,
                event_type="cohort_open",
                sequence=1,
                previous_receipt_sha256=GENESIS_RECEIPT_SHA256,
                payload={"frozen_identity": identity_document, **_WITHHELD},
            )
            receipt_sha256 = _event_hash(genesis)
            connection.execute(
                "INSERT INTO cohort_event VALUES (?, ?, ?, ?, ?)",
                (1, "cohort_open", receipt_sha256, GENESIS_RECEIPT_SHA256, _canonical_json(genesis).decode()),
            )
            connection.commit()
            os.chmod(path, 0o600)
        except BaseException:
            connection.rollback()
            connection.close()
            for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
                candidate.unlink(missing_ok=True)
            try:
                artifact_dir.rmdir()
            except OSError:
                pass
            raise
        finally:
            connection.close()
        recorder = cls(path, cohort_id=cohort_id, frozen_identity=frozen_identity)
        recorder.verify()
        return recorder

    @classmethod
    def resume(
        cls,
        journal_path: str | Path,
        *,
        frozen_identity: FrozenIdentity,
    ) -> ThreeAnchorCohortRecorder:
        path = _journal_path(journal_path, must_exist=True)
        connection = cls._new_connection(path)
        try:
            rows = connection.execute(
                "SELECT cohort_id, frozen_identity_json FROM cohort_metadata"
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise CohortJournalIntegrityError("cohort metadata is unavailable") from exc
        finally:
            connection.close()
        if len(rows) != 1:
            raise CohortJournalIntegrityError("cohort metadata cardinality differs")
        cohort_id, identity_json = rows[0]
        try:
            recorded = FrozenIdentity.from_document(json.loads(identity_json))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise CohortJournalIntegrityError("recorded frozen identity differs") from exc
        if recorded != frozen_identity:
            raise FrozenIdentityDriftError("resume frozen identity differs")
        recorder = cls(path, cohort_id=cohort_id, frozen_identity=recorded)
        recorder.verify()
        summary = recorder._state(recorder._events())
        recorder._append_event(
            "restart",
            {
                "state_at_restart": summary["unit_states"],
                "restart_index": summary["restart_count"] + 1,
                **_WITHHELD,
            },
        )
        return recorder

    @staticmethod
    def _assert_identity(expected: FrozenIdentity) -> None:
        try:
            captured_before = _capture_actual_identity(expected)
            captured_after = _capture_actual_identity(expected)
        except FrozenIdentityDriftError:
            raise
        except Exception as exc:
            raise FrozenIdentityDriftError("frozen identity cannot be reproduced") from exc
        if captured_before != captured_after or captured_before != expected:
            raise FrozenIdentityDriftError("source, policy, manifest, or schema drifted")

    @staticmethod
    def _new_connection(path: Path, *, read_only: bool = False) -> sqlite3.Connection:
        target = f"file:{path}?mode=ro" if read_only else str(path)
        connection = sqlite3.connect(
            target,
            timeout=SQLITE_TIMEOUT_SECONDS,
            isolation_level=None,
            uri=read_only,
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _events(self, connection: sqlite3.Connection | None = None) -> tuple[dict[str, Any], ...]:
        owned = connection is None
        if owned:
            connection = self._new_connection(self._journal_path, read_only=True)
        assert connection is not None
        try:
            rows = connection.execute(
                "SELECT sequence, event_type, receipt_sha256, previous_receipt_sha256, content_json "
                "FROM cohort_event ORDER BY sequence"
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise CohortJournalIntegrityError("cohort event journal is unreadable") from exc
        finally:
            if owned:
                connection.close()
        if not rows:
            raise CohortJournalIntegrityError("cohort event journal is empty")
        previous = GENESIS_RECEIPT_SHA256
        events: list[dict[str, Any]] = []
        for expected_sequence, row in enumerate(rows, start=1):
            sequence, event_type, receipt_sha256, stored_previous, content_json = row
            try:
                document = json.loads(content_json)
            except (TypeError, json.JSONDecodeError) as exc:
                raise CohortJournalIntegrityError("cohort event JSON is invalid") from exc
            if (
                sequence != expected_sequence
                or stored_previous != previous
                or not isinstance(document, dict)
                or _canonical_json(document).decode() != content_json
                or document.get("schema_version") != EVENT_SCHEMA_VERSION
                or document.get("cohort_id") != self.cohort_id
                or document.get("event_type") != event_type
                or document.get("sequence") != sequence
                or document.get("previous_receipt_sha256") != stored_previous
                or not isinstance(document.get("payload"), dict)
                or _event_hash(document) != receipt_sha256
            ):
                raise CohortJournalIntegrityError("cohort event chain differs")
            document["receipt_sha256"] = receipt_sha256
            events.append(document)
            previous = receipt_sha256
        if events[0]["event_type"] != "cohort_open":
            raise CohortJournalIntegrityError("cohort genesis differs")
        return tuple(events)

    def _verify_metadata(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT singleton, schema_version, cohort_id, frozen_identity_json, "
            "frozen_identity_sha256, artifact_directory FROM cohort_metadata"
        ).fetchall()
        if len(rows) != 1:
            raise CohortJournalIntegrityError("cohort metadata cardinality differs")
        singleton, schema, cohort_id, identity_json, identity_sha, artifact_dir = rows[0]
        identity_document = self.frozen_identity.document()
        if (
            singleton != 1
            or schema != COHORT_SCHEMA_VERSION
            or cohort_id != self.cohort_id
            or identity_json != _canonical_json(identity_document).decode()
            or identity_sha != _domain_hash(SCHEMA_IDENTITY_DOMAIN, identity_document)
            or artifact_dir != str(self._artifact_dir)
        ):
            raise CohortJournalIntegrityError("cohort metadata differs")
        triggers = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            ).fetchall()
        }
        if triggers != {
            "cohort_metadata_no_update",
            "cohort_metadata_no_delete",
            "cohort_event_no_update",
            "cohort_event_no_delete",
        }:
            raise CohortJournalIntegrityError("append-only triggers differ")

    def _verify_artifacts(self, events: tuple[dict[str, Any], ...]) -> None:
        if self._artifact_dir.is_symlink() or not self._artifact_dir.is_dir():
            raise CohortJournalIntegrityError("artifact directory is missing or replaced")
        if stat.S_IMODE(self._artifact_dir.stat().st_mode) != 0o700:
            raise CohortJournalIntegrityError("artifact directory mode differs")
        references = [
            reference
            for event in events
            for reference in _walk_artifact_references(event["payload"])
        ]
        names: set[str] = set()
        for reference in references:
            name = reference.get("artifact_name")
            digest = reference.get("sha256")
            size = reference.get("size")
            if (
                not isinstance(name, str)
                or _ARTIFACT_NAME.fullmatch(name) is None
                or PurePosixPath(name).name != name
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
            ):
                raise CohortJournalIntegrityError("artifact reference is malformed")
            _digest(digest, "artifact hash")
            if name in names:
                raise CohortJournalIntegrityError("artifact is referenced more than once")
            names.add(name)
            path = self._artifact_dir / name
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise CohortJournalIntegrityError(
                    "journal-referenced artifact is absent; cohort is non-closeable"
                ) from exc
            if (
                path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o444
            ):
                raise CohortJournalIntegrityError("artifact type or mode differs")
            raw = path.read_bytes()
            if len(raw) != size or _sha256(raw) != digest:
                raise CohortJournalIntegrityError("artifact bytes differ")
        actual = {path.name for path in self._artifact_dir.iterdir()}
        if actual != names:
            raise CohortJournalIntegrityError("artifact inventory has an orphan or omission")

    def _verify_reused_ledger_prefix(self, events: tuple[dict[str, Any], ...]) -> None:
        freeze = next((event for event in events if event["event_type"] == "cohort_freeze"), None)
        if freeze is None:
            return
        payload = freeze["payload"]
        path = _absolute_regular_path(payload["reused_live_ledger_path"], "reused live ledger")
        prefix_ref = payload["failed_history"]["ledger"]
        prefix = (self._artifact_dir / prefix_ref["artifact_name"]).read_bytes()
        current = path.read_bytes()
        if not current.startswith(prefix):
            raise CohortJournalIntegrityError("reused live ledger lost failed-drill prefix")
        if len([line for line in current.splitlines() if line.strip()]) < FAILED_DRILL_RESERVATION_COUNT:
            raise CohortJournalIntegrityError("reused live ledger lost reservations")

    def verify(self) -> None:
        _journal_path(self._journal_path, must_exist=True)
        self._assert_identity(self.frozen_identity)
        connection = self._new_connection(self._journal_path, read_only=True)
        try:
            self._verify_metadata(connection)
            events = self._events(connection)
        except sqlite3.DatabaseError as exc:
            raise CohortJournalIntegrityError("cohort journal is corrupt") from exc
        finally:
            connection.close()
        self._verify_artifacts(events)
        state = self._state(events)
        self._verify_semantics(events, state)
        self._verify_reused_ledger_prefix(events)

    def _append_event(self, event_type: str, payload: Mapping[str, Any]) -> P2Receipt:
        connection = self._new_connection(self._journal_path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            events = self._events(connection)
            sequence = len(events) + 1
            previous = events[-1]["receipt_sha256"]
            document = _event_document(
                cohort_id=self.cohort_id,
                event_type=event_type,
                sequence=sequence,
                previous_receipt_sha256=previous,
                payload=payload,
            )
            receipt_sha256 = _event_hash(document)
            connection.execute(
                "INSERT INTO cohort_event VALUES (?, ?, ?, ?, ?)",
                (sequence, event_type, receipt_sha256, previous, _canonical_json(document).decode()),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        self.verify()
        return P2Receipt(receipt_sha256, {**document, "receipt_sha256": receipt_sha256})

    def _manifest(self) -> ObservationRouteManifest:
        return ObservationRouteManifest.load(
            Path(self.frozen_identity.route_manifest_path),
            expected_sha256=self.frozen_identity.route_manifest_sha256,
        )

    @staticmethod
    def _state(events: tuple[dict[str, Any], ...]) -> dict[str, Any]:
        frozen = False
        unit_states: dict[str, str] = {}
        unit_events: dict[str, dict[str, dict[str, Any]]] = {}
        candidate_attempts: list[str] = []
        restart_count = 0
        replay_pair_count = 0
        for event_index, event in enumerate(events):
            event_type = event["event_type"]
            payload = event["payload"]
            if event_type == "cohort_open":
                if event_index != 0:
                    raise CohortJournalIntegrityError("cohort open is duplicated")
                continue
            if any(payload.get(key) != value for key, value in _WITHHELD.items()):
                raise CohortJournalIntegrityError("event overstates a withheld claim")
            if event_type == "cohort_freeze":
                if frozen:
                    raise CohortJournalIntegrityError("cohort freeze is duplicated")
                frozen = True
                continue
            if event_type == "restart":
                restart_count += 1
                if (
                    payload.get("restart_index") != restart_count
                    or payload.get("state_at_restart") != unit_states
                ):
                    raise CohortJournalIntegrityError("restart counter differs")
                continue
            if event_type == "replay_pair":
                replay_pair_count += 1
                continue
            if not frozen:
                raise CohortJournalIntegrityError("evidence precedes cohort freeze")
            unit_id = payload.get("unit_id")
            if not isinstance(unit_id, str):
                raise CohortJournalIntegrityError("unit event lacks unit identity")
            current = unit_states.get(unit_id, "PENDING")
            expected: dict[str, tuple[str, str]] = {
                "candidate_miss": ("PENDING", "MISSED"),
                "obs1": ("PENDING", "OBS1"),
                "a1": ("OBS1", "A1"),
                "a2": ("A1", "A2"),
                "obs2": ("A2", "OBS2"),
                "a3": ("OBS2", "COMPLETE"),
            }
            if event_type not in expected or current != expected[event_type][0]:
                raise CohortJournalIntegrityError("unit transition order differs")
            unit_states[unit_id] = expected[event_type][1]
            unit_events.setdefault(unit_id, {})[event_type] = event
            if event_type in {"candidate_miss", "obs1"}:
                candidate_attempts.append(unit_id)
        return {
            "frozen": frozen,
            "unit_states": unit_states,
            "unit_events": unit_events,
            "candidate_attempts": candidate_attempts,
            "restart_count": restart_count,
            "replay_pair_count": replay_pair_count,
        }

    def _expected_a2_target(
        self,
        state: Mapping[str, Any],
        unit_id: str,
    ) -> bytes:
        obs1 = self._unit_event(state, unit_id, "obs1")["payload"]
        a1 = self._unit_event(state, unit_id, "a1")["payload"]
        target = {
            "schema_version": A2_TARGET_SCHEMA_VERSION,
            "cohort_id": self.cohort_id,
            "unit_id": unit_id,
            "anchor_role": "A2",
            "url": obs1["url"],
            "obs1_receipt_sha256": obs1["receipt_sha256"],
            "a1_evidence_sha256": a1["attestation"]["evidence_sha256"],
            "manifest_sha256": self.frozen_identity.route_manifest_sha256,
            "policy_sha256": self.frozen_identity.policy_sha256,
            **_WITHHELD,
        }
        target["target_sha256"] = _domain_hash(A2_TARGET_DOMAIN, target)
        return _canonical_json(target) + b"\n"

    def _verify_semantics(
        self,
        events: tuple[dict[str, Any], ...],
        state: Mapping[str, Any],
    ) -> None:
        manifest = self._manifest()
        freeze = next(
            (event for event in events if event["event_type"] == "cohort_freeze"),
            None,
        )
        if freeze is not None and (
            freeze["payload"].get("issuer_calls_per_complete_unit")
            != ISSUER_CALLS_PER_COMPLETE_UNIT
            or freeze["payload"].get("maximum_later_issuer_calls")
            != ISSUER_CALLS_PER_COMPLETE_UNIT * manifest.required_observation_units
            or freeze["payload"].get("p2_issuer_calls") != 0
        ):
            raise CohortJournalIntegrityError("issuer call budget differs")
        manifest_ids = [route.employer_or_board_id for route in manifest.candidates]
        attempts = state["candidate_attempts"]
        if attempts != manifest_ids[: len(attempts)] or len(attempts) > len(manifest_ids):
            raise CohortJournalIntegrityError("manifest candidate order differs")
        accepted = [
            unit_id
            for unit_id, unit_state in state["unit_states"].items()
            if unit_state != "MISSED"
        ]
        if len(accepted) > REQUIRED_OBSERVATION_UNITS:
            raise CohortJournalIntegrityError("cohort denominator was broadened")
        routes = {
            route.employer_or_board_id: route.url for route in manifest.candidates
        }
        seen_anchor_evidence: set[str] = set()
        seen_a2_tokens: set[str] = set()
        for unit_id, unit_events in state["unit_events"].items():
            if unit_id not in routes:
                raise CohortJournalIntegrityError("unit is absent from the manifest")
            if "candidate_miss" in unit_events:
                miss_payload = unit_events["candidate_miss"]["payload"]
                miss_document = _canonical_json_object(
                    self._artifact_bytes(miss_payload["miss_receipt"]),
                    "candidate miss receipt",
                )
                if (
                    miss_payload.get("url") != routes[unit_id]
                    or miss_document.get("url") != routes[unit_id]
                    or miss_document.get("accepted") is not False
                ):
                    raise CohortJournalIntegrityError("candidate miss semantics differ")
                continue

            obs1_payload = unit_events["obs1"]["payload"]
            obs1_bytes = self._artifact_bytes(obs1_payload["receipt"])
            obs1_document = self._validate_observation(
                obs1_bytes,
                expected_url=routes[unit_id],
                expected_anchor=None,
            )
            if (
                obs1_payload.get("url") != routes[unit_id]
                or obs1_payload.get("receipt_sha256") != _sha256(obs1_bytes)
                or obs1_payload.get("body_sha256")
                != obs1_document["response"]["body_sha256"]
                or obs1_payload.get("reservation_chain_head_sha256")
                != obs1_document["reservation_binding"]["chain_head_sha256"]
            ):
                raise CohortJournalIntegrityError("observation 1 derivation differs")
            if "a1" not in unit_events:
                continue
            a1_payload = unit_events["a1"]["payload"]
            a1, a1_binding = self._verify_anchor(
                unit_id=unit_id,
                role="A1",
                response_bytes=self._artifact_bytes(a1_payload["response"]),
                entropy=self._artifact_bytes(a1_payload["entropy"]),
                target_receipt_bytes=obs1_bytes,
                prior_anchor=None,
            )
            if (
                a1_payload.get("attestation") != a1.document()
                or a1_payload.get("anchor") != a1_binding
                or a1.evidence_sha256 in seen_anchor_evidence
            ):
                raise CohortJournalIntegrityError("A1 semantic replay differs")
            seen_anchor_evidence.add(a1.evidence_sha256)
            if "a2" not in unit_events:
                continue
            a2_payload = unit_events["a2"]["payload"]
            a2_target = self._artifact_bytes(a2_payload["target"])
            if a2_target != self._expected_a2_target(state, unit_id):
                raise CohortJournalIntegrityError("A2 target derivation differs")
            a2, a2_binding = self._verify_anchor(
                unit_id=unit_id,
                role="A2",
                response_bytes=self._artifact_bytes(a2_payload["response"]),
                entropy=self._artifact_bytes(a2_payload["entropy"]),
                target_receipt_bytes=a2_target,
                prior_anchor=a1,
            )
            assert a1.midpoint_unix is not None and a1.radius_seconds is not None
            assert a2.midpoint_unix is not None and a2.radius_seconds is not None
            conservative = (a2.midpoint_unix - a2.radius_seconds) - (
                a1.midpoint_unix + a1.radius_seconds
            )
            a2_token = _domain_hash(A2_TOKEN_DOMAIN, a2.document())
            if (
                conservative < MINIMUM_AUTHENTICATED_SEPARATION_SECONDS
                or a2_payload.get("attestation") != a2.document()
                or a2_payload.get("anchor") != a2_binding
                or a2_payload.get("conservative_separation_seconds") != conservative
                or a2_payload.get("separation_proved_before_obs2") is not True
                or a2_payload.get("a2_token_sha256") != a2_token
                or a2.evidence_sha256 in seen_anchor_evidence
                or a2_token in seen_a2_tokens
            ):
                raise CohortJournalIntegrityError("A2 semantic replay differs")
            seen_anchor_evidence.add(a2.evidence_sha256)
            seen_a2_tokens.add(a2_token)
            if "obs2" not in unit_events:
                continue
            obs2_payload = unit_events["obs2"]["payload"]
            obs2_bytes = self._artifact_bytes(obs2_payload["receipt"])
            obs2_document = self._validate_observation(
                obs2_bytes,
                expected_url=routes[unit_id],
                expected_anchor=a2_token,
            )
            if (
                obs2_payload.get("url") != routes[unit_id]
                or obs2_payload.get("receipt_sha256") != _sha256(obs2_bytes)
                or obs2_payload.get("body_sha256")
                != obs2_document["response"]["body_sha256"]
                or obs2_payload.get("reservation_chain_head_sha256")
                != obs2_document["reservation_binding"]["chain_head_sha256"]
                or obs2_payload.get("embedded_a2_token_sha256") != a2_token
                or obs2_payload.get("a2_gate_event_sequence")
                != unit_events["a2"]["sequence"]
                or _sha256(obs2_bytes) == _sha256(obs1_bytes)
                or obs2_document["reservation_binding"]["chain_head_sha256"]
                == obs1_document["reservation_binding"]["chain_head_sha256"]
            ):
                raise CohortJournalIntegrityError("observation 2 derivation differs")
            if "a3" not in unit_events:
                continue
            a3_payload = unit_events["a3"]["payload"]
            a3, a3_binding = self._verify_anchor(
                unit_id=unit_id,
                role="A3",
                response_bytes=self._artifact_bytes(a3_payload["response"]),
                entropy=self._artifact_bytes(a3_payload["entropy"]),
                target_receipt_bytes=obs2_bytes,
                prior_anchor=a2,
            )
            assert a3.midpoint_unix is not None and a3.radius_seconds is not None
            if (
                (a3.midpoint_unix - a3.radius_seconds)
                < (a2.midpoint_unix - a2.radius_seconds)
                or a3_payload.get("attestation") != a3.document()
                or a3_payload.get("anchor") != a3_binding
                or a3_payload.get("a3_seals_obs2_only") is not True
                or a3_payload.get("a3_establishes_separation") is not False
                or a3.evidence_sha256 in seen_anchor_evidence
            ):
                raise CohortJournalIntegrityError("A3 semantic replay differs")
            seen_anchor_evidence.add(a3.evidence_sha256)

        for index, event in enumerate(events):
            if event["event_type"] != "replay_pair":
                continue
            expected = self._replay_receipt_for_events(events[:index]).to_bytes()
            payload = event["payload"]
            first = self._artifact_bytes(payload["receipts"]["first"])
            second = self._artifact_bytes(payload["receipts"]["second"])
            if (
                first != expected
                or second != expected
                or first != second
                or payload.get("replay_receipt_sha256")
                != json.loads(expected)["receipt_sha256"]
                or payload.get("byte_identical") is not True
                or payload.get("invocation_count") != 2
                or payload.get("independent_processes_proven_by_p2") is not False
            ):
                raise CohortJournalIntegrityError("double-replay witness differs")

    def freeze_cohort(self, plan: CohortPlan) -> CohortFreezeReceipt:
        if not isinstance(plan, CohortPlan):
            raise TypeError("cohort freeze requires a typed plan")
        self.verify()
        state = self._state(self._events())
        if state["frozen"]:
            raise CohortStateError("cohort is already frozen")
        if (
            plan.failed_ledger_sha256 != FAILED_DRILL_LEDGER_SHA256
            or plan.failed_receipt_sha256 != FAILED_DRILL_RECEIPT_SHA256
            or plan.failed_robots_sha256 != FAILED_DRILL_ROBOTS_SHA256
            or plan.failed_content_sha256 != FAILED_DRILL_CONTENT_SHA256
        ):
            raise CohortStateError("failed-drill identity differs from authority")
        manifest = self._manifest()
        policy_raw = _read_exact_file(
            Path(self.frozen_identity.policy_path),
            self.frozen_identity.policy_sha256,
            "policy",
            expected_mode=0o600,
        )
        policy_document = _canonical_json_object(policy_raw, "policy")
        if policy_records_hash(policy_document.get("hosts")) != self.frozen_identity.policy_records_sha256:
            raise FrozenIdentityDriftError("policy records hash differs")
        raw_values = {
            "ledger": _read_exact_file(
                Path(plan.failed_ledger_path),
                plan.failed_ledger_sha256,
                "failed ledger",
                expected_mode=0o600,
            ),
            "receipt": _read_exact_file(
                Path(plan.failed_receipt_path),
                plan.failed_receipt_sha256,
                "failed receipt",
                expected_mode=0o444,
            ),
            "robots": _read_exact_file(
                Path(plan.failed_robots_path),
                plan.failed_robots_sha256,
                "failed robots",
                expected_mode=0o444,
            ),
            "content": _read_exact_file(
                Path(plan.failed_content_path),
                plan.failed_content_sha256,
                "failed content",
                expected_mode=0o444,
            ),
        }
        if len([line for line in raw_values["ledger"].splitlines() if line.strip()]) != FAILED_DRILL_RESERVATION_COUNT:
            raise CohortStateError("failed drill must disclose exactly two reservations")
        references = {
            label: _publish_raw_artifact(self._artifact_dir, f"failed-{label}", raw)
            for label, raw in raw_values.items()
        }
        payload = {
            "schema_version": FREEZE_SCHEMA_VERSION,
            "manifest_sha256": manifest.manifest_sha256,
            "manifest_order": [route.employer_or_board_id for route in manifest.candidates],
            "required_observation_units": manifest.required_observation_units,
            "minimum_fully_verified_units": manifest.minimum_fully_verified_units,
            "minimum_distinct_employers_or_boards": manifest.minimum_distinct_employers_or_boards,
            "maximum_candidate_attempts": manifest.maximum_candidate_attempts,
            "replacement_rule": manifest.replacement_rule,
            "issuer_calls_per_complete_unit": ISSUER_CALLS_PER_COMPLETE_UNIT,
            "maximum_later_issuer_calls": (
                ISSUER_CALLS_PER_COMPLETE_UNIT
                * manifest.required_observation_units
            ),
            "p2_issuer_calls": 0,
            "policy_sha256": self.frozen_identity.policy_sha256,
            "policy_records_sha256": self.frozen_identity.policy_records_sha256,
            "failed_history": references,
            "failed_history_non_cohort": True,
            "failed_history_reservations_counted": FAILED_DRILL_RESERVATION_COUNT,
            "reused_live_ledger_path": str(Path(plan.reused_live_ledger_path).resolve()),
            "immutable_and_irreversible": True,
            **_WITHHELD,
        }
        receipt = self._append_event("cohort_freeze", payload)
        _fsync_directory(self._artifact_dir)
        return CohortFreezeReceipt(receipt.receipt_sha256, receipt.document)

    def _next_candidate(self, state: Mapping[str, Any]) -> tuple[str, str]:
        manifest = self._manifest()
        attempts = state["candidate_attempts"]
        expected_prefix = [route.employer_or_board_id for route in manifest.candidates[: len(attempts)]]
        if attempts != expected_prefix or len(attempts) >= len(manifest.candidates):
            raise CohortStateError("manifest order is exhausted or differs")
        route = manifest.candidates[len(attempts)]
        return route.employer_or_board_id, route.url

    def record_candidate_miss(self, unit_id: str, miss_receipt_bytes: bytes) -> P2Receipt:
        self.verify()
        events = self._events()
        state = self._state(events)
        if not state["frozen"]:
            raise CohortStateError("cohort must be frozen before a miss")
        if len(
            [value for value in state["unit_states"].values() if value != "MISSED"]
        ) >= REQUIRED_OBSERVATION_UNITS:
            raise CohortStateError("the admitted denominator is already complete")
        expected_id, expected_url = self._next_candidate(state)
        if unit_id != expected_id:
            raise CohortStateError("candidate miss violates manifest order")
        document = _canonical_json_object(miss_receipt_bytes, "candidate miss receipt")
        if document.get("url") != expected_url or document.get("accepted") is not False:
            raise CohortStateError("candidate miss receipt differs")
        reference = _publish_raw_artifact(self._artifact_dir, f"miss-{unit_id}", miss_receipt_bytes)
        return self._append_event(
            "candidate_miss",
            {"unit_id": unit_id, "url": expected_url, "miss_receipt": reference, **_WITHHELD},
        )

    def _validate_observation(
        self,
        raw: bytes,
        *,
        expected_url: str,
        expected_anchor: str | None,
    ) -> dict[str, Any]:
        document = _canonical_json_object(raw, "observation receipt")
        if set(document) != _OBSERVATION_REQUIRED_FIELDS or document.get("schema") != "jaa10.external-observation-acquisition.v1":
            raise CohortStateError("observation receipt fields differ")
        if any(document.get(key) is not value for key, value in _OBSERVATION_LIMITATIONS.items()):
            raise CohortStateError("observation receipt overstates a limitation")
        if document.get("route_class") != LEVER_LIST_ROUTE_CLASS or document.get("policy_sha256") != self.frozen_identity.policy_sha256:
            raise CohortStateError("observation route or policy differs")
        request = document.get("request")
        response = document.get("response")
        if (
            not isinstance(request, dict)
            or set(request) != {"url", "method", "purpose", "effective_kwargs"}
            or request.get("url") != expected_url
            or request.get("method") != "GET"
            or request.get("purpose") != "list"
            or not isinstance(request.get("effective_kwargs"), dict)
            or not isinstance(response, dict)
            or set(response)
            != {
                "status",
                "url",
                "body_bytes",
                "body_sha256",
                "represented_headers_sha256",
                "represented_request_headers_sha256",
            }
            or response.get("url") != expected_url
            or response.get("status") != 200
            or not isinstance(response.get("body_bytes"), int)
            or isinstance(response.get("body_bytes"), bool)
            or response.get("body_bytes") < 2
            or _HEX_64.fullmatch(str(response.get("body_sha256"))) is None
            or _HEX_64.fullmatch(str(response.get("represented_headers_sha256")))
            is None
            or _HEX_64.fullmatch(
                str(response.get("represented_request_headers_sha256"))
            )
            is None
            or document.get("pre_observation_anchor_sha256") != expected_anchor
            or document.get("allowed_hosts") != ["api.lever.co"]
        ):
            raise CohortStateError("observation surface or anchor differs")
        binding = document.get("reservation_binding")
        if not isinstance(binding, dict) or set(binding) != {
            "schema",
            "robots",
            "content",
            "chain_head_sha256",
        }:
            raise CohortStateError("observation reservation binding is malformed")
        robots = binding.get("robots")
        content = binding.get("content")
        if (
            not isinstance(robots, dict)
            or not isinstance(content, dict)
            or _HEX_64.fullmatch(str(robots.get("event_sha256"))) is None
            or _HEX_64.fullmatch(str(content.get("event_sha256"))) is None
            or content.get("prev_event_sha256") != robots.get("event_sha256")
            or binding.get("chain_head_sha256") != content.get("event_sha256")
        ):
            raise CohortStateError("observation reservations differ")
        return document

    def admit_obs1_receipt(self, unit_id: str, receipt_bytes: bytes) -> P2Receipt:
        self.verify()
        state = self._state(self._events())
        if not state["frozen"]:
            raise CohortStateError("cohort must be frozen before observation 1")
        if len([value for value in state["unit_states"].values() if value != "MISSED"]) >= REQUIRED_OBSERVATION_UNITS:
            raise CohortStateError("the admitted denominator is already complete")
        expected_id, expected_url = self._next_candidate(state)
        if unit_id != expected_id:
            raise CohortStateError("observation 1 violates manifest order")
        document = self._validate_observation(receipt_bytes, expected_url=expected_url, expected_anchor=None)
        reference = _publish_raw_artifact(self._artifact_dir, f"obs1-{unit_id}", receipt_bytes)
        return self._append_event(
            "obs1",
            {
                "unit_id": unit_id,
                "url": expected_url,
                "route_class": LEVER_LIST_ROUTE_CLASS,
                "receipt": reference,
                "receipt_sha256": _sha256(receipt_bytes),
                "body_sha256": document["response"]["body_sha256"],
                "reservation_chain_head_sha256": document["reservation_binding"]["chain_head_sha256"],
                "interpretation_contract": "same_official_surface_canonical_list_json.v1",
                **_WITHHELD,
            },
        )

    def _unit_event(self, state: Mapping[str, Any], unit_id: str, event_type: str) -> dict[str, Any]:
        try:
            return state["unit_events"][unit_id][event_type]
        except KeyError as exc:
            raise CohortStateError(f"{unit_id} lacks required {event_type}") from exc

    def _artifact_bytes(self, reference: Mapping[str, Any]) -> bytes:
        return (self._artifact_dir / str(reference["artifact_name"])).read_bytes()

    def _verify_anchor(
        self,
        *,
        unit_id: str,
        role: str,
        response_bytes: bytes,
        entropy: bytes,
        target_receipt_bytes: bytes,
        prior_anchor: ExternalTimeAttestation | None,
    ) -> tuple[ExternalTimeAttestation, dict[str, Any]]:
        attestation = verify_external_time_response(
            response_bytes,
            target_receipt_bytes,
            entropy,
            prior_anchor=prior_anchor,
        )
        if not isinstance(attestation, ExternalTimeAttestation):
            raise CohortStateError("external-time verifier returned an untyped result")
        attestation.verify()
        if (
            attestation.status is not ExternalTimeStatus.VERIFIED
            or attestation.midpoint_unix is None
            or attestation.radius_seconds is None
            or attestation.receipt_sha256 != _sha256(target_receipt_bytes)
        ):
            raise CohortStateError(f"{role} is not a verified receipt-bound anchor")
        binding = {
            "schema_version": ANCHOR_SCHEMA_VERSION,
            "cohort_id": self.cohort_id,
            "unit_id": unit_id,
            "anchor_role": role,
            "target_receipt_sha256": _sha256(target_receipt_bytes),
            "attestation_evidence_sha256": attestation.evidence_sha256,
            "midpoint_unix": attestation.midpoint_unix,
            "radius_seconds": attestation.radius_seconds,
            **_WITHHELD,
        }
        binding["anchor_binding_sha256"] = _domain_hash(ANCHOR_DOMAINS[role], binding)
        return attestation, binding

    def admit_a1(
        self,
        unit_id: str,
        response_bytes: bytes,
        entropy: bytes,
        receipt_bytes: bytes,
    ) -> P2Receipt:
        self.verify()
        state = self._state(self._events())
        if state["unit_states"].get(unit_id) != "OBS1":
            raise CohortStateError("A1 requires observation 1")
        obs1 = self._unit_event(state, unit_id, "obs1")["payload"]
        if receipt_bytes != self._artifact_bytes(obs1["receipt"]):
            raise CohortStateError("A1 target differs from observation 1")
        attestation, binding = self._verify_anchor(
            unit_id=unit_id,
            role="A1",
            response_bytes=response_bytes,
            entropy=entropy,
            target_receipt_bytes=receipt_bytes,
            prior_anchor=None,
        )
        payload = {
            "unit_id": unit_id,
            "anchor": binding,
            "attestation": attestation.document(),
            "response": _publish_raw_artifact(self._artifact_dir, f"a1-response-{unit_id}", response_bytes),
            "entropy": _publish_raw_artifact(self._artifact_dir, f"a1-entropy-{unit_id}", entropy),
            **_WITHHELD,
        }
        return self._append_event("a1", payload)

    def a2_target_bytes(self, unit_id: str) -> bytes:
        self.verify()
        state = self._state(self._events())
        if state["unit_states"].get(unit_id) != "A1":
            raise CohortStateError("A2 target requires A1")
        return self._expected_a2_target(state, unit_id)

    def _attestation_from_event(self, event: Mapping[str, Any]) -> ExternalTimeAttestation:
        document = event["payload"]["attestation"]
        result = object.__new__(ExternalTimeAttestation)
        for field in ExternalTimeAttestation.__dataclass_fields__:
            value = document["status"] if field == "status" else document[field]
            if field == "status":
                value = ExternalTimeStatus(value)
            object.__setattr__(result, field, value)
        result.verify()
        return result

    def admit_a2(
        self,
        unit_id: str,
        response_bytes: bytes,
        entropy: bytes,
        receipt_bytes: bytes,
    ) -> P2Receipt:
        self.verify()
        state = self._state(self._events())
        if state["unit_states"].get(unit_id) != "A1":
            raise CohortStateError("A2 requires A1")
        expected_target = self.a2_target_bytes(unit_id)
        if receipt_bytes != expected_target:
            raise CohortStateError("A2 target is not cohort/unit/role bound")
        a1 = self._attestation_from_event(self._unit_event(state, unit_id, "a1"))
        attestation, binding = self._verify_anchor(
            unit_id=unit_id,
            role="A2",
            response_bytes=response_bytes,
            entropy=entropy,
            target_receipt_bytes=receipt_bytes,
            prior_anchor=a1,
        )
        assert attestation.midpoint_unix is not None and attestation.radius_seconds is not None
        assert a1.midpoint_unix is not None and a1.radius_seconds is not None
        conservative = (attestation.midpoint_unix - attestation.radius_seconds) - (
            a1.midpoint_unix + a1.radius_seconds
        )
        if conservative < MINIMUM_AUTHENTICATED_SEPARATION_SECONDS:
            raise CohortStateError("A2 does not prove the full conservative 24-hour interval")
        token = _domain_hash(A2_TOKEN_DOMAIN, attestation.document())
        payload = {
            "unit_id": unit_id,
            "anchor": binding,
            "attestation": attestation.document(),
            "a2_token_sha256": token,
            "conservative_separation_seconds": conservative,
            "separation_proved_before_obs2": True,
            "target": _publish_json_artifact(
                self._artifact_dir,
                f"a2-target-{unit_id}",
                _canonical_json_object(receipt_bytes, "A2 target"),
            ),
            "response": _publish_raw_artifact(self._artifact_dir, f"a2-response-{unit_id}", response_bytes),
            "entropy": _publish_raw_artifact(self._artifact_dir, f"a2-entropy-{unit_id}", entropy),
            **_WITHHELD,
        }
        return self._append_event("a2", payload)

    def a2_token_sha256(self, unit_id: str) -> str:
        self.verify()
        state = self._state(self._events())
        if state["unit_states"].get(unit_id) != "A2":
            raise CohortStateError("A2 token is unavailable")
        return str(self._unit_event(state, unit_id, "a2")["payload"]["a2_token_sha256"])

    def admit_obs2_receipt(self, unit_id: str, receipt_bytes: bytes) -> P2Receipt:
        self.verify()
        state = self._state(self._events())
        if state["unit_states"].get(unit_id) != "A2":
            raise CohortStateError("observation 2 requires its fresh A2")
        obs1 = self._unit_event(state, unit_id, "obs1")["payload"]
        a2 = self._unit_event(state, unit_id, "a2")["payload"]
        document = self._validate_observation(
            receipt_bytes,
            expected_url=obs1["url"],
            expected_anchor=a2["a2_token_sha256"],
        )
        if (
            _sha256(receipt_bytes) == obs1["receipt_sha256"]
            or document["reservation_binding"]["chain_head_sha256"]
            == obs1["reservation_chain_head_sha256"]
        ):
            raise CohortStateError("observation 2 is not a distinct reservation/receipt")
        reference = _publish_raw_artifact(self._artifact_dir, f"obs2-{unit_id}", receipt_bytes)
        return self._append_event(
            "obs2",
            {
                "unit_id": unit_id,
                "url": obs1["url"],
                "route_class": LEVER_LIST_ROUTE_CLASS,
                "receipt": reference,
                "receipt_sha256": _sha256(receipt_bytes),
                "body_sha256": document["response"]["body_sha256"],
                "reservation_chain_head_sha256": document["reservation_binding"]["chain_head_sha256"],
                "embedded_a2_token_sha256": document["pre_observation_anchor_sha256"],
                "a2_gate_event_sequence": self._unit_event(state, unit_id, "a2")["sequence"],
                "interpretation_contract": obs1["interpretation_contract"],
                **_WITHHELD,
            },
        )

    def admit_a3(
        self,
        unit_id: str,
        response_bytes: bytes,
        entropy: bytes,
        receipt_bytes: bytes,
    ) -> P2Receipt:
        self.verify()
        state = self._state(self._events())
        if state["unit_states"].get(unit_id) != "OBS2":
            raise CohortStateError("A3 requires observation 2")
        obs2 = self._unit_event(state, unit_id, "obs2")["payload"]
        if receipt_bytes != self._artifact_bytes(obs2["receipt"]):
            raise CohortStateError("A3 target differs from observation 2")
        a2 = self._attestation_from_event(self._unit_event(state, unit_id, "a2"))
        attestation, binding = self._verify_anchor(
            unit_id=unit_id,
            role="A3",
            response_bytes=response_bytes,
            entropy=entropy,
            target_receipt_bytes=receipt_bytes,
            prior_anchor=a2,
        )
        assert attestation.midpoint_unix is not None and attestation.radius_seconds is not None
        assert a2.midpoint_unix is not None and a2.radius_seconds is not None
        if (attestation.midpoint_unix - attestation.radius_seconds) < (
            a2.midpoint_unix - a2.radius_seconds
        ):
            raise CohortStateError("A3 rolls back before A2")
        payload = {
            "unit_id": unit_id,
            "anchor": binding,
            "attestation": attestation.document(),
            "a3_seals_obs2_only": True,
            "a3_establishes_separation": False,
            "response": _publish_raw_artifact(self._artifact_dir, f"a3-response-{unit_id}", response_bytes),
            "entropy": _publish_raw_artifact(self._artifact_dir, f"a3-entropy-{unit_id}", entropy),
            **_WITHHELD,
        }
        return self._append_event("a3", payload)

    def _replay_receipt_for_events(
        self,
        events: tuple[dict[str, Any], ...],
    ) -> ReplayReceipt:
        state = self._state(events)
        units: list[dict[str, object]] = []
        for unit_id in sorted(state["unit_events"]):
            unit_events = state["unit_events"][unit_id]
            units.append(
                {
                    "unit_id": unit_id,
                    "state": state["unit_states"][unit_id],
                    "event_receipts": {
                        name: unit_events[name]["receipt_sha256"]
                        for name in sorted(unit_events)
                    },
                }
            )
        document = {
            "schema_version": REPLAY_SCHEMA_VERSION,
            "cohort_id": self.cohort_id,
            "frozen_identity": self.frozen_identity.document(),
            "event_count": len(events),
            "chain_head_sha256": events[-1]["receipt_sha256"],
            "cohort_frozen": state["frozen"],
            "candidate_attempts": state["candidate_attempts"],
            "units": units,
            "restart_count": state["restart_count"],
            "replay_is_read_only": True,
            **_WITHHELD,
        }
        receipt_sha256 = _domain_hash(REPLAY_DOMAIN, document)
        document["receipt_sha256"] = receipt_sha256
        return ReplayReceipt(receipt_sha256, document)

    def replay(self) -> ReplayReceipt:
        self.verify()
        return self._replay_receipt_for_events(self._events())

    def admit_replay_pair(self, first_bytes: bytes, second_bytes: bytes) -> P2Receipt:
        self.verify()
        state = self._state(self._events())
        if state["replay_pair_count"]:
            raise CohortStateError("double-replay witness already exists")
        if (
            not state["frozen"]
            or len(
                [
                    value
                    for value in state["unit_states"].values()
                    if value == "COMPLETE"
                ]
            )
            < REQUIRED_OBSERVATION_UNITS
        ):
            raise CohortStateError("double replay requires the complete denominator")
        first = _canonical_json_object(first_bytes, "first replay receipt")
        second = _canonical_json_object(second_bytes, "second replay receipt")
        if first != second or first.get("schema_version") != REPLAY_SCHEMA_VERSION:
            raise CohortStateError("independent replay outputs are not byte-identical")
        claimed = first.get("receipt_sha256")
        core = {key: value for key, value in first.items() if key != "receipt_sha256"}
        if claimed != _domain_hash(REPLAY_DOMAIN, core) or claimed != self.replay().receipt_sha256:
            raise CohortStateError("replay receipt does not match current immutable inputs")
        references = {
            "first": _publish_raw_artifact(self._artifact_dir, "replay-first", first_bytes),
            "second": _publish_raw_artifact(self._artifact_dir, "replay-second", second_bytes),
        }
        return self._append_event(
            "replay_pair",
            {
                "schema_version": REPLAY_PAIR_SCHEMA_VERSION,
                "replay_receipt_sha256": claimed,
                "byte_identical": True,
                "invocation_count": 2,
                "independent_processes_proven_by_p2": False,
                "receipts": references,
                **_WITHHELD,
            },
        )

    def close_readiness(self) -> ClosureReport:
        self.verify()
        events = self._events()
        state = self._state(events)
        complete_ids = sorted(
            unit_id for unit_id, value in state["unit_states"].items() if value == "COMPLETE"
        )
        fully_verified_ids = list(complete_ids)
        manifest = self._manifest()
        distinct_employers = len(set(complete_ids))
        admitted_anchor_count = sum(
            event_type in {"a1", "a2", "a3"}
            for unit_events in state["unit_events"].values()
            for event_type in unit_events
        )
        restart_sequences = [event["sequence"] for event in events if event["event_type"] == "restart"]
        spanning_restart = False
        for unit_id in complete_ids:
            unit_events = state["unit_events"][unit_id]
            a1_sequence = unit_events["a1"]["sequence"]
            a2_sequence = unit_events["a2"]["sequence"]
            if any(a1_sequence < sequence < a2_sequence for sequence in restart_sequences):
                spanning_restart = True
                break
        reasons: list[str] = []
        if not state["frozen"]:
            reasons.append("cohort_not_frozen")
        if len(complete_ids) < REQUIRED_OBSERVATION_UNITS:
            reasons.append("complete_denominator_below_10")
        if len(fully_verified_ids) < MINIMUM_FULLY_VERIFIED_UNITS:
            reasons.append("fully_verified_denominator_below_8")
        if distinct_employers < MINIMUM_DISTINCT_EMPLOYERS:
            reasons.append("distinct_employers_below_3")
        expected_attempts = [route.employer_or_board_id for route in manifest.candidates[: len(state["candidate_attempts"])]]
        if state["candidate_attempts"] != expected_attempts:
            reasons.append("manifest_order_differs")
        if state["restart_count"] < 2:
            reasons.append("restart_drills_below_2")
        if not spanning_restart:
            reasons.append("no_restart_spans_a1_a2_window")
        if state["replay_pair_count"] != 1:
            reasons.append("double_replay_witness_absent")
        freeze = next((event for event in events if event["event_type"] == "cohort_freeze"), None)
        if (
            freeze is None
            or freeze["payload"].get("failed_history_non_cohort") is not True
            or freeze["payload"].get("failed_history_reservations_counted")
            != FAILED_DRILL_RESERVATION_COUNT
        ):
            reasons.append("failed_drill_disclosure_differs")
        document = {
            "schema_version": READINESS_SCHEMA_VERSION,
            "cohort_id": self.cohort_id,
            "complete_units": len(complete_ids),
            "fully_verified_units": len(fully_verified_ids),
            "distinct_employers_or_boards": distinct_employers,
            "candidate_attempts": len(state["candidate_attempts"]),
            "required_observation_units": REQUIRED_OBSERVATION_UNITS,
            "minimum_fully_verified_units": MINIMUM_FULLY_VERIFIED_UNITS,
            "minimum_distinct_employers_or_boards": MINIMUM_DISTINCT_EMPLOYERS,
            "authenticated_separation_seconds": MINIMUM_AUTHENTICATED_SEPARATION_SECONDS,
            "issuer_calls_per_complete_unit": ISSUER_CALLS_PER_COMPLETE_UNIT,
            "maximum_later_issuer_calls": (
                ISSUER_CALLS_PER_COMPLETE_UNIT * REQUIRED_OBSERVATION_UNITS
            ),
            "p2_issuer_calls": 0,
            "admitted_anchor_count": admitted_anchor_count,
            "restart_drills": state["restart_count"],
            "restart_spanning_window": spanning_restart,
            "replay_invocations": 2 if state["replay_pair_count"] == 1 else 0,
            "independent_replay_processes_proven_by_p2": False,
            "failed_drill_non_cohort": freeze is not None,
            "failed_drill_reservations_counted": FAILED_DRILL_RESERVATION_COUNT if freeze else 0,
            "ready_for_later_live_metric_evaluation": not reasons,
            "not_ready_reasons": reasons,
            "readiness_is_not_liveness": True,
            **_WITHHELD,
        }
        receipt_sha256 = _domain_hash(READINESS_DOMAIN, document)
        document["receipt_sha256"] = receipt_sha256
        return ClosureReport(receipt_sha256, document)


__all__ = [
    "A2_TARGET_SCHEMA_VERSION",
    "CohortFreezeReceipt",
    "CohortJournalIntegrityError",
    "CohortPlan",
    "CohortStateError",
    "ClosureReport",
    "FrozenIdentity",
    "FrozenIdentityDriftError",
    "ISSUER_CALLS_PER_COMPLETE_UNIT",
    "MINIMUM_AUTHENTICATED_SEPARATION_SECONDS",
    "P2Receipt",
    "ReplayReceipt",
    "ThreeAnchorCohortError",
    "ThreeAnchorCohortRecorder",
    "capture_frozen_identity",
    "schema_identity_sha256",
]
