"""Faceless internal JAA preparation and deterministic no-submit evidence."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from market_aligner.processing import parse_eligibility_receipt

SCHEMA_VERSION = "market-aligner.internal-jaa.v1"
_IDS = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$", re.ASCII)
_JOB_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,255}$", re.ASCII)
_DIGEST = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FAILURES = frozenset({"identity_required", "unsupported_ats", "human_verification", "provider_timeout"})
_RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$", re.ASCII)
_LEARNING_STAGES = frozenset({"ats_preflight", "capture", "improvement"})
_LEARNING_ISSUES = frozenset({"prepared", "blocked", "identity_required", "unsupported_ats", "human_verification", "provider_timeout"})
_LEARNING_SUMMARIES = frozenset({"observation_captured", "outcome_blocked", "improvement_required"})


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _IDS.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"{label} must be an ASCII path-safe ID")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _job_key(value: object) -> str:
    if not isinstance(value, str) or not _JOB_KEY.fullmatch(value):
        raise ValueError("job key must use the canonical Market key grammar")
    return value


def _canonical(raw: bytes) -> dict[str, object]:
    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in rows:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid forensic JSON") from exc
    if not isinstance(value, dict) or raw != (canonical_json(value) + "\n").encode():
        raise ValueError("forensic JSON is not canonical")
    return value


def _root(value: str | Path, *, create: bool) -> tuple[Path, tuple[int, int]]:
    root = Path(value)
    if not root.is_absolute() or any(part in {".", ".."} for part in root.parts[1:]):
        raise ValueError("forensic root must be absolute and canonical")
    current = Path("/")
    for index, part in enumerate(root.parts[1:]):
        current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if not create or index != len(root.parts) - 2:
                raise KeyError("forensic root is missing") from None
            current.mkdir(mode=0o700)
            info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("forensic root has unsafe path component")
    info = os.lstat(root)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("forensic root must be current-user 0700")
    return root, (info.st_dev, info.st_ino)


def _manifests(root: Path, *, create: bool) -> Path:
    path = root / "manifests"
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if not create:
            raise KeyError("forensic manifests are missing") from None
        path.mkdir(mode=0o700)
        info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("forensic manifests are unsafe")
    return path


def _learning_events(root: Path, *, create: bool) -> Path:
    path = root / "learning-events"
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if not create:
            raise KeyError("forensic learning events are missing") from None
        path.mkdir(mode=0o700)
        info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("forensic learning events are unsafe")
    return path


def _read(path: Path) -> bytes:
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600:
        raise ValueError("forensic manifest is unsafe")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("forensic manifest changed while opening")
        data = b"".join(iter(lambda: os.read(fd, 65536), b""))
        after = os.lstat(path)
        if (after.st_dev, after.st_ino, after.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ValueError("forensic manifest changed while reading")
        return data
    finally:
        os.close(fd)


def _write_once(directory: Path, name: str, data: bytes) -> None:
    target = directory / name
    try:
        if _read(target) == data:
            return
        raise FileExistsError("attempt ID already has different evidence")
    except FileNotFoundError:
        pass
    temporary = directory / f".{name}.{uuid.uuid4().hex}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(temporary, target, follow_symlinks=False)
    except FileExistsError:
        if _read(target) != data:
            raise FileExistsError("attempt ID already has different evidence")
    finally:
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class ApplicationSource:
    profile_id: str
    job_key: str
    eligibility_receipt_sha256: str
    fit_receipt_sha256: str
    evidence_reference_sha256: str
    contact_reference_sha256: str
    source_sha256: str

    def __post_init__(self) -> None:
        _id(self.profile_id, "profile ID")
        _job_key(self.job_key)
        for name in ("eligibility_receipt_sha256", "fit_receipt_sha256", "evidence_reference_sha256", "contact_reference_sha256", "source_sha256"):
            _digest(getattr(self, name), name)

    def document(self) -> dict[str, object]:
        return self.__dict__ | {"schema_version": SCHEMA_VERSION, "identity_authority": False, "submission_authority": False}


@dataclass(frozen=True)
class SanityReviewReceipt:
    source_sha256: str
    artifact_set_sha256: str
    receipt_sha256: str
    backend: str = "fixture_capture"
    model: str = "deterministic-v1"
    verdict: str = "pass"

    def __post_init__(self) -> None:
        for name in ("source_sha256", "artifact_set_sha256", "receipt_sha256"):
            _digest(getattr(self, name), name)
        if (self.backend, self.model, self.verdict) != ("fixture_capture", "deterministic-v1", "pass"):
            raise ValueError("unsupported faceless sanity receipt")


@dataclass(frozen=True)
class ATSForensicReceipt:
    attempt_id: str
    application_id: str
    manifest_sha256: str
    receipt_sha256: str
    outcome: str
    failure_class: str | None
    event_count: int
    root_identity: tuple[int, int]

    def __post_init__(self) -> None:
        _id(self.attempt_id, "attempt ID")
        _id(self.application_id, "application ID")
        _digest(self.manifest_sha256, "manifest SHA-256")
        _digest(self.receipt_sha256, "receipt SHA-256")
        if self.outcome not in {"prepared", "blocked"} or (self.outcome == "prepared") != (self.failure_class is None) or self.failure_class not in _FAILURES | {None} or self.event_count < 1:
            raise ValueError("invalid forensic outcome")

    def document(self) -> dict[str, object]:
        return {"schema_version": SCHEMA_VERSION, "attempt_id": self.attempt_id, "application_id": self.application_id, "manifest_path": f"manifests/{self.attempt_id}.json", "manifest_sha256": self.manifest_sha256, "receipt_sha256": self.receipt_sha256, "outcome": self.outcome, "failure_class": self.failure_class, "event_count": self.event_count, "root_identity": list(self.root_identity), "diagnostic_only": True, "raw_payloads_persisted": False, "identity_authority": False, "release_authority": False, "submission_authority": False}


@dataclass(frozen=True)
class ATSForensicLearningEvent:
    event_sha256: str
    recorded_at: str
    cycle_id: str
    stage: str
    issue_code: str
    summary: str
    attempt_id: str
    application_id: str
    manifest_sha256: str
    receipt_sha256: str
    outcome: str
    failure_class: str | None
    event_count: int

    def __post_init__(self) -> None:
        _digest(self.event_sha256, "learning event SHA-256")
        if not isinstance(self.recorded_at, str) or not _RFC3339_UTC.fullmatch(self.recorded_at):
            raise ValueError("learning event time must be canonical RFC3339 UTC")
        try:
            datetime.fromisoformat(f"{self.recorded_at[:-1]}+00:00")
        except ValueError as exc:
            raise ValueError("learning event time must be canonical RFC3339 UTC") from exc
        _id(self.cycle_id, "learning cycle ID")
        if self.stage not in _LEARNING_STAGES or self.issue_code not in _LEARNING_ISSUES or self.summary not in _LEARNING_SUMMARIES:
            raise ValueError("learning event uses an unsupported closed value")
        _id(self.attempt_id, "attempt ID")
        _id(self.application_id, "application ID")
        _digest(self.manifest_sha256, "manifest SHA-256")
        _digest(self.receipt_sha256, "receipt SHA-256")
        if self.outcome not in {"prepared", "blocked"} or (self.outcome == "prepared") != (self.failure_class is None) or self.failure_class not in _FAILURES | {None} or self.event_count < 1:
            raise ValueError("learning event forensic outcome is invalid")
        if self.event_sha256 != sha256(canonical_json(self.document(include_hash=False)).encode()):
            raise ValueError("learning event identity differs")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        value = {"schema_version": SCHEMA_VERSION, "recorded_at": self.recorded_at, "cycle_id": self.cycle_id, "stage": self.stage, "issue_code": self.issue_code, "summary": self.summary, "attempt_id": self.attempt_id, "application_id": self.application_id, "manifest_sha256": self.manifest_sha256, "receipt_sha256": self.receipt_sha256, "outcome": self.outcome, "failure_class": self.failure_class, "event_count": self.event_count, "diagnostic_only": True, "raw_payloads_persisted": False, "identity_authority": False, "release_authority": False, "submission_authority": False}
        if include_hash:
            value["event_sha256"] = self.event_sha256
        return value


class ATSForensicRecorder:
    def __init__(self, root: str | Path, *, attempt_id: str, application_id: str, binding_sha256: str) -> None:
        self.root, self.root_identity = _root(root, create=True)
        self.attempt_id = _id(attempt_id, "attempt ID")
        self.application_id = _id(application_id, "application ID")
        self.binding_sha256 = _digest(binding_sha256, "binding SHA-256")
        self.events: list[dict[str, object]] = []

    def checkpoint(self, name: str) -> None:
        if name not in {"prepared", "blocked"}:
            raise ValueError("unsupported forensic checkpoint")
        event = {"sequence": len(self.events) + 1, "checkpoint": name}
        self.events.append(event | {"event_sha256": sha256(canonical_json(event).encode())})

    def finalize(self, *, outcome: str, failure_class: str | None = None) -> ATSForensicReceipt:
        if not self.events:
            raise ValueError("forensic observation has no events")
        manifest = {"schema_version": SCHEMA_VERSION, "attempt_id": self.attempt_id, "application_id": self.application_id, "binding_sha256": self.binding_sha256, "root_identity": list(self.root_identity), "outcome": outcome, "failure_class": failure_class, "events": self.events, "diagnostic_only": True, "raw_payloads_persisted": False, "identity_authority": False, "release_authority": False, "submission_authority": False}
        data = (canonical_json(manifest) + "\n").encode()
        _write_once(_manifests(self.root, create=True), f"{self.attempt_id}.json", data)
        receipt = ATSForensicReceipt(self.attempt_id, self.application_id, sha256(data), "0" * 64, outcome, failure_class, len(self.events), self.root_identity)
        identity = receipt.document() | {"receipt_sha256": None}
        return ATSForensicReceipt(self.attempt_id, self.application_id, receipt.manifest_sha256, sha256(canonical_json(identity).encode()), outcome, failure_class, len(self.events), self.root_identity)


def load_forensic_receipt(root: str | Path, *, attempt_id: str, application_id: str, binding_sha256: str) -> ATSForensicReceipt:
    path, identity = _root(root, create=False)
    try:
        data = _read(_manifests(path, create=False) / f"{_id(attempt_id, 'attempt ID')}.json")
    except FileNotFoundError:
        raise KeyError(attempt_id) from None
    manifest = _canonical(data)
    exact = {"schema_version", "attempt_id", "application_id", "binding_sha256", "root_identity", "outcome", "failure_class", "events", "diagnostic_only", "raw_payloads_persisted", "identity_authority", "release_authority", "submission_authority"}
    if set(manifest) != exact or manifest["attempt_id"] != attempt_id or manifest["application_id"] != application_id or manifest["binding_sha256"] != _digest(binding_sha256, "binding SHA-256") or manifest["root_identity"] != list(identity) or manifest["diagnostic_only"] is not True or manifest["raw_payloads_persisted"] is not False or any(manifest[x] is not False for x in ("identity_authority", "release_authority", "submission_authority")) or not isinstance(manifest["events"], list):
        raise ValueError("forensic manifest binding differs")
    provisional = ATSForensicReceipt(attempt_id, application_id, sha256(data), "0" * 64, manifest["outcome"], manifest["failure_class"], len(manifest["events"]), identity)
    receipt_doc = provisional.document() | {"receipt_sha256": None}
    return ATSForensicReceipt(attempt_id, application_id, provisional.manifest_sha256, sha256(canonical_json(receipt_doc).encode()), provisional.outcome, provisional.failure_class, provisional.event_count, identity)


def _verify_learning_receipt(root: str | Path, receipt: ATSForensicReceipt) -> None:
    if not isinstance(receipt, ATSForensicReceipt):
        raise TypeError("learning events require ATSForensicReceipt")
    path, identity = _root(root, create=False)
    data = _read(_manifests(path, create=False) / f"{receipt.attempt_id}.json")
    manifest = _canonical(data)
    expected = {"schema_version", "attempt_id", "application_id", "binding_sha256", "root_identity", "outcome", "failure_class", "events", "diagnostic_only", "raw_payloads_persisted", "identity_authority", "release_authority", "submission_authority"}
    if set(manifest) != expected or manifest["schema_version"] != SCHEMA_VERSION or manifest["attempt_id"] != receipt.attempt_id or manifest["application_id"] != receipt.application_id or manifest["root_identity"] != list(identity) or manifest["outcome"] != receipt.outcome or manifest["failure_class"] != receipt.failure_class or manifest["diagnostic_only"] is not True or manifest["raw_payloads_persisted"] is not False or any(manifest[name] is not False for name in ("identity_authority", "release_authority", "submission_authority")) or not isinstance(manifest["events"], list) or len(manifest["events"]) != receipt.event_count or sha256(data) != receipt.manifest_sha256:
        raise ValueError("learning event forensic receipt binding differs")
    receipt_document = receipt.document() | {"receipt_sha256": None}
    if receipt.receipt_sha256 != sha256(canonical_json(receipt_document).encode()):
        raise ValueError("learning event forensic receipt identity differs")


def _learning_event_name(event_sha256: str) -> str:
    return f"{_digest(event_sha256, 'learning event SHA-256')}.json"


def _learning_event_from_document(value: object) -> ATSForensicLearningEvent:
    keys = {"schema_version", "recorded_at", "cycle_id", "stage", "issue_code", "summary", "attempt_id", "application_id", "manifest_sha256", "receipt_sha256", "outcome", "failure_class", "event_count", "diagnostic_only", "raw_payloads_persisted", "identity_authority", "release_authority", "submission_authority", "event_sha256"}
    if not isinstance(value, dict) or set(value) != keys or value["schema_version"] != SCHEMA_VERSION or value["diagnostic_only"] is not True or value["raw_payloads_persisted"] is not False or any(value[name] is not False for name in ("identity_authority", "release_authority", "submission_authority")):
        raise ValueError("learning event schema differs")
    event = ATSForensicLearningEvent(**{key: value[key] for key in keys if key not in {"schema_version", "diagnostic_only", "raw_payloads_persisted", "identity_authority", "release_authority", "submission_authority"}})
    return event


def record_canary_learning_event(root: str | Path, receipt: ATSForensicReceipt, *, recorded_at: str, cycle_id: str, stage: str, issue_code: str, summary: str) -> ATSForensicLearningEvent:
    """Create-or-verify one closed, receipt-bound, no-submit learning event."""
    _verify_learning_receipt(root, receipt)
    fields = {"recorded_at": recorded_at, "cycle_id": cycle_id, "stage": stage, "issue_code": issue_code, "summary": summary, "attempt_id": receipt.attempt_id, "application_id": receipt.application_id, "manifest_sha256": receipt.manifest_sha256, "receipt_sha256": receipt.receipt_sha256, "outcome": receipt.outcome, "failure_class": receipt.failure_class, "event_count": receipt.event_count}
    event = ATSForensicLearningEvent(**fields, event_sha256=sha256(canonical_json({"schema_version": SCHEMA_VERSION, **fields, "diagnostic_only": True, "raw_payloads_persisted": False, "identity_authority": False, "release_authority": False, "submission_authority": False}).encode()))
    root_path, _identity = _root(root, create=False)
    _write_once(_learning_events(root_path, create=True), _learning_event_name(event.event_sha256), (canonical_json(event.document()) + "\n").encode())
    return verify_canary_learning_event(root, event.event_sha256)


def verify_canary_learning_event(root: str | Path, event_sha256: str) -> ATSForensicLearningEvent:
    root_path, _identity = _root(root, create=False)
    event = _learning_event_from_document(_canonical(_read(_learning_events(root_path, create=False) / _learning_event_name(event_sha256))))
    if event.event_sha256 != event_sha256:
        raise ValueError("learning event path differs from identity")
    receipt = ATSForensicReceipt(event.attempt_id, event.application_id, event.manifest_sha256, event.receipt_sha256, event.outcome, event.failure_class, event.event_count, _identity)
    _verify_learning_receipt(root, receipt)
    return event


def list_canary_learning_events(root: str | Path) -> tuple[ATSForensicLearningEvent, ...]:
    root_path, _identity = _root(root, create=False)
    try:
        directory = _learning_events(root_path, create=False)
    except KeyError:
        return ()
    events: list[ATSForensicLearningEvent] = []
    for path in directory.iterdir():
        if not _DIGEST.fullmatch(path.stem) or path.suffix != ".json":
            raise ValueError("learning event inventory is unsafe")
        events.append(verify_canary_learning_event(root, path.stem))
    return tuple(sorted(events, key=lambda event: (event.recorded_at, event.event_sha256)))


@dataclass(frozen=True)
class CaptureRequest:
    attempt_id: str
    application_id: str
    binding_sha256: str


class CaptureBackend(Protocol):
    def capture(self, request: CaptureRequest, recorder: ATSForensicRecorder) -> tuple[str, str | None]: ...


@dataclass(frozen=True)
class FixtureCaptureBackend:
    outcome: str = "prepared"
    failure_class: str | None = None

    def capture(self, request: CaptureRequest, recorder: ATSForensicRecorder) -> tuple[str, str | None]:
        del request
        recorder.checkpoint(self.outcome)
        return self.outcome, self.failure_class


def prepare_from_market(*, eligibility_receipt: bytes, evidence_reference_sha256: str, contact_reference_sha256: str) -> tuple[ApplicationSource, SanityReviewReceipt]:
    receipt = parse_eligibility_receipt(eligibility_receipt)
    if receipt["decision"] != "pass" or receipt["eligibility_authority"] is not True or receipt["application_authority"] is not False:
        raise ValueError("Market eligibility receipt does not permit faceless preparation")
    fields = {"profile_id": receipt["profile_id"], "job_key": receipt["job_key"], "eligibility_receipt_sha256": receipt["self_hash"], "fit_receipt_sha256": receipt["fit_receipt_self_hash"], "evidence_reference_sha256": _digest(evidence_reference_sha256, "evidence reference"), "contact_reference_sha256": _digest(contact_reference_sha256, "contact reference")}
    source = ApplicationSource(**fields, source_sha256=sha256(canonical_json(fields).encode()))
    artifact = sha256(canonical_json({"source": source.source_sha256, "opaque_preview_only": True}).encode())
    review = {"source_sha256": source.source_sha256, "artifact_set_sha256": artifact, "backend": "fixture_capture", "model": "deterministic-v1", "verdict": "pass"}
    return source, SanityReviewReceipt(**review, receipt_sha256=sha256(canonical_json(review).encode()))


def capture_or_recover(*, root: str | Path, attempt_id: str, application_id: str, source: ApplicationSource, sanity: SanityReviewReceipt, ats_name: str, backend: CaptureBackend | None = None) -> ATSForensicReceipt:
    _id(ats_name, "ATS name")
    if sanity.source_sha256 != source.source_sha256:
        raise ValueError("sanity receipt source differs")
    binding = sha256(canonical_json({"source": source.source_sha256, "sanity": sanity.receipt_sha256, "ats": ats_name}).encode())
    try:
        return load_forensic_receipt(root, attempt_id=attempt_id, application_id=application_id, binding_sha256=binding)
    except KeyError:
        pass
    recorder = ATSForensicRecorder(root, attempt_id=attempt_id, application_id=application_id, binding_sha256=binding)
    if ats_name != "fixture":
        recorder.checkpoint("blocked")
        return recorder.finalize(outcome="blocked", failure_class="unsupported_ats")
    outcome, failure = (backend or FixtureCaptureBackend()).capture(CaptureRequest(attempt_id, application_id, binding), recorder)
    return recorder.finalize(outcome=outcome, failure_class=failure)
