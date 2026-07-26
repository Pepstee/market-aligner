"""Portable publication and validation of JAA-04 Opportunity-0 evidence."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Mapping

from .public_access import PublicAccessPolicy, replay_access_receipt


SCHEMA_VERSION = "jaa04.admission-evidence.v2"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_snapshot_hash(path: Path) -> str:
    """Hash JSON bytes or the complete logical SQLite state, including WAL."""
    if path.suffix.casefold() == ".json":
        return sha256_file(path)
    digest = hashlib.sha256(b"jaa04-sqlite-logical-snapshot-v1\0")
    uri = path.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        for statement in connection.iterdump():
            digest.update(statement.encode("utf-8"))
            digest.update(b"\n")
    return digest.hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def _safe_relative(root: Path, value: object) -> tuple[Path, Path]:
    relative = Path(str(value))
    if relative.is_absolute() or relative in {Path(""), Path(".")}:
        raise ValueError("admission evidence reference must be a relative file")
    target = (root / relative).resolve()
    if root.resolve() not in target.parents:
        raise ValueError("admission evidence reference escapes its raw store")
    return relative, target


def _raw_references(records: Iterable[Mapping[str, Any]]) -> dict[Path, str]:
    result: dict[Path, str] = {}
    for record in records:
        refs = record.get("raw_response_refs")
        if not isinstance(refs, list) or not refs:
            raise ValueError("official JSON admission requires raw response references")
        for ref in refs:
            if not isinstance(ref, Mapping):
                raise ValueError("admission raw response reference is invalid")
            pairs = [(ref.get("raw_response"), ref.get("sha256"))]
            access = ref.get("access_receipt")
            if not isinstance(access, Mapping) or access.get("allowed") is not True:
                raise ValueError("admission access receipt is required")
            pairs.append((
                access.get("raw_response_ref"),
                access.get("content_sha256"),
            ))
            for path_value, digest_value in pairs:
                relative = Path(str(path_value))
                digest = str(digest_value)
                if (relative.is_absolute() or relative in {Path(""), Path(".")}
                        or any(part == ".." for part in relative.parts)
                        or len(digest) != 64
                        or any(character not in "0123456789abcdef" for character in digest)):
                    raise ValueError("admission raw evidence identity is invalid")
                existing = result.get(relative)
                if existing is not None and existing != digest:
                    raise ValueError("one admission raw path declares conflicting hashes")
                result[relative] = digest
    return result


def _copy_exact(source: Path, destination: Path, digest: str) -> None:
    if not source.is_file() or sha256_file(source) != digest:
        raise ValueError("admission raw evidence is missing or differs from its hash")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if sha256_file(destination) != digest:
            raise ValueError("admission publication path collision")
        return
    shutil.copyfile(source, destination)
    if sha256_file(destination) != digest:
        raise RuntimeError("copied admission evidence differs from its source")


def publish_admission_evidence(
    queue_snapshot: Path,
    records: list[Mapping[str, Any]],
    stage: Path,
) -> dict[str, Any]:
    """Copy only the admitted snapshot and referenced raw bytes into a stage."""
    admission = stage / "admission"
    admission.mkdir(parents=True, exist_ok=False)
    json_mode = queue_snapshot.suffix.casefold() == ".json"
    snapshot_name = "queue_snapshot.json" if json_mode else "queue_snapshot.sqlite3"
    snapshot_target = admission / snapshot_name
    if json_mode:
        shutil.copyfile(queue_snapshot, snapshot_target)
        source_snapshot_sha256 = sha256_file(snapshot_target)
    else:
        uri = queue_snapshot.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as source:
            with sqlite3.connect(snapshot_target) as destination:
                source.backup(destination)
        source_snapshot_sha256 = source_snapshot_hash(snapshot_target)
    snapshot_sha256 = sha256_file(snapshot_target)
    referenced: list[dict[str, Any]] = []
    if json_mode:
        payload = json.loads(queue_snapshot.read_text(encoding="utf-8"))
        raw_store = payload.get("raw_store")
        if not isinstance(raw_store, dict) or not raw_store.get("root"):
            raise ValueError("official admission snapshot has no raw store")
        source_root = Path(str(raw_store["root"])).resolve()
        raw_target = admission / "raw"
        references = _raw_references(records)
        for relative, digest in sorted(references.items(), key=lambda row: row[0].as_posix()):
            _, source = _safe_relative(source_root, relative)
            destination = raw_target / relative
            _copy_exact(source, destination, digest)
            referenced.append({
                "path": relative.as_posix(),
                "sha256": digest,
                "size_bytes": destination.stat().st_size,
            })
    descriptor = {
        "schema_version": SCHEMA_VERSION,
        "mode": "official-json-v2" if json_mode else "sqlite-lifecycle-snapshot",
        "snapshot_path": f"admission/{snapshot_name}",
        "snapshot_sha256": snapshot_sha256,
        "source_snapshot_sha256": source_snapshot_sha256,
        "raw_cache_root": "admission/raw" if json_mode else None,
        "referenced_files": referenced,
        "referenced_files_hash": hashlib.sha256(_canonical(referenced)).hexdigest(),
    }
    return descriptor


def _manifest_to_admitted(records: list[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for record in records:
        key = str(record.get("job_key", ""))
        if not key or key in result:
            raise ValueError("manifest admission identities are missing or duplicated")
        result[key] = record
    return result


def validate_admission_evidence(
    capture: Path,
    descriptor: Mapping[str, Any],
    manifest_records: list[Mapping[str, Any]],
    *,
    expected_snapshot_sha256: str,
    access_policies: Mapping[str, PublicAccessPolicy],
) -> None:
    """Replay the published admission linkage without external paths."""
    required = {
        "schema_version", "mode", "snapshot_path", "snapshot_sha256",
        "source_snapshot_sha256", "raw_cache_root", "referenced_files",
        "referenced_files_hash",
    }
    if set(descriptor) != required or descriptor.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("admission evidence descriptor is invalid")
    snapshot_relative, snapshot = _safe_relative(capture, descriptor["snapshot_path"])
    if (not snapshot_relative.as_posix().startswith("admission/")
            or not snapshot.is_file()
            or sha256_file(snapshot) != descriptor.get("snapshot_sha256")
            or descriptor.get("snapshot_sha256") != expected_snapshot_sha256):
        raise ValueError("published admission snapshot is missing or modified")
    records_by_key = _manifest_to_admitted(manifest_records)
    mode = descriptor.get("mode")
    if mode == "sqlite-lifecycle-snapshot":
        if descriptor.get("raw_cache_root") is not None or descriptor.get("referenced_files") != []:
            raise ValueError("SQLite admission descriptor cannot claim a JSON raw store")
        if descriptor.get("source_snapshot_sha256") != source_snapshot_hash(snapshot):
            raise ValueError("published SQLite logical snapshot identity is invalid")
        uri = snapshot.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """SELECT j.job_key,j.url,j.company,j.title,j.payload_hash,
                          j.opportunity
                   FROM employer_research_queue q
                   JOIN pipeline_jobs j USING(job_key)
                   WHERE j.opportunity_decision='pass'"""
            ).fetchall()
        snapshot_records = {str(row["job_key"]): row for row in rows}
        if (len(snapshot_records) != len(rows)
                or not set(records_by_key).issubset(snapshot_records)):
            raise ValueError("published SQLite snapshot does not contain the admitted cohort")
        expected_selection = set(
            sorted(snapshot_records)[:len(records_by_key)]
        )
        if set(records_by_key) != expected_selection:
            raise ValueError(
                "manifest admission does not match deterministic SQLite cohort selection"
            )
        for key, manifest_record in records_by_key.items():
            source = snapshot_records[key]
            reassessment = manifest_record.get("opportunity1_reassessment")
            if (manifest_record.get("vacancy_url") != source["url"]
                    or manifest_record.get("company") != source["company"]
                    or manifest_record.get("role") != source["title"]
                    or manifest_record.get("admitted_payload_hash")
                    != source["payload_hash"]
                    or manifest_record.get("opportunity0_raw_response_refs")
                    not in (None, [])
                    or not isinstance(reassessment, Mapping)
                    or type(reassessment.get("opportunity0_score_bp")) is not int
                    or reassessment["opportunity0_score_bp"]
                    != int(round(float(source["opportunity"]) * 10_000))):
                raise ValueError(
                    "manifest admission differs from its published SQLite snapshot"
                )
    elif mode == "official-json-v2":
        if descriptor.get("source_snapshot_sha256") != descriptor.get("snapshot_sha256"):
            raise ValueError("published JSON snapshot identity is invalid")
        payload = json.loads(snapshot.read_text(encoding="utf-8"))
        raw_records = payload.get("records")
        if (payload.get("schema_version") != "jaa04.official-admitted-queue.v2"
                or not isinstance(raw_records, list)
                or hashlib.sha256(_canonical(raw_records)).hexdigest()
                != payload.get("records_hash")):
            raise ValueError("published official JSON snapshot is invalid or unbound")
        snapshot_records = {
            str(record.get("job_key", "")): record
            for record in raw_records
            if isinstance(record, dict)
        }
        if set(snapshot_records) != set(records_by_key):
            raise ValueError("published JSON snapshot differs from the manifest cohort")
        for key, manifest_record in records_by_key.items():
            source = snapshot_records[key]
            if (manifest_record.get("admitted_payload_hash") != source.get("payload_hash")
                    or manifest_record.get("opportunity0_raw_response_refs")
                    != source.get("raw_response_refs")):
                raise ValueError("manifest admission provenance differs from its snapshot")
        raw_relative, raw_root = _safe_relative(capture, descriptor["raw_cache_root"])
        if raw_relative.as_posix() != "admission/raw" or not raw_root.is_dir():
            raise ValueError("published admission raw cache is missing")
        references = _raw_references(snapshot_records.values())
        actual_files = {
            path.relative_to(raw_root): path
            for path in raw_root.rglob("*") if path.is_file()
        }
        if set(actual_files) != set(references):
            raise ValueError("published admission raw cache is incomplete or over-wide")
        expected_rows = []
        for relative, digest in sorted(references.items(), key=lambda row: row[0].as_posix()):
            path = actual_files[relative]
            if sha256_file(path) != digest:
                raise ValueError("published admission raw bytes differ from their hash")
            expected_rows.append({
                "path": relative.as_posix(),
                "sha256": digest,
                "size_bytes": path.stat().st_size,
            })
        if descriptor.get("referenced_files") != expected_rows:
            raise ValueError("admission referenced-file inventory is inconsistent")
        for record in snapshot_records.values():
            for ref in record["raw_response_refs"]:
                redirect_chain = ref.get("redirect_chain")
                if not isinstance(redirect_chain, list):
                    raise ValueError("admission redirect provenance is invalid")
                content_urls = tuple(dict.fromkeys((
                    str(ref.get("requested_url", "")),
                    *(str(url) for url in redirect_chain),
                    str(ref.get("final_url", "")),
                )))
                replay_access_receipt(
                    ref["access_receipt"],
                    _PublishedRawCache(raw_root),
                    content_urls=content_urls,
                    content_retrieved_at=str(ref.get("observed_at", "")),
                    policies=access_policies,
                )
    else:
        raise ValueError("unsupported admission evidence mode")
    if descriptor.get("referenced_files_hash") != hashlib.sha256(
        _canonical(descriptor.get("referenced_files"))
    ).hexdigest():
        raise ValueError("admission referenced-file inventory hash mismatch")


class _PublishedRawCache:
    """Minimal exact-byte resolver for a published admission raw directory."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def resolve(self, reference: str, expected_sha256: str) -> bytes:
        _, target = _safe_relative(self.root, reference)
        if not target.is_file():
            raise ValueError("published admission raw reference is invalid")
        body = target.read_bytes()
        if hashlib.sha256(body).hexdigest() != expected_sha256:
            raise ValueError("published admission raw bytes differ from their hash")
        return body


def raw_evidence_hash(capture: Path) -> str:
    """Hash research and admission raw bytes in one stable path domain."""
    files = sorted(
        path for root in (capture / "raw", capture / "admission" / "raw")
        if root.is_dir()
        for path in root.rglob("*") if path.is_file()
    )
    return hashlib.sha256(b"".join(
        path.relative_to(capture).as_posix().encode() + b"\0" + path.read_bytes()
        for path in files
    )).hexdigest()
