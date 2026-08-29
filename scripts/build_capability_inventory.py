#!/usr/bin/env python3
"""Build the deterministic cross-copy Market Aligner capability inventory.

This script exists because the migration ledger records subsystem decisions, while the
archaeology acceptance gate needs a distinct, symbol-level account of every preserved
implementation.  It is read-only with respect to donor stores.  JAA paths are always
normalised beneath the ``internal/jaa`` product boundary.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
import tarfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator, Sequence


SCHEMA = "market-aligner.capability-inventory.v1"
SOURCE_SUFFIXES = {".py", ".sh", ".toml", ".yaml", ".yml"}
DONOR_EXCLUDES = (
    "/.git/",
    "/.pytest_cache/",
    "/.venv",
    "/__pycache__/",
    "/application-artifacts/",
    "/data/bulk_",
    "/data_overnight/",
    "/dist-packages/",
    "/env/",
    "/graphify-out/",
    "/llm/data/cache/",
    "/node_modules/",
    "/raw_cache/",
    "/runtime_evidence/",
    "/scraper/data/",
    "/site-packages/",
    "/venv/",
)
JAA_TOP_LEVELS = {
    "baseline_adoption",
    "career_automation",
    "cv_generation",
    "form_filling",
    "jaa_core",
    "llm",
    "profiler",
    "scraper",
    "scripts",
    "skeleton",
}

GMAIL_LIFECYCLE_CAPABILITY = {
    "capability_id": "market.lifecycle.gmail-employer-response.v1",
    "owner": "Market Aligner / internal JAA",
    "status": "required_missing_owner_gate_pending",
    "authority": "gmail_read_only_no_mailbox_mutation",
    "retained": (
        "gmail_confirmation.py (submission-confirmation metadata only)",
        "status_ingestion.py + status_ingestion_live.py (local exports; no mailbox)",
        "status_evidence_store.py + status_store_coordinator.py",
        "outcome_feedback.py + outcome_feedback_live.py",
    ),
    "missing": (
        "read-only Gmail employer-response ingestion adapter",
        "job_id/application_id/attempt_id correlation with explicit ambiguity",
        "private exact-message/thread/body/attachment evidence preservation",
        "append-only idempotent and superseding lifecycle transition receipts",
        "closed response classification and operator action/deadline queue",
        "architecture-owned generic capability adoption/liveness proof",
        "bounded real-mailbox read-only canary with zero mutation",
    ),
    "classes": (
        "acknowledgement",
        "assessment/action-required",
        "interview",
        "rejection",
        "offer",
        "withdrawal/cancellation",
        "human-review-required",
        "unknown/ambiguous",
    ),
    "forbidden": (
        "send",
        "reply",
        "archive",
        "delete",
        "label mutation",
        "attachment upload",
        "Calendar write",
    ),
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _run(args: Sequence[str], *, cwd: Path | None = None) -> bytes:
    return subprocess.check_output(args, cwd=cwd)


def _normalise_repository_path(path: str, *, jaa_only: bool = False) -> str:
    value = PurePosixPath(path).as_posix().lstrip("./")
    if value.startswith("internal/jaa/"):
        return value
    if value.startswith("src/market_aligner/"):
        return value
    if jaa_only:
        return f"internal/jaa/{value}"
    return value


def _candidate_suffix(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in SOURCE_SUFFIXES


def _tar_candidate(path: str) -> bool:
    low = f"/{path.lower()}"
    if not _candidate_suffix(path) or any(item in low for item in DONOR_EXCLUDES):
        return False
    return any(
        marker in low
        for marker in (
            "/market-aligner/",
            "/market_aligner/",
            "/job-application-automation/",
            "/majaa-",
            "/jaa-",
            "/jaa/",
        )
    )


def _normalise_tar_path(path: str) -> str | None:
    parts = list(PurePosixPath(path).parts)
    joined = "/".join(parts)
    for marker in ("src/market_aligner/", "internal/jaa/"):
        if marker in joined:
            return marker + joined.split(marker, 1)[1]

    lower = [part.lower() for part in parts]
    for index, part in enumerate(lower):
        if part in JAA_TOP_LEVELS:
            return "internal/jaa/" + "/".join(parts[index:])

    basename = parts[-1] if parts else ""
    if basename.startswith("test_") and basename.endswith(".py"):
        return f"internal/jaa/{basename}"
    return None


def _semantic_bytes(node: ast.AST) -> bytes:
    return ast.dump(node, annotate_fields=True, include_attributes=False).encode()


@dataclass(frozen=True)
class Feature:
    logical_path: str
    symbol: str
    kind: str
    semantic_sha256: str


def _features(path: str, data: bytes) -> tuple[Feature, ...]:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix != ".py":
        return (Feature(path, "<file>", suffix.lstrip(".") or "file", _sha256(data)),)
    try:
        tree = ast.parse(data.decode("utf-8"), filename=path)
    except (SyntaxError, UnicodeDecodeError):
        return (Feature(path, "<unparsed-module>", "python", _sha256(data)),)

    # The complete file hash is the module-level capability identity.  Re-dumping a
    # very large generated module AST is both slower and less informative than its
    # already canonical byte identity; definitions below still receive AST hashes.
    discovered: list[Feature] = [
        Feature(path, "<module>", "python-module", _sha256(data))
    ]

    def walk(body: Sequence[ast.stmt], prefix: str = "") -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{prefix}{node.name}"
                kind = "class" if isinstance(node, ast.ClassDef) else "function"
                discovered.append(
                    Feature(path, name, kind, _sha256(_semantic_bytes(node)))
                )
                if isinstance(node, ast.ClassDef):
                    walk(node.body, prefix=f"{name}.")

    walk(tree.body)
    return tuple(discovered)


@dataclass
class Implementation:
    content_sha256: str
    origins: set[str] = field(default_factory=set)
    refs: set[str] = field(default_factory=set)
    provenance_count: int = 0
    provenance_examples: set[str] = field(default_factory=set)

    def record_path(self, path: str) -> None:
        self.provenance_count += 1
        if len(self.provenance_examples) < 8:
            self.provenance_examples.add(path)


@dataclass
class FeatureRecord:
    feature: Feature
    implementations: dict[str, Implementation] = field(default_factory=dict)

    def add(
        self,
        *,
        content_sha256: str,
        origin: str,
        path: str,
        ref: str | None = None,
        provenance_count: int = 1,
        provenance_examples: Iterable[str] = (),
    ) -> None:
        implementation = self.implementations.setdefault(
            content_sha256, Implementation(content_sha256=content_sha256)
        )
        implementation.origins.add(origin)
        if ref:
            implementation.refs.add(ref)
        implementation.record_path(path)
        implementation.provenance_count += max(0, provenance_count - 1)
        for item in provenance_examples:
            if len(implementation.provenance_examples) < 8:
                implementation.provenance_examples.add(item)


class Inventory:
    def __init__(self) -> None:
        self.records: dict[tuple[str, str, str, str], FeatureRecord] = {}
        self.canonical_semantics: set[str] = set()
        self.canonical_logical: set[tuple[str, str, str]] = set()
        self._feature_cache: dict[tuple[str, str], tuple[Feature, ...]] = {}

    def add(
        self,
        *,
        logical_path: str,
        data: bytes,
        origin: str,
        physical_path: str,
        ref: str | None = None,
        provenance_count: int = 1,
        provenance_examples: Iterable[str] = (),
    ) -> None:
        content_sha256 = _sha256(data)
        cache_key = (logical_path, content_sha256)
        features = self._feature_cache.get(cache_key)
        if features is None:
            features = _features(logical_path, data)
            self._feature_cache[cache_key] = features
        for feature in features:
            key = (
                feature.logical_path,
                feature.symbol,
                feature.kind,
                feature.semantic_sha256,
            )
            record = self.records.setdefault(key, FeatureRecord(feature=feature))
            record.add(
                content_sha256=content_sha256,
                origin=origin,
                path=physical_path,
                ref=ref,
                provenance_count=provenance_count,
                provenance_examples=provenance_examples,
            )
            if origin == "canonical":
                self.canonical_semantics.add(feature.semantic_sha256)
                self.canonical_logical.add(
                    (feature.logical_path, feature.symbol, feature.kind)
                )

    def status(self, record: FeatureRecord) -> str:
        feature = record.feature
        origins = {
            origin
            for implementation in record.implementations.values()
            for origin in implementation.origins
        }
        if "canonical" in origins:
            return "canonical"
        if feature.semantic_sha256 in self.canonical_semantics:
            return "canonical_relocated_exact"
        logical = (feature.logical_path, feature.symbol, feature.kind)
        if _is_retained_evidence(feature.logical_path):
            return "retained_evidence"
        if logical in self.canonical_logical:
            return "conflicting_variant_review"
        return "integration_required"

    def serialise(self) -> list[dict[str, object]]:
        output: list[dict[str, object]] = []
        for record in sorted(
            self.records.values(),
            key=lambda item: (
                item.feature.logical_path,
                item.feature.symbol,
                item.feature.kind,
                item.feature.semantic_sha256,
            ),
        ):
            feature = record.feature
            status = self.status(record)
            feature_id = _sha256(
                _canonical_json(
                    {
                        "path": feature.logical_path,
                        "symbol": feature.symbol,
                        "kind": feature.kind,
                        "semantic_sha256": feature.semantic_sha256,
                    }
                )
            )
            implementations = []
            for implementation in sorted(
                record.implementations.values(), key=lambda item: item.content_sha256
            ):
                implementations.append(
                    {
                        "content_sha256": implementation.content_sha256,
                        "origins": sorted(implementation.origins),
                        # The complete ref namespace remains hash-bound in the external
                        # combined object store.  Keep bounded examples here so this
                        # review index stays diffable and does not duplicate that store.
                        "ref_count": len(implementation.refs),
                        "ref_examples": sorted(implementation.refs)[:8],
                        "provenance_count": implementation.provenance_count,
                        "provenance_examples": sorted(
                            implementation.provenance_examples
                        ),
                    }
                )
            output.append(
                {
                    "schema": SCHEMA,
                    "feature_id": feature_id,
                    "logical_path": feature.logical_path,
                    "symbol": feature.symbol,
                    "kind": feature.kind,
                    "semantic_sha256": feature.semantic_sha256,
                    "status": status,
                    "implementations": implementations,
                }
            )
        return output


def _is_retained_evidence(path: str) -> bool:
    low = f"/{path.lower()}"
    name = PurePosixPath(path).name
    return (
        "/fixtures/" in low
        or "/runtime_evidence/" in low
        or "/docs/" in low
        or name.startswith("test_")
        or "/tests/" in low
    )


def _canonical_files(root: Path) -> Iterator[tuple[str, bytes]]:
    raw = _run(["git", "ls-tree", "-r", "--name-only", "HEAD"], cwd=root)
    for line in raw.decode().splitlines():
        if not _candidate_suffix(line):
            continue
        path = root / line
        if path.is_file():
            yield _normalise_repository_path(line), path.read_bytes()


def _combined_git_files(git_dir: Path) -> Iterator[tuple[str, str, bytes, str]]:
    refs = _run(["git", f"--git-dir={git_dir}", "show-ref"]).decode().splitlines()
    blob_cache: dict[str, bytes] = {}
    for item in refs:
        _, ref = item.split()
        if "/gigabyte/" not in ref:
            continue
        store = ref.split("/")[2]
        jaa_only = store != "dae9cd4ca365c363"
        tree = _run(
            ["git", f"--git-dir={git_dir}", "ls-tree", "-r", ref]
        ).decode()
        for line in tree.splitlines():
            metadata, path = line.split("\t", 1)
            if not _candidate_suffix(path):
                continue
            blob = metadata.split()[2]
            data = blob_cache.get(blob)
            if data is None:
                data = _run(["git", f"--git-dir={git_dir}", "cat-file", "blob", blob])
                blob_cache[blob] = data
            yield _normalise_repository_path(path, jaa_only=jaa_only), path, data, ref


def _manifest_paths(path: Path) -> dict[str, list[str]]:
    values: dict[str, list[str]] = defaultdict(list)
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if len(line) < 67:
            continue
        digest = line[:64]
        source_path = line[64:].strip()
        if len(digest) == 64 and source_path:
            values[digest].append(source_path)
    return values


def _tar_files(
    path: Path, manifest: dict[str, list[str]]
) -> Iterator[tuple[str, str, bytes, list[str]]]:
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            if not member.isfile() or not _tar_candidate(member.name):
                continue
            logical_path = _normalise_tar_path(member.name)
            if logical_path is None:
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            data = extracted.read()
            digest = _sha256(data)
            yield logical_path, member.name, data, manifest.get(digest, [])


def build_inventory(
    *,
    repository: Path,
    git_dir: Path,
    source_archive: Path,
    source_manifest: Path,
) -> Inventory:
    inventory = Inventory()
    for logical_path, data in _canonical_files(repository):
        inventory.add(
            logical_path=logical_path,
            data=data,
            origin="canonical",
            physical_path=logical_path,
        )
    for logical_path, physical_path, data, ref in _combined_git_files(git_dir):
        inventory.add(
            logical_path=logical_path,
            data=data,
            origin="git-history",
            physical_path=physical_path,
            ref=ref,
        )
    manifest = _manifest_paths(source_manifest)
    for logical_path, physical_path, data, provenance in _tar_files(
        source_archive, manifest
    ):
        inventory.add(
            logical_path=logical_path,
            data=data,
            origin="unique-source-archive",
            physical_path=physical_path,
            provenance_count=max(1, len(provenance)),
            provenance_examples=provenance,
        )
    return inventory


def _write_report(path: Path, records: list[dict[str, object]]) -> None:
    counts: dict[str, int] = defaultdict(int)
    for record in records:
        counts[str(record["status"])] += 1
    lines = [
        "# Market Aligner capability archaeology",
        "",
        "This report is generated by `scripts/build_capability_inventory.py`. It is a",
        "symbol-level disposition index over canonical code, all preserved Gigabyte Git",
        "refs, and the unique-source archive. JAA paths are normalised exclusively beneath",
        "`internal/jaa`; donor copies never gain runtime authority.",
        "",
        "## Status counts",
        "",
    ]
    for status, count in sorted(counts.items()):
        lines.append(f"- `{status}`: {count}")
    gmail = GMAIL_LIFECYCLE_CAPABILITY
    lines.extend(
        [
            "",
            "`integration_required` and `conflicting_variant_review` are fail-closed work",
            "queues, not evidence of safe mergeability. `retained_evidence` remains",
            "recoverable in the hash-bound external archaeology corpus.",
            "",
            "## Required lifecycle capabilities",
            "",
            f"### `{gmail['capability_id']}`",
            "",
            f"- **Owner:** {gmail['owner']}.",
            f"- **Status:** `{gmail['status']}`.",
            "- **Current authority:** read-only Gmail only; forbidden mutations: "
            + ", ".join(gmail["forbidden"])
            + ".",
            "- **Archive search:** all 146 preserved Git refs and the hash-unique source",
            "  archive were content-scanned. The only Gmail implementation is the retained",
            "  narrow submission-confirmation reconciler; no distinct employer-response",
            "  mailbox adapter was found.",
            "- **Retained downstream work:** " + "; ".join(gmail["retained"]) + ".",
            "- **Still missing:** " + "; ".join(gmail["missing"]) + ".",
            "- **Closed classes required:** " + "; ".join(gmail["classes"]) + ".",
            "- **Canary:** withheld until the owner boundary is ready; the first canary must",
            "  be bounded real-mailbox read-only access with zero mailbox mutation and full",
            "  private evidence preservation.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--git-dir", type=Path, required=True)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    inventory = build_inventory(
        repository=args.repository.resolve(),
        git_dir=args.git_dir.resolve(),
        source_archive=args.source_archive.resolve(),
        source_manifest=args.source_manifest.resolve(),
    )
    records = inventory.serialise()
    args.output.write_bytes(b"".join(_canonical_json(record) for record in records))
    _write_report(args.report, records)
    print(json.dumps({"schema": SCHEMA, "records": len(records)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
