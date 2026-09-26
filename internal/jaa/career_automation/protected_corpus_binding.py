"""Deployment-owned binding for the read-only certified JAA-04 corpus.

The protected gate has no caller-selected corpus locator.  It reloads one
canonical, signed document from a compiled path whose file and ancestry are
root-owned.  The signed document binds the clean source, installed wheel,
complete protected tree, and filesystem identity.  The corpus itself is then
reverified before every protected read.

The public key below is deliberately deny-only in this programme checkout: no
matching signing key is present here.  A deployment integration must replace
the pin and provision the root-owned signed document together.  Until then the
protected gate is unavailable by design, not synthetically certified.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib.metadata
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .jaa04_corpus_authority import (
    CORPUS_DIRECTORY,
    CORPUS_IDENTITY,
    INVENTORY_FILES_SHA256,
    INVENTORY_SHA256,
    TRACKED_SEED_SHA256,
    CorpusAuthorityError,
    verify_graphcore_corpus,
)
from .market_aligner_handoff import HandoffContractError, decode_canonical_json


BINDING_SCHEMA_VERSION = "jaa.installed-protected-corpus-binding.v1"
PROTECTED_CORPUS_ENVIRONMENT = "production"
PROTECTED_CORPUS_ISSUER_ID = "gigabyte-deployment-protected-corpus-v1"
PROTECTED_CORPUS_TRUST_ROOT_ID = "gigabyte-jaa-protected-corpus-root-v1"
_COMPILED_BINDING_PATH = Path(
    "/etc/gigabyte/majaa/jaa-protected-corpus-v1.json"
)
PROTECTED_CORPUS_BINDING_PATH = _COMPILED_BINDING_PATH
_ACTIVE_BINDING_PATH = PROTECTED_CORPUS_BINDING_PATH
_COMPILED_VERIFIER_PUBLIC_KEY_B64 = (
    "FDK4wtZgR6g4vHOBcvnOe/A1Kpsw1j0cqo6ZSPS+KR4="
)
PROTECTED_CORPUS_VERIFIER_PUBLIC_KEY_B64 = (
    _COMPILED_VERIFIER_PUBLIC_KEY_B64
)
PROTECTED_CORPUS_VERIFIER_PUBLIC_KEY_SHA256 = (
    "f3bc90a1452d805d231dd9c66b72ab2f741c1b3a44be3b9d2c230bc7b9ad725b"
)
_MAX_BINDING_BYTES = 32_768
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
FORBIDDEN_RUNTIME_LOCATORS = (
    "JAA_CERTIFIED_CORPUS_ROOT",
    "JAA_CERTIFIED_CORPUS_BOOTSTRAP_SOURCE",
)

_PRODUCTION_PUBLIC_KEY = base64.b64decode(
    _COMPILED_VERIFIER_PUBLIC_KEY_B64,
    validate=True,
)
_PRODUCTION_VERIFIER = Ed25519PublicKey.from_public_bytes(
    _PRODUCTION_PUBLIC_KEY
)


class ProtectedCorpusBindingError(RuntimeError):
    """The deployment cannot prove its exact protected corpus binding."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> None:
    raise ProtectedCorpusBindingError(code, message)


def canonical_json_bytes(document: object, *, newline: bool = False) -> bytes:
    payload = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return payload + (b"\n" if newline else b"")


def installed_distribution_manifest(
    *, distribution_name: str = "job-application-automation", expected_version: str = "1.0.0"
) -> tuple[str, str]:
    """Return the exact installed version and RECORD-checked manifest hash."""

    try:
        distribution = importlib.metadata.distribution(
            distribution_name
        )
    except importlib.metadata.PackageNotFoundError as exc:
        raise ProtectedCorpusBindingError(
            "protected_installation_missing",
            "the installed JAA distribution is unavailable",
        ) from exc
    if distribution.version != expected_version:
        _fail(
            "protected_installation_version",
            "the installed JAA distribution version differs",
        )
    rows: list[dict[str, object]] = []
    for entry in sorted(distribution.files or (), key=str):
        installed = Path(distribution.locate_file(entry)).resolve()
        if not installed.is_file():
            _fail(
                "protected_installation_missing",
                "an installed JAA distribution file is unavailable",
            )
        value = installed.read_bytes()
        digest = hashlib.sha256(value).digest()
        rows.append(
            {
                "byte_length": len(value),
                "path": Path(str(entry)).as_posix(),
                "sha256": hashlib.sha256(value).hexdigest(),
            }
        )
        recorded = getattr(entry, "hash", None)
        if recorded is not None and recorded.mode == "sha256":
            encoded = (
                base64.urlsafe_b64encode(digest)
                .rstrip(b"=")
                .decode("ascii")
            )
            if encoded != recorded.value:
                _fail(
                    "protected_installation_tamper",
                    "the installed JAA distribution RECORD differs",
                )
    return (
        distribution.version,
        hashlib.sha256(canonical_json_bytes(rows)).hexdigest(),
    )


def _safe_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _root_identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": metadata.st_dev,
        "group": metadata.st_gid,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "mtime_ns": metadata.st_mtime_ns,
        "owner": metadata.st_uid,
    }


def _validate_root_owned_directory_chain(directory: Path) -> None:
    if not directory.is_absolute():
        _fail(
            "protected_binding_path",
            "the installed protected binding path is invalid",
        )
    current = Path("/")
    for component in directory.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ProtectedCorpusBindingError(
                "protected_binding_missing",
                "the installed protected binding is not provisioned",
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            _fail(
                "protected_binding_permissions",
                "the installed protected binding ancestry is not deployment-owned",
            )


def _read_installed_binding_bytes(
    path: Path,
    *,
    required_owner: int = 0,
) -> bytes:
    """Read one protected regular file without following a final symlink."""

    if not path.is_absolute():
        _fail(
            "protected_binding_path",
            "the installed protected binding path is invalid",
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ProtectedCorpusBindingError(
            "protected_binding_missing",
            "the installed protected binding is not provisioned",
        ) from exc
    except OSError as exc:
        raise ProtectedCorpusBindingError(
            "protected_binding_unsafe",
            "the installed protected binding cannot be opened safely",
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            _fail(
                "protected_binding_unsafe",
                "the installed protected binding is not a single regular file",
            )
        if metadata.st_uid != required_owner:
            _fail(
                "protected_binding_owner",
                "the installed protected binding owner is not trusted",
            )
        if mode & 0o137:
            _fail(
                "protected_binding_permissions",
                "the installed protected binding permissions are unsafe",
            )
        chunks: list[bytes] = []
        remaining = _MAX_BINDING_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_BINDING_BYTES:
            _fail(
                "protected_binding_size",
                "the installed protected binding exceeds its size limit",
            )
        return raw
    finally:
        os.close(descriptor)


def _lexical_directory(
    value: object,
    *,
    required_owner: int | None,
) -> Path:
    if type(value) is not str or not value or "\0" in value:
        _fail(
            "protected_corpus_locator",
            "the signed protected corpus locator is invalid",
        )
    root = Path(value)
    try:
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ProtectedCorpusBindingError(
            "protected_corpus_missing",
            "the signed protected corpus is unavailable",
        ) from exc
    if (
        not root.is_absolute()
        or Path(os.path.abspath(os.fspath(root))) != root
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or resolved != root
    ):
        _fail(
            "protected_corpus_locator",
            "the signed protected corpus locator is unsafe",
        )
    current = Path("/")
    for component in root.parts[1:]:
        current /= component
        try:
            ancestor = current.lstat()
        except OSError as exc:
            raise ProtectedCorpusBindingError(
                "protected_corpus_missing",
                "the signed protected corpus is unavailable",
            ) from exc
        if stat.S_ISLNK(ancestor.st_mode):
            _fail(
                "protected_corpus_locator",
                "the signed protected corpus ancestry contains a symlink",
            )
        if (
            required_owner is not None
            and (
                ancestor.st_uid != required_owner
                or stat.S_IMODE(ancestor.st_mode) & 0o022
            )
        ):
            _fail(
                "protected_corpus_permissions",
                "the signed protected corpus ancestry is not deployment-owned",
            )
    return root


def protected_corpus_tree_sha256(
    value: str | Path,
    *,
    required_owner: int | None = None,
) -> tuple[Path, str, dict[str, int]]:
    """Hash every path, byte, type and stable identity without echoing names."""

    root = _lexical_directory(str(value), required_owner=required_owner)
    try:
        root_before = root.lstat()
        paths = (
            root,
            *sorted(
                root.rglob("*"),
                key=lambda item: item.relative_to(root).as_posix(),
            ),
        )
        rows: list[dict[str, object]] = []
        for path in paths:
            relative = "." if path == root else path.relative_to(root).as_posix()
            before = path.lstat()
            if stat.S_ISLNK(before.st_mode):
                _fail(
                    "protected_corpus_symlink",
                    "the protected corpus contains a symlink",
                )
            if required_owner is not None and (
                before.st_uid != required_owner
                or stat.S_IMODE(before.st_mode) & 0o022
            ):
                _fail(
                    "protected_corpus_permissions",
                    "the protected corpus contains an unsafe filesystem object",
                )
            if stat.S_ISDIR(before.st_mode):
                kind = "directory"
                digest: str | None = None
            elif stat.S_ISREG(before.st_mode):
                kind = "file"
                hasher = hashlib.sha256()
                with path.open("rb") as stream:
                    for chunk in iter(
                        lambda: stream.read(1024 * 1024),
                        b"",
                    ):
                        hasher.update(chunk)
                digest = hasher.hexdigest()
            else:
                _fail(
                    "protected_corpus_object",
                    "the protected corpus contains an unsupported object",
                )
            after = path.lstat()
            if _safe_identity(before) != _safe_identity(after):
                _fail(
                    "protected_corpus_changed",
                    "the protected corpus changed while it was verified",
                )
            rows.append(
                {
                    "device": before.st_dev,
                    "group": before.st_gid,
                    "inode": before.st_ino,
                    "kind": kind,
                    "mode": stat.S_IMODE(before.st_mode),
                    "mtime_ns": before.st_mtime_ns,
                    "owner": before.st_uid,
                    "path": relative,
                    "sha256": digest,
                    "size": before.st_size,
                }
            )
        root_after = root.lstat()
    except ProtectedCorpusBindingError:
        raise
    except OSError as exc:
        raise ProtectedCorpusBindingError(
            "protected_corpus_unreadable",
            "the protected corpus could not be verified",
        ) from exc
    if _safe_identity(root_before) != _safe_identity(root_after):
        _fail(
            "protected_corpus_changed",
            "the protected corpus changed while it was verified",
        )
    payload = canonical_json_bytes(
        {
            "files": rows,
            "schema_version": "jaa.protected-corpus-tree.v1",
        }
    )
    return (
        root,
        hashlib.sha256(payload).hexdigest(),
        _root_identity(root_before),
    )


def _verify_signature(
    document: Mapping[str, Any],
    *,
    verifier: Ed25519PublicKey,
) -> None:
    unsigned = dict(document)
    encoded = unsigned.pop("signature_b64", None)
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise ProtectedCorpusBindingError(
            "protected_binding_signature",
            "the protected binding signature is malformed",
        ) from exc
    try:
        verifier.verify(signature, canonical_json_bytes(unsigned))
    except InvalidSignature as exc:
        raise ProtectedCorpusBindingError(
            "protected_binding_signature",
            "the protected binding signature is not trusted",
        ) from exc


def _parse_signed_binding(
    raw: bytes,
    *,
    verifier: Ed25519PublicKey,
    expected_public_key_b64: str,
) -> dict[str, object]:
    try:
        document = decode_canonical_json(
            raw,
            label="installed protected corpus binding",
            maximum_bytes=_MAX_BINDING_BYTES,
        )
    except HandoffContractError as exc:
        raise ProtectedCorpusBindingError(
            "protected_binding_malformed",
            "the installed protected binding is not canonical JSON",
        ) from exc
    expected_keys = {
        "corpus_identity",
        "corpus_root",
        "environment",
        "installed_manifest_sha256",
        "inventory_files_sha256",
        "inventory_sha256",
        "issuer_id",
        "root_identity",
        "schema_version",
        "signature_b64",
        "source_head",
        "source_tree",
        "tracked_seed_sha256",
        "tree_sha256",
        "trust_root_id",
        "verifier_public_key_b64",
    }
    if type(document) is not dict or set(document) != expected_keys:
        _fail(
            "protected_binding_malformed",
            "the installed protected binding fields differ",
        )
    if (
        document.get("schema_version") != BINDING_SCHEMA_VERSION
        or document.get("environment") != PROTECTED_CORPUS_ENVIRONMENT
        or document.get("issuer_id") != PROTECTED_CORPUS_ISSUER_ID
        or document.get("trust_root_id") != PROTECTED_CORPUS_TRUST_ROOT_ID
        or document.get("verifier_public_key_b64")
        != expected_public_key_b64
        or document.get("corpus_identity") != CORPUS_IDENTITY
        or document.get("inventory_sha256") != INVENTORY_SHA256
        or document.get("inventory_files_sha256")
        != INVENTORY_FILES_SHA256
        or document.get("tracked_seed_sha256") != TRACKED_SEED_SHA256
    ):
        _fail(
            "protected_binding_pins",
            "the installed protected binding differs from deployment pins",
        )
    for key in (
        "installed_manifest_sha256",
        "tree_sha256",
    ):
        if type(document.get(key)) is not str or not _SHA256.fullmatch(
            str(document[key])
        ):
            _fail(
                "protected_binding_malformed",
                "the installed protected binding contains an invalid digest",
            )
    for key in ("source_head", "source_tree"):
        if type(document.get(key)) is not str or not _GIT_OBJECT_ID.fullmatch(
            str(document[key])
        ):
            _fail(
                "protected_binding_malformed",
                "the installed protected binding contains an invalid source identity",
            )
    root_identity = document.get("root_identity")
    if (
        type(root_identity) is not dict
        or set(root_identity)
        != {"device", "group", "inode", "mode", "mtime_ns", "owner"}
        or any(type(value) is not int for value in root_identity.values())
    ):
        _fail(
            "protected_binding_malformed",
            "the installed protected binding root identity is invalid",
        )
    _verify_signature(document, verifier=verifier)
    return dict(document)


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        _fail(
            "protected_source_unavailable",
            "the protected gate source identity is unavailable",
        )
    return completed.stdout.strip()


def _source_identity(repository: Path) -> tuple[str, str]:
    if _git(repository, "status", "--porcelain", "--untracked-files=all"):
        _fail(
            "protected_source_dirty",
            "the protected gate requires an exact clean source head",
        )
    head = _git(repository, "rev-parse", "HEAD")
    tree = _git(repository, "rev-parse", "HEAD^{tree}")
    if not _GIT_OBJECT_ID.fullmatch(head) or not _GIT_OBJECT_ID.fullmatch(tree):
        _fail(
            "protected_source_identity",
            "the protected gate source identity is invalid",
        )
    return head, tree


def _validate_document_against_runtime(
    document: Mapping[str, object],
    *,
    repository: Path,
    source_head: str,
    source_tree: str,
    installed_manifest_sha256: str,
    required_owner: int | None,
) -> Path:
    if (
        document.get("source_head") != source_head
        or document.get("source_tree") != source_tree
        or document.get("installed_manifest_sha256")
        != installed_manifest_sha256
    ):
        _fail(
            "protected_binding_runtime",
            "the protected binding differs from the installed clean runtime",
        )
    root, tree_sha256, root_identity = protected_corpus_tree_sha256(
        str(document.get("corpus_root")),
        required_owner=required_owner,
    )
    if (
        root.name != CORPUS_DIRECTORY
        or document.get("tree_sha256") != tree_sha256
        or document.get("root_identity") != root_identity
    ):
        _fail(
            "protected_binding_tree",
            "the protected binding differs from the current protected tree",
        )
    try:
        authority = verify_graphcore_corpus(
            root,
            repository / "career_automation/fixtures/jaa04_admitted_queue.json",
        )
    except (CorpusAuthorityError, OSError) as exc:
        raise ProtectedCorpusBindingError(
            "protected_corpus_authority",
            "the protected corpus failed exact authority verification",
        ) from exc
    if (
        authority.corpus_root != root
        or authority.corpus_identity != CORPUS_IDENTITY
        or authority.inventory_sha256 != INVENTORY_SHA256
        or authority.inventory_files_sha256 != INVENTORY_FILES_SHA256
    ):
        _fail(
            "protected_corpus_authority",
            "the protected corpus authority binding differs",
        )
    return root


def _safe_projection(
    document: Mapping[str, object],
    *,
    raw: bytes,
) -> dict[str, object]:
    return {
        "binding_sha256": hashlib.sha256(raw).hexdigest(),
        "corpus_identity": CORPUS_IDENTITY,
        "environment": PROTECTED_CORPUS_ENVIRONMENT,
        "installed_manifest_sha256": document["installed_manifest_sha256"],
        "issuer_id": PROTECTED_CORPUS_ISSUER_ID,
        "schema_version": BINDING_SCHEMA_VERSION,
        "source_head": document["source_head"],
        "source_tree": document["source_tree"],
        "tree_sha256": document["tree_sha256"],
        "trust_root_id": PROTECTED_CORPUS_TRUST_ROOT_ID,
        "verifier_public_key_sha256": (
            PROTECTED_CORPUS_VERIFIER_PUBLIC_KEY_SHA256
        ),
    }


def load_installed_protected_corpus_binding(
    repository_root: str | Path,
) -> tuple[Path, dict[str, object]]:
    """Reload and verify the sole deployment-owned binding and exact corpus."""

    if any(key in os.environ for key in FORBIDDEN_RUNTIME_LOCATORS):
        _fail(
            "protected_locator_forbidden",
            "the protected gate refuses caller-selected corpus locators",
        )
    if _ACTIVE_BINDING_PATH != _COMPILED_BINDING_PATH:
        _fail(
            "protected_binding_path",
            "the installed protected binding path differs from the compiled pin",
        )
    repository = Path(repository_root).resolve(strict=True)
    source_head, source_tree = _source_identity(repository)
    _version, installed_manifest_sha256 = installed_distribution_manifest()
    _validate_root_owned_directory_chain(_COMPILED_BINDING_PATH.parent)
    raw = _read_installed_binding_bytes(_COMPILED_BINDING_PATH)
    document = _parse_signed_binding(
        raw,
        verifier=_PRODUCTION_VERIFIER,
        expected_public_key_b64=_COMPILED_VERIFIER_PUBLIC_KEY_B64,
    )
    root = _validate_document_against_runtime(
        document,
        repository=repository,
        source_head=source_head,
        source_tree=source_tree,
        installed_manifest_sha256=installed_manifest_sha256,
        required_owner=0,
    )
    return root, _safe_projection(document, raw=raw)


__all__ = [
    "BINDING_SCHEMA_VERSION",
    "FORBIDDEN_RUNTIME_LOCATORS",
    "PROTECTED_CORPUS_BINDING_PATH",
    "PROTECTED_CORPUS_ENVIRONMENT",
    "PROTECTED_CORPUS_ISSUER_ID",
    "PROTECTED_CORPUS_TRUST_ROOT_ID",
    "PROTECTED_CORPUS_VERIFIER_PUBLIC_KEY_B64",
    "PROTECTED_CORPUS_VERIFIER_PUBLIC_KEY_SHA256",
    "ProtectedCorpusBindingError",
    "canonical_json_bytes",
    "installed_distribution_manifest",
    "load_installed_protected_corpus_binding",
    "protected_corpus_tree_sha256",
]
