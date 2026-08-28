"""Owned, read-only capture boundary for Greenhouse provider semantics.

The production factory consumes the receipt written here.  It never accepts a
caller-built observation as capture authority.  The collector performs a GET,
records the browser-visible and transport bytes, and performs no form or submit
interaction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Mapping
from urllib.parse import urlsplit

from .application_archive import ApplicationArchive, VacancyArchiveIdentity
from .evidence_matching import canonical_json
from tracked_source_revision import source_content_revision


COLLECTOR_IDENTITY = "jaa.playwright-greenhouse-read-only-observer.v4"
COLLECTOR_SOURCE_PATH = "career_automation/provider_observation_capture.py"
_GREENHOUSE_HOSTS = frozenset(
    {
        "boards.greenhouse.io",
        "job-boards.greenhouse.io",
        "job-boards.eu.greenhouse.io",
    }
)
_SENSITIVE_VALUE = re.compile(
    r'(?i)("[^"\\]*(?:token|secret|password|passwd|cookie|csrf|xsrf|api[_-]?key)'
    r'[^"\\]*"\s*:\s*)"(?:\\.|[^"\\])*"'
)
_SENSITIVE_HIDDEN_INPUT = re.compile(
    rb'(?is)(<input\b(?=[^>]*\btype\s*=\s*["\']?hidden["\']?)[^>]*\bvalue\s*=\s*)'
    rb'(["\'])(?:.|\n)*?\2'
)
_SENSITIVE_HIDDEN_INPUT_UNQUOTED = re.compile(
    rb"(?is)(<input\b(?=[^>]*\btype\s*=\s*[\"']?hidden[\"']?)[^>]*"
    rb"\bvalue\s*=\s*)(?![\"'])([^\s>]+)"
)
_BEARER_VALUE = re.compile(rb"(?i)\bbearer\s+[a-z0-9._~+/=-]+")
_BASIC_VALUE = re.compile(rb"(?i)\bbasic\s+[a-z0-9+/=]+")
_PLAIN_SECRET_VALUE = re.compile(
    rb"(?i)\b(password|passwd|csrf|xsrf|access[_ -]?token|api[_ -]?key)"
    rb"\s*[:=]\s*([^\s<>,;]+)"
)
_UNSAFE_AFTER_REDACTION = (
    _SENSITIVE_VALUE,
    _SENSITIVE_HIDDEN_INPUT,
    _SENSITIVE_HIDDEN_INPUT_UNQUOTED,
    _BEARER_VALUE,
    _BASIC_VALUE,
    _PLAIN_SECRET_VALUE,
)


def _bytes(document: Mapping[str, object]) -> bytes:
    return (canonical_json(document) + "\n").encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(repository_root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repository_root), *arguments],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ValueError("provider observer requires an exact Git repository")
    return completed.stdout


def exact_clean_head(repository_root: str | Path) -> str:
    """Return HEAD only when every non-ignored worktree byte is committed."""
    root = Path(repository_root).resolve(strict=True)
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("provider observer requires an exact clean HEAD")
    head = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("provider observer HEAD identity is invalid")
    return head


@dataclass(frozen=True)
class CommittedSourceIdentity:
    repository_root: Path
    source_root: Path
    repository_prefix: str
    head: str
    tree: str
    content_revision: str


def exact_committed_source_identity(
    source_root: str | Path,
) -> CommittedSourceIdentity:
    """Resolve a clean committed source subtree without assuming it owns `.git`."""
    source = Path(source_root).resolve(strict=True)
    if not source.is_dir():
        raise ValueError("committed source root must be a directory")
    head = exact_clean_head(source)
    top_level_text = _git(source, "rev-parse", "--show-toplevel").decode().strip()
    prefix = _git(source, "rev-parse", "--show-prefix").decode().strip()
    try:
        repository = Path(top_level_text).resolve(strict=True)
    except OSError as exc:
        raise ValueError("committed source repository root is unavailable") from exc
    if repository != source and repository not in source.parents:
        raise ValueError("committed source repository root escapes the source path")
    pure_prefix = PurePosixPath(prefix)
    if (
        (prefix and not prefix.endswith("/"))
        or pure_prefix.is_absolute()
        or any(part in {"", ".", ".."} for part in pure_prefix.parts)
    ):
        raise ValueError("committed source repository prefix is unsafe")
    projected = repository.joinpath(*pure_prefix.parts).resolve(strict=True)
    if projected != source:
        raise ValueError("committed source repository prefix is ambiguous")
    markers = [
        parent / ".git"
        for parent in (source, *source.parents)
        if (parent / ".git").exists() or (parent / ".git").is_symlink()
    ]
    if markers != [repository / ".git"]:
        raise ValueError("nested or ambiguous Git repositories are forbidden")
    marker = markers[0]
    if marker.is_symlink() or not (marker.is_file() or marker.is_dir()):
        raise ValueError("committed source Git metadata is unsafe")
    tree = _git(source, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise ValueError("committed source tree identity is invalid")
    return CommittedSourceIdentity(
        repository,
        source,
        prefix,
        head,
        tree,
        source_content_revision(source),
    )


def collector_source_identity(
    repository_root: str | Path, *, commit: str = "HEAD"
) -> tuple[bytes, str]:
    root = Path(repository_root).resolve(strict=True)
    identity = exact_committed_source_identity(root)
    selected = identity.head if commit == "HEAD" else commit
    if selected != identity.head:
        raise ValueError("provider observer source commit differs from exact HEAD")
    source = _git(
        root,
        "show",
        f"{selected}:{identity.repository_prefix}{COLLECTOR_SOURCE_PATH}",
    )
    if source != (root / COLLECTOR_SOURCE_PATH).read_bytes():
        raise ValueError("provider observer source differs from exact clean HEAD")
    return source, _sha256(source)


def _write_create_only(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("provider observation archive path must not be a symlink")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError:
        if path.read_bytes() != value:
            raise ValueError("content-addressed provider observation object differs")
        return
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _archive_object(root: Path, value: bytes) -> str:
    digest = _sha256(value)
    _write_create_only(root / "objects" / digest[:2] / digest, value)
    return digest


@dataclass(frozen=True)
class ProviderObservationCaptureReceipt:
    manifest_sha256: str
    manifest_path: Path
    observation_sha256: str
    observation: bytes
    observed_at: str
    source_url: str
    form_inventory_sha256: str | None = None
    form_inventory: bytes | None = None
    acceptance_receipt_sha256: str | None = None


class ProviderObservationCaptureFailure(RuntimeError):
    """A read-only capture failed after its exact evidence was archived."""

    def __init__(
        self,
        message: str,
        *,
        receipt: ProviderObservationCaptureReceipt,
    ) -> None:
        self.receipt = receipt
        super().__init__(
            f"{message}; archived capture manifest {receipt.manifest_sha256}"
        )


def _redact_sensitive_response(value: bytes) -> bytes:
    text = value.decode("utf-8", errors="replace")
    redacted = _SENSITIVE_VALUE.sub(r'\1"[REDACTED]"', text).encode("utf-8")
    redacted = _SENSITIVE_HIDDEN_INPUT.sub(rb'\1\2[REDACTED]\2', redacted)
    redacted = _SENSITIVE_HIDDEN_INPUT_UNQUOTED.sub(
        rb"\1[REDACTED]", redacted
    )
    redacted = _BEARER_VALUE.sub(b"Bearer [REDACTED]", redacted)
    redacted = _BASIC_VALUE.sub(b"Basic [REDACTED]", redacted)
    redacted = _PLAIN_SECRET_VALUE.sub(rb"\1: [REDACTED]", redacted)
    for pattern in _UNSAFE_AFTER_REDACTION:
        target = (
            redacted.decode("utf-8", errors="replace")
            if isinstance(pattern.pattern, str)
            else redacted
        )
        unsafe = pattern.search(target)
        matched = unsafe.group(0) if unsafe else b""
        if unsafe and "[REDACTED]" not in (
            matched if isinstance(matched, str) else matched.decode(errors="replace")
        ):
            raise ValueError("provider response redaction did not remove a secret")
    return redacted


def _failure_observation(
    *,
    source_url: str,
    observed_at: str,
    code: str,
    status: int | None,
    final_url: str | None = None,
    acceptance_receipt_sha256: str | None = None,
) -> bytes:
    return _bytes(
        {
            "schema_version": "jaa.greenhouse-nonconsequential-canary-failure.v1",
            "provider": "greenhouse",
            "observed_at": observed_at,
            "request": {
                "method": "GET",
                "status": status,
                "url": source_url,
                "final_url": final_url,
            },
            "failure": {"code": code},
            "operator_acceptance_receipt_sha256": acceptance_receipt_sha256,
            "interaction": {
                "fields_filled": 0,
                "files_uploaded": 0,
                "submit_clicks": 0,
            },
        }
    )


def _persist_failure(
    *,
    archive_root: str | Path,
    repository_root: str | Path,
    source_url: str,
    observed_at: str,
    code: str,
    status: int | None,
    final_url: str | None,
    primary_response: bytes,
    visible_content: bytes,
    network: list[dict[str, object]],
    screenshot: bytes | None,
    screenshot_safety: bytes | None = None,
    form_inventory: bytes | None = None,
    operator_acceptance: Mapping[str, object] | None = None,
) -> ProviderObservationCaptureFailure:
    receipt = _persist_capture(
        archive_root=archive_root,
        repository_root=repository_root,
        source_url=source_url,
        observed_at=observed_at,
        observation=_failure_observation(
            source_url=source_url,
            observed_at=observed_at,
            code=code,
            status=status,
            final_url=final_url,
            acceptance_receipt_sha256=(
                str(operator_acceptance["receipt_sha256"])
                if operator_acceptance is not None
                else None
            ),
        ),
        primary_response=primary_response or b"[unavailable]\n",
        visible_content=visible_content or b"[unavailable]\n",
        network_events=_bytes(
            {
                "schema_version": "jaa.provider-observation-network.v1",
                "events": network,
            }
        ),
        screenshot=screenshot,
        screenshot_safety=screenshot_safety,
        form_inventory=form_inventory,
        form_inventory_unavailable_reason=(
            None if form_inventory is not None else code
        ),
        operator_acceptance=operator_acceptance,
    )
    _terminalize_capture_failure(
        receipt,
        archive_root=archive_root,
        repository_root=repository_root,
        source_url=source_url,
        code=code,
        primary_response=primary_response,
    )
    return ProviderObservationCaptureFailure(code, receipt=receipt)


def _terminalize_capture_failure(
    receipt: ProviderObservationCaptureReceipt,
    *,
    archive_root: str | Path,
    repository_root: str | Path,
    source_url: str,
    code: str,
    primary_response: bytes,
) -> None:
    """Link every failed capture to an append-only terminal JAA attempt."""
    parsed = urlsplit(source_url)
    vacancy_id = parsed.path.rstrip("/").rsplit("/", 1)[-1]
    capture_manifest = receipt.manifest_path.read_bytes()
    vacancy = VacancyArchiveIdentity(
        job_key=f"greenhouse:{parsed.hostname}:{vacancy_id}",
        vacancy_sha256=_sha256(primary_response or capture_manifest),
        role_title="Provider observation canary",
        company_name=parsed.path.strip("/").split("/", 1)[0] or "Greenhouse",
        source_url=source_url,
    )
    archive = ApplicationArchive(archive_root, repository_root=repository_root)
    attempt = archive.create_attempt(vacancy)
    source = attempt.add_artifact(
        "vacancy.source_identity",
        _bytes(vacancy.document()),
        media_type="application/json",
        disposition="observed",
    )
    capture = attempt.add_artifact(
        "vacancy.capture",
        primary_response or b"[unavailable]\n",
        media_type="text/html",
        disposition="observed",
    )
    provider_receipt = attempt.add_artifact(
        "provider.capture_failure_receipt",
        capture_manifest,
        media_type="application/json",
        disposition="observed",
    )
    result = attempt.add_artifact(
        "submission.result",
        _bytes(
            {
                "state": "abandoned",
                "phase": "before_click_intent",
                "reason_code": code,
                "click_intent_recorded": False,
                "click_may_have_occurred": False,
                "submit_clicks": 0,
            }
        ),
        media_type="application/json",
        disposition="rejected",
    )
    terminal_sha256 = attempt.finalize_terminal(
        outcome="abandoned",
        selected={
            source.role: source.sha256,
            capture.role: capture.sha256,
            provider_receipt.role: provider_receipt.sha256,
            result.role: result.sha256,
        },
    )
    link = _bytes(
        {
            "schema_version": "jaa.provider-capture-terminal-link.v1",
            "capture_manifest_sha256": receipt.manifest_sha256,
            "attempt_id": attempt.attempt_id,
            "terminal_manifest_sha256": terminal_sha256,
        }
    )
    _write_create_only(
        Path(archive_root).resolve(strict=True)
        / "provider-observation-captures"
        / f"{receipt.manifest_sha256}.terminal.json",
        link,
    )


def _persist_capture(
    *,
    archive_root: str | Path,
    repository_root: str | Path,
    source_url: str,
    observed_at: str,
    observation: bytes,
    primary_response: bytes,
    visible_content: bytes,
    network_events: bytes,
    screenshot: bytes | None,
    screenshot_safety: bytes | None = None,
    form_inventory: bytes | None = None,
    form_inventory_unavailable_reason: str | None = None,
    operator_acceptance: Mapping[str, object] | None = None,
) -> ProviderObservationCaptureReceipt:
    """Persist an owned capture as create-only content-addressed objects."""
    root = Path(archive_root).resolve(strict=True)
    repository = Path(repository_root).resolve(strict=True)
    source_identity = exact_committed_source_identity(repository)
    head = source_identity.head
    source, source_sha256 = collector_source_identity(
        repository, commit=source_identity.head
    )
    if source != Path(__file__).read_bytes():
        raise ValueError("running provider observer differs from exact HEAD")
    if operator_acceptance is not None and any(
        operator_acceptance.get(key) != value
        for key, value in {
            "source_url": source_url,
            "repository_commit": head,
            "repository_tree": source_identity.tree,
            "collector_source_sha256": source_sha256,
        }.items()
    ):
        raise ValueError("provider observation acceptance differs at publication")
    parsed = urlsplit(source_url)
    if parsed.scheme != "https" or parsed.hostname not in _GREENHOUSE_HOSTS:
        raise ValueError("provider observer only accepts canonical Greenhouse HTTPS")
    match = re.search(r"(?:^|/)jobs/(\d+)(?:/|$)", parsed.path)
    if match is None or parsed.query or parsed.fragment:
        raise ValueError("provider observer source URL lacks a canonical vacancy ID")
    try:
        stamp = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("provider observer time is invalid") from exc
    if stamp.tzinfo is None:
        raise ValueError("provider observer time must be timezone-aware")
    artifacts = {
        "network_events": _archive_object(root, network_events),
        "observation": _archive_object(root, observation),
        "primary_response": _archive_object(root, primary_response),
        "visible_content": _archive_object(root, visible_content),
    }
    if screenshot is not None:
        if screenshot_safety is None:
            raise ValueError("provider screenshot requires a masking proof")
        artifacts["screenshot"] = _archive_object(root, screenshot)
        artifacts["screenshot_safety"] = _archive_object(root, screenshot_safety)
    elif screenshot_safety is not None:
        artifacts["screenshot_safety"] = _archive_object(root, screenshot_safety)
    if form_inventory is not None:
        artifacts["form_inventory"] = _archive_object(root, form_inventory)
    manifest = {
        "schema_version": "jaa.provider-observation-capture.v1",
        "capture_mode": "production_live",
        "collector_identity": COLLECTOR_IDENTITY,
        "collector_source_path": COLLECTOR_SOURCE_PATH,
        "collector_source_sha256": source_sha256,
        "repository_commit": head,
        "repository_tree": source_identity.tree,
        "source_content_revision": source_identity.content_revision,
        "provider": "greenhouse",
        "source_url": source_url,
        "vacancy_id": match.group(1),
        "observed_at": stamp.astimezone(timezone.utc).isoformat(),
        "interaction": {
            "fields_filled": 0,
            "files_uploaded": 0,
            "submit_clicks": 0,
        },
        "artifacts": artifacts,
        "form_inventory": {
            "availability": (
                "captured" if form_inventory is not None else "unavailable"
            ),
            "reason": (
                None
                if form_inventory is not None
                else form_inventory_unavailable_reason
            ),
            "sha256": artifacts.get("form_inventory"),
        },
    }
    if operator_acceptance is not None:
        receipt_sha256 = operator_acceptance.get("receipt_sha256")
        if not isinstance(receipt_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", receipt_sha256
        ):
            raise ValueError("provider observation acceptance receipt identity is invalid")
        manifest["operator_acceptance"] = dict(operator_acceptance)
    value = _bytes(manifest)
    digest = _archive_object(root, value)
    manifest_path = root / "provider-observation-captures" / f"{digest}.json"
    _write_create_only(manifest_path, value)
    return ProviderObservationCaptureReceipt(
        manifest_sha256=digest,
        manifest_path=manifest_path,
        observation_sha256=artifacts["observation"],
        observation=observation,
        observed_at=str(manifest["observed_at"]),
        source_url=source_url,
        form_inventory_sha256=artifacts.get("form_inventory"),
        form_inventory=form_inventory,
        acceptance_receipt_sha256=(
            str(operator_acceptance["receipt_sha256"])
            if operator_acceptance is not None
            else None
        ),
    )


def _extract_loader_value(html: str, key: str) -> str:
    patterns = (
        rf'"{re.escape(key)}"\s*:\s*"((?:\\.|[^"\\])*)"',
        rf"'{re.escape(key)}'\s*:\s*'((?:\\.|[^'\\])*)'",
    )
    for pattern in patterns:
        match = re.search(pattern, html)
        if match:
            raw = match.group(1)
            try:
                return json.loads(f'"{raw}"')
            except json.JSONDecodeError:
                return raw.replace("\\/", "/")
    raise ValueError(f"Greenhouse loader did not expose {key}")


def load_provider_observation_capture(
    *, archive_root: str | Path, manifest_sha256: str
) -> dict[str, object]:
    """Resolve one capture in place and return sanitized metadata only."""
    if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
        raise ValueError("provider capture manifest hash is invalid")
    root = Path(archive_root).resolve(strict=True)
    manifest_path = (
        root / "provider-observation-captures" / f"{manifest_sha256}.json"
    )
    if manifest_path.is_symlink():
        raise ValueError("provider capture manifest path is unsafe")
    raw = manifest_path.read_bytes()
    if _sha256(raw) != manifest_sha256:
        raise ValueError("provider capture manifest hash differs")
    manifest = json.loads(raw)
    if not isinstance(manifest, dict) or raw != _bytes(manifest):
        raise ValueError("provider capture manifest is not canonical")
    if manifest.get("schema_version") != "jaa.provider-observation-capture.v1":
        raise ValueError("provider capture manifest schema is unsupported")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("provider capture artifacts are malformed")
    rows: dict[str, dict[str, object]] = {}
    resolved: dict[str, bytes] = {}
    for role, digest in sorted(artifacts.items()):
        if (
            not isinstance(role, str)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ValueError("provider capture artifact identity is malformed")
        path = root / "objects" / digest[:2] / digest
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("provider capture artifact path is unsafe")
        value = path.read_bytes()
        if _sha256(value) != digest:
            raise ValueError("provider capture artifact hash differs")
        resolved[role] = value
        rows[role] = {"sha256": digest, "byte_length": len(value)}
    observation = json.loads(resolved["observation"])
    failure = observation.get("failure") if isinstance(observation, dict) else None
    inventory = manifest.get("form_inventory")
    if not isinstance(inventory, dict):
        inventory = {
            "availability": (
                "captured" if "form_inventory" in artifacts else "unavailable"
            ),
            "reason": (
                failure.get("code")
                if isinstance(failure, dict)
                else "not_preserved"
            ),
            "sha256": artifacts.get("form_inventory"),
        }
    form_summary: dict[str, object] = dict(inventory)
    if "form_inventory" in resolved:
        form_document = json.loads(resolved["form_inventory"])
        state = (
            form_document.get("form_state", {})
            if isinstance(form_document, dict)
            else {}
        )
        fields = state.get("fields", []) if isinstance(state, dict) else []
        form_summary["field_count"] = len(fields) if isinstance(fields, list) else 0
    acceptance = manifest.get("operator_acceptance")
    tree = manifest.get("repository_tree")
    if tree is None and isinstance(acceptance, dict):
        tree = acceptance.get("repository_tree")
    return {
        "schema_version": "jaa.provider-observation-view.v1",
        "manifest_sha256": manifest_sha256,
        "provider": manifest.get("provider"),
        "source_url": manifest.get("source_url"),
        "observed_at": manifest.get("observed_at"),
        "repository_commit": manifest.get("repository_commit"),
        "repository_tree": tree,
        "source_content_revision": manifest.get("source_content_revision"),
        "interaction": manifest.get("interaction"),
        "outcome": (
            failure.get("code") if isinstance(failure, dict) else "observed"
        ),
        "form_inventory": form_summary,
        "operator_acceptance": (
            dict(acceptance) if isinstance(acceptance, dict) else None
        ),
        "artifacts": rows,
    }


def render_provider_observation_capture(
    *, archive_root: str | Path, manifest_sha256: str
) -> str:
    view = load_provider_observation_capture(
        archive_root=archive_root, manifest_sha256=manifest_sha256
    )
    inventory = view["form_inventory"]
    lines = [
        f"Provider observation: {view['manifest_sha256']}",
        f"Target: {view['source_url']}",
        f"Outcome: {view['outcome']}",
        f"Observed: {view['observed_at']}",
        f"Form inventory: {inventory['availability']}",
    ]
    if inventory.get("reason"):
        lines.append(f"Form inventory reason: {inventory['reason']}")
    if "field_count" in inventory:
        lines.append(f"Observed fields: {inventory['field_count']}")
    acceptance = view["operator_acceptance"]
    if isinstance(acceptance, dict):
        lines.extend(
            [
                f"Acceptance: {acceptance.get('acceptance_id')}",
                f"Acceptance receipt: {acceptance.get('receipt_sha256')}",
                f"Acceptance envelope: {acceptance.get('envelope_sha256')}",
                f"Acceptance key: {acceptance.get('key_id')}",
                f"Acceptance consumed: {acceptance.get('consumed_at')}",
            ]
        )
    lines.append("Artifacts:")
    for role, row in sorted(view["artifacts"].items()):
        lines.append(
            f"- {role} {row['sha256']} ({row['byte_length']} bytes)"
        )
    return "\n".join(lines) + "\n"


def _capture_preflight(
    source_url: str, repository_root: str | Path
) -> tuple[str, str, str]:
    repository = Path(repository_root).resolve(strict=True)
    identity = exact_committed_source_identity(repository)
    source, source_sha256 = collector_source_identity(
        repository, commit=identity.head
    )
    if source != Path(__file__).read_bytes():
        raise ValueError("running provider observer differs from exact HEAD")
    parsed = urlsplit(source_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in _GREENHOUSE_HOSTS
        or re.search(r"(?:^|/)jobs/(\d+)(?:/|$)", parsed.path) is None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("provider observer source URL is not canonical Greenhouse HTTPS")
    return identity.head, identity.tree, source_sha256


def _mask_page_for_screenshot(page: object) -> bytes:
    proof = page.evaluate(  # type: ignore[attr-defined]
        """() => {
            let clearedInputs = 0;
            for (const element of document.querySelectorAll('input, textarea')) {
                if ('value' in element && element.value) clearedInputs += 1;
                if ('value' in element) element.value = '';
                element.removeAttribute('value');
            }
            const opaque = document.querySelectorAll('img, svg, canvas, video, iframe');
            const opaqueMediaRemoved = opaque.length;
            opaque.forEach((element) => element.remove());
            let redactedTextNodes = 0;
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
            const nodes = [];
            while (walker.nextNode()) nodes.push(walker.currentNode);
            const secret = /(password|passwd|csrf|xsrf|access[_ -]?token|api[_ -]?key|authorization)\\s*[:=]\\s*\\S+/ig;
            for (const node of nodes) {
                const replacement = node.nodeValue.replace(secret, '$1: [REDACTED]');
                if (replacement !== node.nodeValue) redactedTextNodes += 1;
                node.nodeValue = replacement;
            }
            return {clearedInputs, opaqueMediaRemoved, redactedTextNodes};
        }"""
    )
    if not isinstance(proof, Mapping):
        raise ValueError("provider screenshot masking proof is malformed")
    return _bytes(
        {
            "schema_version": "jaa.provider-screenshot-masking-proof.v1",
            "input_values_cleared": int(proof.get("clearedInputs", 0)),
            "opaque_media_removed": int(proof.get("opaqueMediaRemoved", 0)),
            "secret_text_nodes_redacted": int(proof.get("redactedTextNodes", 0)),
            "policy": "clear-fields-remove-opaque-media-redact-labelled-secrets",
        }
    )


def capture_greenhouse_observation(
    *,
    source_url: str,
    archive_root: str | Path,
    repository_root: str | Path,
    job_key: str,
    acceptance_envelope_path: str | Path,
    operator_public_key_path: str | Path,
    timeout_ms: int = 30_000,
) -> ProviderObservationCaptureReceipt:
    """Navigate read-only and capture provider-owned success semantics."""
    repository_commit, repository_tree, collector_source_sha256 = _capture_preflight(
        source_url, repository_root
    )
    match = re.search(r"(?:^|/)jobs/(\d+)(?:/|$)", urlsplit(source_url).path)
    assert match is not None
    from .provider_observation_authority import (
        verify_and_consume_provider_observation_acceptance,
    )

    acceptance_receipt, acceptance_created = (
        verify_and_consume_provider_observation_acceptance(
            envelope_path=acceptance_envelope_path,
            public_key_path=operator_public_key_path,
            archive_root=archive_root,
            job_key=job_key,
            source_url=source_url,
            source_job_id=match.group(1),
            timeout_ms=timeout_ms,
            repository_commit=repository_commit,
            repository_tree=repository_tree,
            collector_source_sha256=collector_source_sha256,
        )
    )
    if not acceptance_created:
        raise ValueError(
            "provider observation acceptance was already consumed; protected navigation will not retry"
        )
    operator_acceptance = acceptance_receipt.document()
    # Import lazily so verification users do not require the browser extra.
    from playwright.sync_api import sync_playwright

    network: list[dict[str, object]] = []
    primary_body = b""
    visible_content = b""
    screenshot: bytes | None = None
    screenshot_safety: bytes | None = None
    form_inventory: bytes | None = None
    final_url: str | None = None
    response_status: int | None = None
    observed_at = datetime.now(timezone.utc).isoformat()
    browser = None
    stage = "playwright_start"
    try:
        with sync_playwright() as playwright:
            stage = "browser_launch"
            browser = playwright.chromium.launch(headless=True)
            stage = "page_create"
            page = browser.new_page()

            def record(response: object) -> None:
                request = response.request
                if request.resource_type not in {"document", "xhr", "fetch", "script"}:
                    return
                parsed_url = urlsplit(response.url)
                network.append(
                    {
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "status": response.status,
                        "url": f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}",
                    }
                )

            page.on("response", record)
            stage = "navigation"
            response = page.goto(
                source_url, wait_until="domcontentloaded", timeout=timeout_ms
            )
            response_status = response.status if response is not None else None
            if response is not None:
                stage = "response_body_read"
                primary_body = _redact_sensitive_response(response.body())
            stage = "hydration_wait"
            page.wait_for_timeout(750)
            stage = "visible_text_read"
            visible_content = _redact_sensitive_response(
                page.locator("body").inner_text().encode("utf-8")
            )
            stage = "screenshot_masking"
            screenshot_safety = _mask_page_for_screenshot(page)
            stage = "screenshot_capture"
            screenshot = page.screenshot(full_page=True)
            stage = "form_inventory"
            from .production_ats_executor import collect_greenhouse_form_inventory

            form_inventory = collect_greenhouse_form_inventory(page)
            final_url = page.url
            stage = "browser_close"
            browser.close()
    except Exception as exc:
        if browser is not None and stage != "browser_close":
            try:
                browser.close()
            except Exception:
                pass
        raise _persist_failure(
            archive_root=archive_root,
            repository_root=repository_root,
            source_url=source_url,
            observed_at=observed_at,
            code=f"provider_{stage}_failed",
            status=response_status,
            final_url=final_url,
            primary_response=primary_body,
            visible_content=visible_content,
            network=network,
            screenshot=screenshot,
            screenshot_safety=screenshot_safety,
            form_inventory=form_inventory,
            operator_acceptance=operator_acceptance,
        ) from exc
    if response_status is None or not 200 <= response_status < 300:
        raise _persist_failure(
            archive_root=archive_root,
            repository_root=repository_root,
            source_url=source_url,
            observed_at=observed_at,
            code="provider_http_status_failed",
            status=response_status,
            final_url=final_url,
            primary_response=primary_body,
            visible_content=visible_content,
            network=network,
            screenshot=screenshot,
            screenshot_safety=screenshot_safety,
            form_inventory=form_inventory,
            operator_acceptance=operator_acceptance,
        )
    if final_url.rstrip("/") != source_url.rstrip("/"):
        raise _persist_failure(
            archive_root=archive_root,
            repository_root=repository_root,
            source_url=source_url,
            observed_at=observed_at,
            code="provider_route_changed",
            status=response_status,
            final_url=final_url,
            primary_response=primary_body,
            visible_content=visible_content,
            network=network,
            screenshot=screenshot,
            screenshot_safety=screenshot_safety,
            form_inventory=form_inventory,
            operator_acceptance=operator_acceptance,
        )
    # The current Greenhouse renderer removes its loader script after hydration.
    # Resolve provider-owned submit semantics from the exact redacted document
    # response, not from mutable post-hydration DOM HTML.
    loader_source = primary_body.decode("utf-8", errors="replace")
    try:
        confirmation_path = _extract_loader_value(
            loader_source, "confirmationPath"
        )
        submit_path = _extract_loader_value(loader_source, "submitPath")
        try:
            confirmation_message = _extract_loader_value(
                loader_source, "confirmation_message"
            )
        except ValueError:
            confirmation_message = _extract_loader_value(
                loader_source, "confirmationMessage"
            )
    except ValueError as exc:
        raise _persist_failure(
            archive_root=archive_root,
            repository_root=repository_root,
            source_url=source_url,
            observed_at=observed_at,
            code="provider_success_semantics_unavailable",
            status=response_status,
            final_url=final_url,
            primary_response=primary_body,
            visible_content=visible_content,
            network=network,
            screenshot=screenshot,
            screenshot_safety=screenshot_safety,
            form_inventory=form_inventory,
            operator_acceptance=operator_acceptance,
        ) from exc
    observation = _bytes(
        {
            "schema_version": "jaa.greenhouse-nonconsequential-canary.v1",
            "provider": "greenhouse",
            "observed_at": observed_at,
            "request": {"method": "GET", "status": response_status, "url": source_url},
            "provider_loader_paths": {
                "confirmationPath": confirmation_path,
                "confirmation_message": confirmation_message,
                "submitPath": submit_path,
            },
            "form_inventory_sha256": _sha256(form_inventory),
            "operator_acceptance_receipt_sha256": (
                acceptance_receipt.receipt_sha256
            ),
            "interaction": {
                "fields_filled": 0,
                "files_uploaded": 0,
                "submit_clicks": 0,
            },
        }
    )
    return _persist_capture(
        archive_root=archive_root,
        repository_root=repository_root,
        source_url=source_url,
        observed_at=observed_at,
        observation=observation,
        primary_response=primary_body,
        visible_content=visible_content,
        network_events=_bytes(
            {
                "schema_version": "jaa.provider-observation-network.v1",
                "events": network,
            }
        ),
        screenshot=screenshot,
        screenshot_safety=screenshot_safety,
        form_inventory=form_inventory,
        operator_acceptance=operator_acceptance,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_url")
    parser.add_argument("--archive-root", required=True)
    parser.add_argument("--repository-root", default=".")
    parser.add_argument("--job-key", required=True)
    parser.add_argument("--acceptance-envelope", required=True)
    parser.add_argument("--operator-public-key", required=True)
    args = parser.parse_args()
    receipt = capture_greenhouse_observation(
        source_url=args.source_url,
        archive_root=args.archive_root,
        repository_root=args.repository_root,
        job_key=args.job_key,
        acceptance_envelope_path=args.acceptance_envelope,
        operator_public_key_path=args.operator_public_key,
    )
    print(
        canonical_json(
            {
                "manifest_path": str(receipt.manifest_path),
                "manifest_sha256": receipt.manifest_sha256,
                "observation_sha256": receipt.observation_sha256,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "COLLECTOR_IDENTITY",
    "COLLECTOR_SOURCE_PATH",
    "CommittedSourceIdentity",
    "ProviderObservationCaptureReceipt",
    "ProviderObservationCaptureFailure",
    "capture_greenhouse_observation",
    "collector_source_identity",
    "exact_clean_head",
    "exact_committed_source_identity",
    "load_provider_observation_capture",
    "render_provider_observation_capture",
]
