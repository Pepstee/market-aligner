"""Repository-reviewed authority for owned provider-observation captures."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .evidence_matching import canonical_json
from .provider_observation_capture import exact_clean_head


_FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"
_POLICY_PATH = _FIXTURE_ROOT / "trusted-greenhouse-success-observations.json"
_CAPTURE_OBJECT_ROOT = _FIXTURE_ROOT / "provider-observation-capture-objects"
_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_ZERO_INTERACTION = {"fields_filled": 0, "files_uploaded": 0, "submit_clicks": 0}
_IMMUTABLE_LEGACY_COLLECTORS = frozenset(
    {
        (
            "jaa.playwright-greenhouse-read-only-observer.v3",
            "8b0868399733a33716c3f37818f58dab8cb204bf",
            "2d8859b69fcba66d2c0767fc8fe24a58f5b3c5ed01a3752280d8c6d00056220f",
        ),
        (
            "jaa.repository-playwright-route-fixture.v1",
            "cf4543f5906918c7e25143c18c344ddd6c6b602e",
            "c87b0941bcd8df37d328724bead6a01c231cd85d7068a588491ed62cf843a463",
        ),
    }
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_document(value: bytes, label: str) -> dict[str, object]:
    try:
        document = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid JSON") from exc
    if not isinstance(document, dict) or value != (
        canonical_json(document) + "\n"
    ).encode("utf-8"):
        raise ValueError(f"{label} is not canonical JSON")
    return document


def _repository_prefix(repository_root: str | Path) -> str:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(Path(repository_root).resolve(strict=True)),
            "rev-parse",
            "--show-prefix",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    prefix = completed.stdout.strip()
    if completed.returncode != 0 or (prefix and not prefix.endswith("/")):
        raise ValueError("provider observation repository prefix is invalid")
    return prefix


def _git_show(
    repository_root: str | Path,
    revision: str,
    relative_path: str,
    *,
    allow_legacy_root: bool = False,
) -> bytes:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != relative_path:
        raise ValueError("provider observation source path is unsafe")
    committed_path = f"{_repository_prefix(repository_root)}{relative_path}"
    repository = str(Path(repository_root).resolve(strict=True))

    def read_path(path: str) -> bytes | None:
        completed = subprocess.run(
            ["git", "-C", repository, "show", f"{revision}:{path}"],
            check=False,
            capture_output=True,
        )
        return completed.stdout if completed.returncode == 0 else None

    committed = read_path(committed_path)
    legacy = (
        read_path(relative_path)
        if allow_legacy_root and committed_path != relative_path
        else None
    )
    if committed is not None and legacy is not None and committed != legacy:
        raise ValueError("provider observation authority source path is ambiguous")
    value = committed if committed is not None else legacy
    if value is None:
        raise ValueError("provider observation authority source is absent from Git")
    return value


def _trusted_policy() -> tuple[dict[str, object], bytes, str]:
    value = _POLICY_PATH.read_bytes()
    document = _canonical_document(value, "provider observation trust policy")
    authorities = document.get("authorities")
    if (
        document.get("schema_version") != "jaa.trusted-provider-observations.v2"
        or not isinstance(authorities, list)
        or not authorities
    ):
        raise ValueError("provider observation trust policy is malformed")
    return document, value, _sha256(value)


def _verify_exact_head_policy(repository_root: str | Path, policy_value: bytes) -> str:
    head = exact_clean_head(repository_root)
    committed = _git_show(
        repository_root,
        "HEAD",
        "career_automation/fixtures/trusted-greenhouse-success-observations.json",
    )
    if committed != policy_value:
        raise ValueError("provider observation trust policy differs from exact HEAD")
    return head


@dataclass(frozen=True)
class ProviderObservationAuthorityReceipt:
    authority_id: str
    collector_identity: str
    collector_source_path: str
    collector_source_sha256: str
    collector_repository_commit: str
    scope: str
    observation_sha256: str
    capture_manifest_sha256: str
    trust_policy_sha256: str
    source_url: str
    observed_at: str
    attempt_id: str | None
    vacancy_capture_sha256: str | None
    network_evidence_sha256: str
    schema_version: str = "jaa.provider-observation-authority-receipt.v2"

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "authority_id": self.authority_id,
            "collector_identity": self.collector_identity,
            "collector_source_path": self.collector_source_path,
            "collector_source_sha256": self.collector_source_sha256,
            "collector_repository_commit": self.collector_repository_commit,
            "scope": self.scope,
            "observation_sha256": self.observation_sha256,
            "capture_manifest_sha256": self.capture_manifest_sha256,
            "trust_policy_sha256": self.trust_policy_sha256,
            "source_url": self.source_url,
            "observed_at": self.observed_at,
            "attempt_id": self.attempt_id,
            "vacancy_capture_sha256": self.vacancy_capture_sha256,
            "network_evidence_sha256": self.network_evidence_sha256,
        }


def _matching_authority(
    policy: Mapping[str, object], *, observation_sha256: str, source_url: str
) -> Mapping[str, object]:
    matches = [
        row
        for row in policy["authorities"]
        if isinstance(row, Mapping)
        and row.get("observation_sha256") == observation_sha256
        and row.get("source_url") == source_url
    ]
    if len(matches) != 1:
        raise ValueError(
            "provider success observation is not a unique repository-trusted authority"
        )
    return matches[0]


def _capture_manifest_bytes(
    authority: Mapping[str, object], *, scope: str, archive_root: str | Path
) -> bytes:
    digest = authority.get("capture_manifest_sha256")
    if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
        raise ValueError("provider observation capture manifest identity is invalid")
    if scope == "repository_fixture":
        name = authority.get("fixture_manifest")
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError("provider observation fixture manifest path is invalid")
        path = _FIXTURE_ROOT / name
    elif scope == "production_capture":
        root = Path(archive_root).resolve(strict=True)
        path = root / "provider-observation-captures" / f"{digest}.json"
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError("provider observation capture path must not be a symlink")
    else:
        raise ValueError("trusted provider observation scope is unsupported")
    value = path.read_bytes()
    if _sha256(value) != digest:
        raise ValueError("provider observation capture manifest bytes differ")
    return value


def _artifact_bytes(
    digest: str,
    *,
    scope: str,
    archive_root: str | Path,
    authority: Mapping[str, object],
) -> bytes:
    if not _HEX_64.fullmatch(digest):
        raise ValueError("provider observation capture artifact identity is invalid")
    if scope == "repository_fixture":
        names = authority.get("fixture_artifacts")
        if not isinstance(names, Mapping):
            raise ValueError("provider observation fixture artifact map is missing")
        candidates = [name for name, candidate in names.items() if candidate == digest]
        if len(candidates) != 1 or not isinstance(candidates[0], str):
            raise ValueError(
                "provider observation fixture artifact is not uniquely bound"
            )
        name = candidates[0]
        if Path(name).name != name:
            raise ValueError("provider observation fixture artifact path is invalid")
        path = _CAPTURE_OBJECT_ROOT / name
    else:
        root = Path(archive_root).resolve(strict=True)
        path = root / "objects" / digest[:2] / digest
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError("provider observation object path must not be a symlink")
    value = path.read_bytes()
    if _sha256(value) != digest:
        raise ValueError("provider observation capture artifact bytes differ")
    return value


def _verify_capture_manifest(
    authority: Mapping[str, object],
    observation: bytes,
    *,
    scope: str,
    archive_root: str | Path,
    repository_root: str | Path,
) -> Mapping[str, object]:
    value = _capture_manifest_bytes(authority, scope=scope, archive_root=archive_root)
    manifest = _canonical_document(value, "provider observation capture manifest")
    artifacts = manifest.get("artifacts")
    collector_identity = manifest.get("collector_identity")
    source_path = manifest.get("collector_source_path")
    source_digest = manifest.get("collector_source_sha256")
    commit = manifest.get("repository_commit")
    if (
        manifest.get("schema_version") != "jaa.provider-observation-capture.v1"
        or manifest.get("capture_mode")
        != (
            "repository_fixture" if scope == "repository_fixture" else "production_live"
        )
        or manifest.get("provider") != "greenhouse"
        or manifest.get("source_url") != authority.get("source_url")
        or manifest.get("observed_at") != authority.get("observed_at")
        or manifest.get("interaction") != _ZERO_INTERACTION
        or not isinstance(artifacts, Mapping)
        or not isinstance(collector_identity, str)
        or not collector_identity
        or collector_identity != collector_identity.strip()
        or not isinstance(source_path, str)
        or Path(source_path).as_posix() != source_path
        or Path(source_path).is_absolute()
        or ".." in Path(source_path).parts
        or "." in Path(source_path).parts
        or not isinstance(source_digest, str)
        or not _HEX_64.fullmatch(source_digest)
        or not isinstance(commit, str)
        or not _HEX_40.fullmatch(commit)
    ):
        raise ValueError("provider observation capture manifest is malformed")
    required_artifacts = {
        "observation",
        "primary_response",
        "visible_content",
        "network_events",
    }
    if not required_artifacts.issubset(artifacts):
        raise ValueError("provider observation capture artifacts are incomplete")
    if scope == "production_capture" and (
        "screenshot" not in artifacts or len(set(artifacts.values())) != len(artifacts)
    ):
        raise ValueError("production provider capture artifacts are not independent")
    resolved: dict[str, bytes] = {}
    for label, digest in artifacts.items():
        if not isinstance(label, str) or not isinstance(digest, str):
            raise ValueError("provider observation capture artifact is malformed")
        resolved[label] = _artifact_bytes(
            digest,
            scope=scope,
            archive_root=archive_root,
            authority=authority,
        )
    if resolved["observation"] != observation:
        raise ValueError("provider observation differs from capture receipt")
    if scope == "production_capture":
        network = _canonical_document(
            resolved["network_events"], "provider observation network evidence"
        )
        events = network.get("events")
        if (
            network.get("schema_version") != "jaa.provider-observation-network.v1"
            or not isinstance(events, list)
            or not any(
                isinstance(event, Mapping)
                and event.get("method") == "GET"
                and event.get("resource_type") == "document"
                and event.get("status") == 200
                and event.get("url") == authority.get("source_url")
                for event in events
            )
            or not resolved["primary_response"]
            or not resolved["visible_content"]
        ):
            raise ValueError(
                "production provider capture transport evidence is invalid"
            )
    source = _git_show(
        repository_root,
        commit,
        source_path,
        allow_legacy_root=True,
    )
    if _sha256(source) != source_digest:
        raise ValueError("provider observation collector source identity differs")
    current_source = _git_show(repository_root, "HEAD", source_path)
    legacy_identity = (collector_identity, commit, source_digest)
    if (
        current_source != source
        and legacy_identity not in _IMMUTABLE_LEGACY_COLLECTORS
    ):
        raise ValueError("provider observation collector changed since capture")
    if authority.get("collector_identity") is not None:
        raise ValueError("trust policy must not assert or relabel collector identity")
    return manifest


def verify_provider_observation_authority(
    observation: bytes,
    *,
    source_url: str,
    archive_root: str | Path,
    repository_root: str | Path,
) -> ProviderObservationAuthorityReceipt:
    """Resolve exact bytes only through a reviewed, owned capture receipt."""
    digest = _sha256(observation)
    policy, policy_value, policy_sha256 = _trusted_policy()
    _verify_exact_head_policy(repository_root, policy_value)
    authority = _matching_authority(
        policy,
        observation_sha256=digest,
        source_url=source_url,
    )
    observation_document = _canonical_document(
        observation, "trusted provider success observation"
    )
    request = observation_document.get("request")
    vacancy_match = re.search(r"(?:^|/)jobs/(\d+)(?:/|$)", source_url)
    if (
        observation_document.get("schema_version")
        != "jaa.greenhouse-nonconsequential-canary.v1"
        or observation_document.get("provider") != "greenhouse"
        or observation_document.get("observed_at") != authority.get("observed_at")
        or not isinstance(request, Mapping)
        or request.get("url") != source_url
        or observation_document.get("interaction") != _ZERO_INTERACTION
        or vacancy_match is None
    ):
        raise ValueError("trusted provider observation identity is inconsistent")
    scope = authority.get("scope")
    authority_id = authority.get("authority_id")
    if (
        not isinstance(scope, str)
        or not isinstance(authority_id, str)
        or not authority_id
    ):
        raise ValueError("trusted provider observation authority is malformed")
    manifest = _verify_capture_manifest(
        authority,
        observation,
        scope=scope,
        archive_root=archive_root,
        repository_root=repository_root,
    )
    if manifest.get("vacancy_id") != vacancy_match.group(1):
        raise ValueError("provider observation capture vacancy identity differs")
    artifacts = manifest["artifacts"]
    assert isinstance(artifacts, Mapping)
    return ProviderObservationAuthorityReceipt(
        authority_id=authority_id,
        collector_identity=str(manifest["collector_identity"]),
        collector_source_path=str(manifest["collector_source_path"]),
        collector_source_sha256=str(manifest["collector_source_sha256"]),
        collector_repository_commit=str(manifest["repository_commit"]),
        scope=scope,
        observation_sha256=digest,
        capture_manifest_sha256=str(authority["capture_manifest_sha256"]),
        trust_policy_sha256=policy_sha256,
        source_url=source_url,
        observed_at=str(authority["observed_at"]),
        attempt_id=(
            str(authority["attempt_id"]) if authority.get("attempt_id") else None
        ),
        vacancy_capture_sha256=(
            str(authority["vacancy_capture_sha256"])
            if authority.get("vacancy_capture_sha256")
            else None
        ),
        network_evidence_sha256=str(artifacts["network_events"]),
    )


def load_provider_observation_authority(
    *,
    source_url: str,
    archive_root: str | Path,
    repository_root: str | Path,
) -> tuple[bytes, ProviderObservationAuthorityReceipt]:
    """Resolve provider bytes from the trusted policy and owned capture only."""
    policy, policy_value, _ = _trusted_policy()
    _verify_exact_head_policy(repository_root, policy_value)
    matches = [
        row
        for row in policy["authorities"]
        if isinstance(row, Mapping) and row.get("source_url") == source_url
    ]
    if len(matches) != 1:
        raise ValueError(
            "provider source URL lacks one trusted observation authority"
        )
    authority = matches[0]
    scope = authority.get("scope")
    if not isinstance(scope, str):
        raise ValueError("provider observation scope is invalid")
    manifest_value = _capture_manifest_bytes(
        authority, scope=scope, archive_root=archive_root
    )
    manifest = _canonical_document(
        manifest_value, "provider observation capture manifest"
    )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping) or not isinstance(
        artifacts.get("observation"), str
    ):
        raise ValueError("provider observation capture lacks observation bytes")
    observation = _artifact_bytes(
        str(artifacts["observation"]),
        scope=scope,
        archive_root=archive_root,
        authority=authority,
    )
    receipt = verify_provider_observation_authority(
        observation,
        source_url=source_url,
        archive_root=archive_root,
        repository_root=repository_root,
    )
    return observation, receipt


__all__ = [
    "ProviderObservationAuthorityReceipt",
    "load_provider_observation_authority",
    "verify_provider_observation_authority",
]
