from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts import jaa_certification_profile as profile
from scripts import seal_jaa_certification_evidence as sealer


def _write_root(base: Path, name: str, files: dict[str, bytes]) -> Path:
    root = base / name
    for relative, payload in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    return root


def test_seal_writes_exact_validated_noncertifying_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus_files = {
        "corpus_inventory.json": b'{"schema":"test-corpus"}\n',
        "record.json": b'{"id":1}\n',
    }
    corpus = _write_root(tmp_path, "corpus", corpus_files)
    remote_prefix = "/remote/jaa09-corpus"
    corpus_manifest = tmp_path / "corpus.sha256"
    corpus_manifest.write_text(
        "".join(
            f"{hashlib.sha256(payload).hexdigest()}  {remote_prefix}/{relative}\n"
            for relative, payload in sorted(corpus_files.items())
        ),
        encoding="utf-8",
    )
    external_files = {"registry.json": b"external\n"}
    exact_files = {"certificate.json": b"certificate\n"}
    historical_files = {"historical.json": b"historical\n"}
    external = _write_root(tmp_path, "external", external_files)
    exact = _write_root(tmp_path, "exact", exact_files)
    historical = _write_root(tmp_path, "historical", historical_files)

    external_expected = {
        name: hashlib.sha256(payload).hexdigest()
        for name, payload in external_files.items()
    }
    exact_expected = {
        name: hashlib.sha256(payload).hexdigest()
        for name, payload in exact_files.items()
    }
    historical_expected = {
        name: hashlib.sha256(payload).hexdigest()
        for name, payload in historical_files.items()
    }
    monkeypatch.setattr(sealer, "EXTERNAL_CONTROL_FILES", external_expected)
    monkeypatch.setattr(sealer, "EXACT_SOURCE_CERTIFICATE_FILES", exact_expected)
    monkeypatch.setattr(sealer, "LINUX_HISTORICAL_FILES", historical_expected)
    monkeypatch.setattr(
        profile,
        "JAA09_CORPUS_MANIFEST_SHA256",
        hashlib.sha256(corpus_manifest.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        profile,
        "JAA09_CORPUS_INVENTORY_SHA256",
        hashlib.sha256(corpus_files["corpus_inventory.json"]).hexdigest(),
    )
    monkeypatch.setattr(
        profile,
        "JAA10_EXACT_SOURCE_CERTIFICATE_SHA256",
        next(iter(exact_expected.values())),
    )
    monkeypatch.setattr(
        profile,
        "JAA10_LINUX_HISTORICAL_EVIDENCE_SHA256S",
        frozenset(historical_expected.values()),
    )

    output = tmp_path / "sealed"
    paths = sealer.seal(
        corpus_root=corpus,
        corpus_manifest=corpus_manifest,
        corpus_manifest_prefix=remote_prefix,
        external_control_root=external,
        exact_source_certificate_root=exact,
        linux_historical_root=historical,
        output_directory=output,
    )
    hooks = profile.load_evidence_config(paths["config"])
    assert {hook.evidence_id for hook in hooks} == profile.REQUIRED_EVIDENCE_IDS
    receipt = json.loads(paths["receipt"].read_text(encoding="utf-8"))
    assert receipt["claims"] == {
        "evidence_transferred_and_hash_validated": True,
        "current_source_certified": False,
        "current_source_linux_execution_verified": False,
        "product_certified": False,
        "jaa11_certified": False,
    }
    with pytest.raises(profile.CertificationProfileError, match="new absolute"):
        sealer.seal(
            corpus_root=corpus,
            corpus_manifest=corpus_manifest,
            corpus_manifest_prefix=remote_prefix,
            external_control_root=external,
            exact_source_certificate_root=exact,
            linux_historical_root=historical,
            output_directory=output,
        )


def test_seal_rejects_changed_or_extra_critical_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _write_root(tmp_path, "external", {"registry.json": b"changed\n"})
    monkeypatch.setattr(
        sealer,
        "EXTERNAL_CONTROL_FILES",
        {"registry.json": hashlib.sha256(b"expected\n").hexdigest()},
    )
    with pytest.raises(profile.CertificationProfileError, match="changed"):
        sealer._assert_exact_inventory(
            root, sealer.EXTERNAL_CONTROL_FILES, "external-control"
        )
