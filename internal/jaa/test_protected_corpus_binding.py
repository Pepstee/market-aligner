from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from career_automation import protected_corpus_binding as pcb


def _make_tree(tmp_path):
    root = tmp_path.resolve() / "jaa04_graphcore_corpus"
    root.mkdir()
    (root / "a.json").write_bytes(b'{"a":1}')
    (root / "nested").mkdir()
    (root / "nested" / "b.bin").write_bytes(b"\x00\x01\x02")
    return root


def _ephemeral_key():
    private_key = Ed25519PrivateKey.generate()
    public_b64 = base64.b64encode(
        private_key.public_key().public_bytes_raw()
    ).decode("ascii")
    return private_key, public_b64


def _synthetic_document(verifier_public_key_b64: str) -> dict[str, object]:
    return {
        "corpus_identity": pcb.CORPUS_IDENTITY,
        "corpus_root": "/opt/gigabyte/jaa/jaa04_graphcore_corpus",
        "environment": pcb.PROTECTED_CORPUS_ENVIRONMENT,
        "installed_manifest_sha256": "0" * 64,
        "inventory_files_sha256": pcb.INVENTORY_FILES_SHA256,
        "inventory_sha256": pcb.INVENTORY_SHA256,
        "issuer_id": pcb.PROTECTED_CORPUS_ISSUER_ID,
        "root_identity": {
            "device": 1,
            "group": 0,
            "inode": 2,
            "mode": 0o40755,
            "mtime_ns": 3,
            "owner": 0,
        },
        "schema_version": pcb.BINDING_SCHEMA_VERSION,
        "signature_b64": "",
        "source_head": "a" * 40,
        "source_tree": "b" * 40,
        "tracked_seed_sha256": pcb.TRACKED_SEED_SHA256,
        "tree_sha256": "c" * 64,
        "trust_root_id": pcb.PROTECTED_CORPUS_TRUST_ROOT_ID,
        "verifier_public_key_b64": verifier_public_key_b64,
    }


def _signed_raw(document: dict[str, object], private_key: Ed25519PrivateKey) -> bytes:
    unsigned = {k: v for k, v in document.items() if k != "signature_b64"}
    signature = private_key.sign(pcb.canonical_json_bytes(unsigned))
    signed = dict(unsigned)
    signed["signature_b64"] = base64.b64encode(signature).decode("ascii")
    return pcb.canonical_json_bytes(signed)


def _clear_forbidden_locators(monkeypatch):
    for name in pcb.FORBIDDEN_RUNTIME_LOCATORS:
        monkeypatch.delenv(name, raising=False)


def _guard_runtime_access(monkeypatch):
    def _forbidden(*args, **kwargs):
        raise AssertionError("runtime file access attempted")

    monkeypatch.setattr(pcb, "_source_identity", _forbidden)
    monkeypatch.setattr(pcb, "installed_distribution_manifest", _forbidden)
    monkeypatch.setattr(pcb, "_validate_root_owned_directory_chain", _forbidden)
    monkeypatch.setattr(pcb, "_read_installed_binding_bytes", _forbidden)


@pytest.mark.parametrize("locator", pcb.FORBIDDEN_RUNTIME_LOCATORS)
def test_loader_rejects_forbidden_locator_before_file_access(
    tmp_path, monkeypatch, locator
):
    _clear_forbidden_locators(monkeypatch)
    monkeypatch.setenv(locator, str(tmp_path))
    _guard_runtime_access(monkeypatch)
    with pytest.raises(pcb.ProtectedCorpusBindingError) as excinfo:
        pcb.load_installed_protected_corpus_binding(tmp_path)
    assert excinfo.value.code == "protected_locator_forbidden"


def test_loader_rejects_wrong_active_pin(tmp_path, monkeypatch):
    _clear_forbidden_locators(monkeypatch)
    monkeypatch.setattr(
        pcb, "_ACTIVE_BINDING_PATH", tmp_path.resolve() / "other.json"
    )
    _guard_runtime_access(monkeypatch)
    with pytest.raises(pcb.ProtectedCorpusBindingError) as excinfo:
        pcb.load_installed_protected_corpus_binding(tmp_path)
    assert excinfo.value.code == "protected_binding_path"


def test_tree_digest_is_stable(tmp_path):
    root = _make_tree(tmp_path)
    first = pcb.protected_corpus_tree_sha256(root, required_owner=None)
    second = pcb.protected_corpus_tree_sha256(root, required_owner=None)
    assert first[0] == second[0] == root
    assert first[1] == second[1]
    assert first[2] == second[2]


def test_tree_digest_changes_on_byte_mutation(tmp_path):
    root = _make_tree(tmp_path)
    before = pcb.protected_corpus_tree_sha256(root, required_owner=None)[1]
    (root / "a.json").write_bytes(b'{"a":2}')
    after = pcb.protected_corpus_tree_sha256(root, required_owner=None)[1]
    assert before != after


def test_tree_digest_refuses_symlink_child(tmp_path):
    root = _make_tree(tmp_path)
    (root / "link").symlink_to(root / "a.json")
    with pytest.raises(pcb.ProtectedCorpusBindingError) as excinfo:
        pcb.protected_corpus_tree_sha256(root, required_owner=None)
    assert excinfo.value.code == "protected_corpus_symlink"


def test_parse_signed_binding_accepts_valid_synthetic_document():
    private_key, public_b64 = _ephemeral_key()
    document = _synthetic_document(public_b64)
    raw = _signed_raw(document, private_key)
    parsed = pcb._parse_signed_binding(
        raw,
        verifier=private_key.public_key(),
        expected_public_key_b64=public_b64,
    )
    unsigned = {k: v for k, v in document.items() if k != "signature_b64"}
    assert {k: v for k, v in parsed.items() if k != "signature_b64"} == unsigned


def test_parse_signed_binding_rejects_tampered_document():
    private_key, public_b64 = _ephemeral_key()
    document = _synthetic_document(public_b64)
    unsigned = {k: v for k, v in document.items() if k != "signature_b64"}
    signature = private_key.sign(pcb.canonical_json_bytes(unsigned))
    tampered = dict(unsigned)
    tampered["tree_sha256"] = "d" * 64
    tampered["signature_b64"] = base64.b64encode(signature).decode("ascii")
    with pytest.raises(pcb.ProtectedCorpusBindingError) as excinfo:
        pcb._parse_signed_binding(
            pcb.canonical_json_bytes(tampered),
            verifier=private_key.public_key(),
            expected_public_key_b64=public_b64,
        )
    assert excinfo.value.code == "protected_binding_signature"


def test_parse_signed_binding_rejects_wrong_verifier_key():
    private_key, public_b64 = _ephemeral_key()
    other_key, _ = _ephemeral_key()
    raw = _signed_raw(_synthetic_document(public_b64), private_key)
    with pytest.raises(pcb.ProtectedCorpusBindingError) as excinfo:
        pcb._parse_signed_binding(
            raw,
            verifier=other_key.public_key(),
            expected_public_key_b64=public_b64,
        )
    assert excinfo.value.code == "protected_binding_signature"


def test_parse_signed_binding_rejects_malformed_signature():
    private_key, public_b64 = _ephemeral_key()
    unsigned = {
        k: v for k, v in _synthetic_document(public_b64).items()
        if k != "signature_b64"
    }
    unsigned["signature_b64"] = "@@@@"
    with pytest.raises(pcb.ProtectedCorpusBindingError) as excinfo:
        pcb._parse_signed_binding(
            pcb.canonical_json_bytes(unsigned),
            verifier=private_key.public_key(),
            expected_public_key_b64=public_b64,
        )
    assert excinfo.value.code == "protected_binding_signature"


def test_parse_signed_binding_rejects_wrong_shape():
    private_key, public_b64 = _ephemeral_key()
    unsigned = {
        k: v for k, v in _synthetic_document(public_b64).items()
        if k != "signature_b64" and k != "corpus_root"
    }
    signature = private_key.sign(pcb.canonical_json_bytes(unsigned))
    unsigned["signature_b64"] = base64.b64encode(signature).decode("ascii")
    with pytest.raises(pcb.ProtectedCorpusBindingError) as excinfo:
        pcb._parse_signed_binding(
            pcb.canonical_json_bytes(unsigned),
            verifier=private_key.public_key(),
            expected_public_key_b64=public_b64,
        )
    assert excinfo.value.code == "protected_binding_malformed"


def test_parse_signed_binding_rejects_wrong_pins():
    private_key, public_b64 = _ephemeral_key()
    document = _synthetic_document(public_b64)
    document["environment"] = "development"
    raw = _signed_raw(document, private_key)
    with pytest.raises(pcb.ProtectedCorpusBindingError) as excinfo:
        pcb._parse_signed_binding(
            raw,
            verifier=private_key.public_key(),
            expected_public_key_b64=public_b64,
        )
    assert excinfo.value.code == "protected_binding_pins"
