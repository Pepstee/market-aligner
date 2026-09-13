from __future__ import annotations

import tempfile
import unittest
import hashlib
import json
from datetime import date
from pathlib import Path

import yaml
from contextlib import redirect_stdout
from io import StringIO

from market_aligner.cli import main
from market_aligner.profiler.importers import (
    import_evidence_led,
    import_guided_profile,
    project_canonical_authority,
)
from market_aligner.profiler.schema import CandidateProfile, EvidenceItem, TrackProfile, new_profile_id
from market_aligner.profiler.store import ProfileStore


class ProfileTests(unittest.TestCase):
    def test_round_trip_uses_opaque_id_and_external_store(self) -> None:
        evidence = EvidenceItem(
            evidence_id="ev-1",
            kind="project",
            claim="Implemented a deterministic queue.",
            source_ref="private://portfolio/item-1",
            status="verified",
            confidence=0.9,
        )
        profile = CandidateProfile(
            profile_id=new_profile_id(),
            version="v1",
            tracks={
                "automation": TrackProfile(
                    interest=8,
                    demonstrated_skill=7,
                    confidence=0.8,
                    market_readiness=6,
                    evidence_ids=(evidence.evidence_id,),
                    rationale="Bound to a verified project.",
                )
            },
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = ProfileStore(temporary)
            store.save(profile, [evidence])
            loaded, ledger = store.load(profile.profile_id)
            self.assertEqual(profile, loaded)
            self.assertEqual(evidence, ledger[evidence.evidence_id])
            self.assertEqual([profile.profile_id], store.list_profile_ids())
            self.assertTrue(
                str(store.directory(profile.profile_id)).startswith(str(Path(temporary).resolve()))
            )

    def test_missing_evidence_is_rejected(self) -> None:
        profile = CandidateProfile(
            profile_id=new_profile_id(),
            version="v1",
            tracks={
                "test": TrackProfile(0, 0, 0, 0, evidence_ids=("missing",), rationale="unknown")
            },
        )
        with self.assertRaisesRegex(ValueError, "missing evidence"):
            profile.validate_evidence({})

    def test_importers_keep_unverified_legacy_profile_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guided = root / "guided.yaml"
            guided.write_text(
                yaml.safe_dump(
                    {
                        "meta": {"subject": "Private label", "version": "legacy-v2"},
                        "profile": {"track": {"interest": 7, "skill": 5, "confidence": 0.6}},
                    }
                ),
                encoding="utf-8",
            )
            profile, evidence = import_guided_profile(guided)
            self.assertEqual([], evidence)
            self.assertFalse(profile.tracks["track"].evidence_ids)
            self.assertEqual(0.0, profile.tracks["track"].market_readiness)
            self.assertIn("no itemised evidence ledger", profile.unknowns[0].lower())

            combined = root / "combined.yaml"
            combined.write_text(
                yaml.safe_dump(
                    {
                        "meta": {"subject": "Private label", "version": "v3"},
                        "evidence": [
                            {
                                "id": "ev-a",
                                "kind": "project",
                                "claim": "Built a tested service.",
                                "source": "private://evidence/a",
                                "status": "verified",
                                "confidence": 0.8,
                            }
                        ],
                        "career_tracks": {
                            "service": {
                                "interest": 8,
                                "skill": 6,
                                "confidence": 0.8,
                                "market_readiness": 5,
                                "evidence": ["ev-a"],
                                "rationale": "One verified service.",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            profile, evidence = import_evidence_led(combined)
            self.assertEqual(("ev-a",), profile.tracks["service"].evidence_ids)
            self.assertEqual("verified", evidence[0].status)

    def test_llm_projection_excludes_identity_and_source_locations(self) -> None:
        item = EvidenceItem("e", "project", "Built a queue.", "/private/path", "explicit", 0.8)
        profile = CandidateProfile(
            profile_id=new_profile_id(),
            version="v1",
            display_label="Private label",
            tracks={"queue": TrackProfile(8, 7, 0.8, 6, ("e",), "Project evidence")},
        )
        context = profile.llm_context({"e": item})
        rendered = str(context)
        self.assertNotIn("Private label", rendered)
        self.assertNotIn("/private/path", rendered)

    def _projection_sources(self, root: Path) -> tuple[Path, Path, Path]:
        packet = root / "approved.json"
        packet.write_text(
            json.dumps(
                {
                    "schema_version": "jaa05.operator-approved-statements.v1",
                    "statements": [
                        {
                            "id": "E-001",
                            "kind": "portfolio_artifact",
                            "proof_class": "portfolio_artifact",
                            "statement": "Built a tested deterministic service.",
                        }
                    ],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        statement_sha256 = hashlib.sha256(
            b"Built a tested deterministic service."
        ).hexdigest()
        packet_sha256 = hashlib.sha256(packet.read_bytes()).hexdigest()
        authority = root / "authority.json"
        authority.write_text(
            json.dumps(
                {
                    "schema_version": "jaa.production-candidate-authority.v2",
                    "candidate_projection": {
                        "schema_version": "jaa.candidate-authority-projection.v1",
                        "projection_sha256": "a" * 64,
                        "source_hashes": {"approved_evidence": packet_sha256},
                        "approved_evidence": [
                            {
                                "id": "E-001",
                                "kind": "portfolio_artifact",
                                "proof_class": "portfolio_artifact",
                                "statement_sha256": statement_sha256,
                            }
                        ],
                        "availability": {
                            "remote_preference": "preferred",
                            "sponsorship_required": False,
                        },
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        legacy = root / "legacy-v1.4.yaml"
        legacy.write_text(
            yaml.safe_dump(
                {
                    "meta": {"version": "v1.4", "subject": "Private candidate"},
                    "career_tracks": {
                        "automation": {
                            "interest": 9,
                            "skill": 7,
                            "confidence": 0.8,
                            "market_readiness": 6,
                            "evidence": ["E-001", "E-999"],
                            "rationale": "Legacy prose must not become authority.",
                            "gaps": ["Legacy gap"],
                        }
                    },
                    "evidence": [
                        {
                            "id": "E-001",
                            "claim": "Built a tested deterministic service.",
                        }
                    ],
                    "capabilities": {"summary": "Unbound legacy capability."},
                    "constraints": {
                        "remote_preference": "required",
                        "legacy_only": True,
                        "legacy_reviewed_on": date(2026, 7, 19),
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        return authority, packet, legacy

    def _projection_mapping(self, root: Path, authority: Path, packet: Path, legacy: Path) -> Path:
        mapping = root / "mapping.json"
        mapping.write_text(
            json.dumps(
                {
                    "schema": "market-aligner.canonical-evidence-mapping.v1",
                    "authority_sha256": hashlib.sha256(authority.read_bytes()).hexdigest(),
                    "evidence_packet_sha256": hashlib.sha256(packet.read_bytes()).hexdigest(),
                    "legacy_profile_sha256": hashlib.sha256(legacy.read_bytes()).hexdigest(),
                    "legacy_evidence_sha256": hashlib.sha256(legacy.read_bytes()).hexdigest(),
                    "mappings": {"E-001": ["E-001"]},
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return mapping

    def test_canonical_projection_maps_exact_evidence_and_records_losses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authority, packet, legacy = self._projection_sources(root)
            data_home = root / "external-data"
            profile, evidence, receipt = project_canonical_authority(
                authority_path=authority,
                evidence_packet_path=packet,
                legacy_profile_path=legacy,
                data_home=data_home,
            )

            self.assertEqual(("E-001",), profile.tracks["automation"].evidence_ids)
            self.assertEqual({}, profile.capabilities)
            self.assertEqual("preferred", profile.constraints["remote_preference"])
            self.assertEqual("Built a tested deterministic service.", evidence[0].claim)
            self.assertFalse(receipt.release_authority)
            self.assertTrue(any(item.reason_code == "absent_from_canonical_authority" for item in receipt.omissions))
            self.assertTrue(any(item.reason_code == "unbound_legacy_capability_prose" for item in receipt.omissions))
            self.assertTrue(any(item.reason_code == "legacy_constraint_differs_from_canonical_authority" for item in receipt.conflicts))
            directory = data_home / "profiles" / profile.profile_id
            self.assertTrue(directory.joinpath("profile.yaml").is_file())
            self.assertTrue(directory.joinpath("evidence.jsonl").is_file())
            self.assertTrue(directory.joinpath("projection-receipt.json").is_file())
            self.assertNotIn("Private candidate", directory.joinpath("profile.yaml").read_text())

            replay = project_canonical_authority(
                authority_path=authority,
                evidence_packet_path=packet,
                legacy_profile_path=legacy,
                data_home=data_home,
            )
            self.assertEqual((profile, evidence, receipt), replay)

    def test_project_canonical_cli_uses_hash_bound_mapping_and_replays(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authority, packet, legacy = self._projection_sources(root)
            mapping = self._projection_mapping(root, authority, packet, legacy)
            data_home = root / "external-data"
            argv = [
                "profiles", "project-canonical",
                "--authority", str(authority),
                "--approved-evidence", str(packet),
                "--legacy-profile", str(legacy),
                "--legacy-evidence", str(legacy),
                "--evidence-mapping", str(mapping),
                "--data-home", str(data_home),
            ]
            first = StringIO()
            with redirect_stdout(first):
                self.assertEqual(0, main(argv))
            second = StringIO()
            with redirect_stdout(second):
                self.assertEqual(0, main(argv))
            self.assertEqual(json.loads(first.getvalue()), json.loads(second.getvalue()))
            result = json.loads(first.getvalue())
            self.assertEqual(["automation"], result["track_names"])
            self.assertFalse(result["release_authority"])

            mapping_payload = json.loads(mapping.read_text())
            mapping_payload["legacy_profile_sha256"] = "0" * 64
            mapping.write_text(json.dumps(mapping_payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not bind"):
                main(argv)

    def test_projection_rejects_source_and_destination_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authority, packet, legacy = self._projection_sources(root)
            data_home = root / "external-data"
            profile, _, _ = project_canonical_authority(
                authority_path=authority,
                evidence_packet_path=packet,
                legacy_profile_path=legacy,
                data_home=data_home,
            )
            receipt_path = data_home / "profiles" / profile.profile_id / "projection-receipt.json"
            receipt_path.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "projection drift"):
                project_canonical_authority(
                    authority_path=authority,
                    evidence_packet_path=packet,
                    legacy_profile_path=legacy,
                    data_home=data_home,
                )

            packet.write_text(packet.read_text() + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not bind"):
                project_canonical_authority(
                    authority_path=authority,
                    evidence_packet_path=packet,
                    legacy_profile_path=legacy,
                    data_home=root / "other-data",
                )


if __name__ == "__main__":
    unittest.main()


def test_retained_profile_revision_is_exact_and_ignores_current_pointer(tmp_path):
    from dataclasses import asdict, replace
    import pytest

    store = ProfileStore(tmp_path / "data")
    old = CandidateProfile(profile_id=new_profile_id(), version="v1", tracks={
        "synthetic": TrackProfile(0, 0, 0, 0, evidence_ids=(), rationale="Synthetic fixture")
    })
    store.save(replace(old, version="v2"), [])
    directory = store.directory(old.profile_id)
    key = hashlib.sha256(old.version.encode()).hexdigest()
    revisions = directory / "revisions"
    revisions.mkdir(mode=0o700)
    revision = revisions / key
    revision.mkdir(mode=0o700)
    profile_bytes = yaml.safe_dump(asdict(old), sort_keys=False, allow_unicode=True, width=100).encode()
    evidence_bytes = b""
    manifest = {
        "schema_version": "market-aligner.profile-current.v1",
        "profile_version": old.version, "version_key": key,
        "profile_sha256": hashlib.sha256(profile_bytes).hexdigest(),
        "evidence_ledger_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
    }
    for name, raw in {"profile.yaml": profile_bytes, "evidence.jsonl": evidence_bytes,
                      "manifest.json": json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()}.items():
        path = revision / name
        path.write_bytes(raw)
        path.chmod(0o600)
    (directory / "current.json").write_text("invalid pointer must not be consulted")
    assert store.load_revision(old.profile_id, old.version) == (old, {})
    assert store.load(old.profile_id)[0].version == "v2"
    with pytest.raises(KeyError):
        store.load_revision(old.profile_id, "missing")
    path = revision / "profile.yaml"
    path.write_bytes(profile_bytes.replace(b"version: v1", b"version: v9"))
    with pytest.raises(ValueError, match="manifest or content differs"):
        store.load_revision(old.profile_id, old.version)
    path.unlink()
    path.symlink_to(directory / "profile.yaml")
    with pytest.raises((OSError, ValueError)):
        store.load_revision(old.profile_id, old.version)
    path.unlink()
    path.write_bytes(profile_bytes)
    path.chmod(0o600)
    assert store.load_revision(old.profile_id, old.version) == (old, {})

    # A retained donor store has only a current pointer plus revisions.
    for name in ("profile.yaml", "evidence.jsonl", "generation.json"):
        (directory / name).unlink()
    pointer = directory / "current.json"
    pointer.write_bytes((revision / "manifest.json").read_bytes())
    pointer.chmod(0o600)
    assert store.list_profile_ids() == [old.profile_id]
    assert store.load(old.profile_id) == (old, {})
    changed = {**manifest, "profile_sha256": "0" * 64}
    pointer.write_text(json.dumps(changed, sort_keys=True, separators=(",", ":")))
    with pytest.raises(ValueError, match="differs from revision manifest"):
        store.load(old.profile_id)
    pointer.write_bytes((revision / "manifest.json").read_bytes())
    assert store.load(old.profile_id) == (old, {})
    (directory / "generation.json").write_bytes(b"invalid generation")
    (directory / "generation.json").chmod(0o600)
    with pytest.raises((ValueError, FileNotFoundError)):
        store.load(old.profile_id)
