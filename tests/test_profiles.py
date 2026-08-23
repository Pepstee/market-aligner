from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from market_aligner.profiler.importers import import_evidence_led, import_guided_profile
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


if __name__ == "__main__":
    unittest.main()
