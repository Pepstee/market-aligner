from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from career_automation.documents import (
    DocumentEngineManifest,
    DocumentOperationManifest,
    DocumentSidecarPolicy,
    EngineVerification,
    require_verification_consensus,
)


def _engine(*, licence: str = "MIT", zone: str = "mit-core") -> DocumentEngineManifest:
    return DocumentEngineManifest(
        engine="pdf-repair", version="1.0", source_repository="https://example.test/repo",
        source_revision="abc123", licence_identifier=licence, licence_zone=zone,
        image="example/pdf-core@sha256:" + "a" * 64,
    )


def _operation(engine: DocumentEngineManifest | None = None, **overrides) -> DocumentOperationManifest:
    values = {
        "operation_id": "op-1", "operation": "repair", "input_sha256": "b" * 64,
        "output_format": "pdf", "engine": engine or _engine(),
        "network_disabled": True, "analytics_disabled": True,
        "persistent_storage_disabled": True, "sharing_disabled": True,
        "read_only_root": True,
    }
    values.update(overrides)
    return DocumentOperationManifest(**values)


class DocumentSidecarPolicyTests(unittest.TestCase):
    def test_rejects_restricted_licence_zones_and_unsafe_flags(self) -> None:
        policy = DocumentSidecarPolicy()
        with self.assertRaisesRegex(PermissionError, "licence"):
            policy.validate(_operation(_engine(licence="Proprietary", zone="restricted")))
        with self.assertRaisesRegex(PermissionError, "network_disabled"):
            policy.validate(_operation(network_disabled=False))

    def test_container_spec_is_digest_pinned_and_hardened(self) -> None:
        policy = DocumentSidecarPolicy()
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "input"
            source.mkdir()
            destination = Path(temporary) / "output"
            destination.mkdir()
            spec = policy.docker_run_spec(
                _operation(), input_directory=source, output_directory=destination,
                sidecar_command=("repair", "/input/cv.pdf", "/output/cv.pdf"),
            )
        command = " ".join(spec.argv)
        self.assertIn("--network none", command)
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop ALL", command)
        self.assertIn("@sha256:", command)

    def test_multi_engine_verification_requires_same_artifact_and_all_pass(self) -> None:
        digest = "c" * 64
        results = [
            EngineVerification("pdftotext", digest, True),
            EngineVerification("qpdf", digest, True),
        ]
        accepted = require_verification_consensus(
            results, required_engines=("pdftotext", "qpdf")
        )
        self.assertEqual(len(accepted), 2)
        with self.assertRaisesRegex(RuntimeError, "failed"):
            require_verification_consensus(
                [results[0], EngineVerification("qpdf", digest, False)],
                required_engines=("pdftotext", "qpdf"),
            )


if __name__ == "__main__":
    unittest.main()
