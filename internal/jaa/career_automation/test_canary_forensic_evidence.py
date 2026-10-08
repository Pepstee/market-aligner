from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from career_automation.canary_forensic_evidence import (
    ARTIFACT_FILENAME,
    INDEX_FILENAME,
    MAX_SOURCE_BYTES,
    RECEIPT_FILENAME,
    CanaryForensicEvidenceError,
    archive_exact_canary_evidence,
    list_canary_forensic_events,
    record_canary_forensic_event,
    verify_exact_canary_evidence,
)


class CanaryForensicEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.repository = self.base / "repository"
        self.repository.mkdir(mode=0o700)
        self.root = self.base / "private-forensics"
        self.source = self.base / "capture.yml"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_source(self, body: bytes) -> None:
        self.source.write_bytes(body)
        self.source.chmod(0o600)

    def _archive(self, body: bytes = b'textbox "Password": lost-access-secret\n'):
        self._write_source(body)
        return archive_exact_canary_evidence(
            self.source,
            root=self.root,
            repository_root=self.repository,
            media_type="application/x-yaml",
        )

    def test_credentials_and_binary_bytes_are_preserved_exactly_and_privately(self) -> None:
        body = (
            b'textbox "Password": account-recovery-secret\n'
            b"access_token: useful-token\n\x00\xff\x10"
        )
        receipt = self._archive(body)

        verified, artifact = verify_exact_canary_evidence(
            self.root, self.repository, receipt.receipt_sha256
        )
        self.assertEqual(verified, receipt)
        self.assertEqual(artifact, body)
        self.assertTrue(receipt.credentials_may_be_present)
        self.assertTrue(receipt.exact_bytes_retained)
        self.assertFalse(receipt.certifies_provider_success)
        self.assertFalse(receipt.submission_authority)

        directory = self.root / receipt.receipt_sha256
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for filename in (ARTIFACT_FILENAME, RECEIPT_FILENAME):
            metadata = (directory / filename).stat()
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual(metadata.st_nlink, 1)

    def test_exact_replay_is_idempotent(self) -> None:
        first = self._archive(b"same exact diagnostic\n")
        before = sorted(path.name for path in self.root.iterdir())
        second = self._archive(b"same exact diagnostic\n")
        self.assertEqual(second, first)
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), before)

    def test_source_symlink_hardlink_and_oversize_are_rejected(self) -> None:
        self._write_source(b"diagnostic")
        symlink = self.base / "capture-link"
        symlink.symlink_to(self.source)
        with self.assertRaises(OSError):
            archive_exact_canary_evidence(
                symlink, root=self.root, repository_root=self.repository
            )

        hardlink = self.base / "capture-hardlink"
        os.link(self.source, hardlink)
        with self.assertRaisesRegex(CanaryForensicEvidenceError, "unsafe or oversized"):
            archive_exact_canary_evidence(
                self.source, root=self.root, repository_root=self.repository
            )
        hardlink.unlink()

        with self.source.open("wb") as handle:
            handle.truncate(MAX_SOURCE_BYTES + 1)
        with self.assertRaisesRegex(CanaryForensicEvidenceError, "unsafe or oversized"):
            archive_exact_canary_evidence(
                self.source, root=self.root, repository_root=self.repository
            )

    def test_archive_inside_repository_or_unsafe_root_is_rejected(self) -> None:
        self._write_source(b"diagnostic")
        with self.assertRaisesRegex(CanaryForensicEvidenceError, "outside Git"):
            archive_exact_canary_evidence(
                self.source,
                root=self.repository / "forensics",
                repository_root=self.repository,
            )

        self.root.mkdir(mode=0o700)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(CanaryForensicEvidenceError, "mode 0700"):
            archive_exact_canary_evidence(
                self.source, root=self.root, repository_root=self.repository
            )

    def test_tampered_artifact_receipt_mode_and_inventory_fail_closed(self) -> None:
        receipt = self._archive(b"original diagnostic")
        directory = self.root / receipt.receipt_sha256
        artifact = directory / ARTIFACT_FILENAME
        artifact.write_bytes(b"tampered diagnostic")
        artifact.chmod(0o600)
        with self.assertRaisesRegex(CanaryForensicEvidenceError, "identity differs"):
            verify_exact_canary_evidence(self.root, self.repository, receipt.receipt_sha256)

        receipt = self._archive(b"second diagnostic")
        directory = self.root / receipt.receipt_sha256
        receipt_path = directory / RECEIPT_FILENAME
        receipt_path.chmod(0o644)
        with self.assertRaisesRegex(CanaryForensicEvidenceError, "unsafe"):
            verify_exact_canary_evidence(self.root, self.repository, receipt.receipt_sha256)

        receipt_path.chmod(0o600)
        (directory / "extra").write_bytes(b"unexpected")
        with self.assertRaisesRegex(CanaryForensicEvidenceError, "inventory"):
            verify_exact_canary_evidence(self.root, self.repository, receipt.receipt_sha256)

    def test_append_only_index_records_detail_and_exact_replay_once(self) -> None:
        body = b"HTTP 403\nchallenge=turnstile\npassword=retained-for-recovery\n"
        self._write_source(body)
        arguments = dict(
            source_path=self.source,
            root=self.root,
            repository_root=self.repository,
            recorded_at="2026-08-26T12:00:00Z",
            cycle_id="canary-018",
            stage="ats_preflight",
            issue_code="bot_challenge",
            summary="The ATS returned an interactive challenge before applicant entry.",
            technical_detail=(
                "Captured the exact response and challenge marker; no bypass or final click was attempted."
            ),
            media_type="text/plain",
        )
        first = record_canary_forensic_event(**arguments)
        replay = record_canary_forensic_event(**arguments)
        self.assertEqual(replay, first)
        self.assertEqual(first.sequence, 1)

        arguments["recorded_at"] = "2026-08-26T12:01:00Z"
        arguments["issue_code"] = "bot_challenge_review"
        arguments["summary"] = "The challenge evidence was reviewed after the terminal result."
        second = record_canary_forensic_event(**arguments)
        self.assertEqual(second.sequence, 2)
        self.assertEqual(list_canary_forensic_events(root=self.root, repository_root=self.repository), (first, second))

        index = self.root / INDEX_FILENAME
        metadata = index.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_nlink, 1)
        connection = sqlite3.connect(index)
        try:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE canary_forensic_events SET summary = 'rewritten' WHERE sequence = 1"
                )
            connection.rollback()
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute("DELETE FROM canary_forensic_events WHERE sequence = 1")
        finally:
            connection.close()

    def test_invalid_event_is_rejected_before_index_creation(self) -> None:
        self._write_source(b"diagnostic")
        with self.assertRaisesRegex(ValueError, "RFC3339"):
            record_canary_forensic_event(
                self.source,
                root=self.root,
                repository_root=self.repository,
                recorded_at="yesterday",
                cycle_id="canary-018",
                stage="ats_preflight",
                issue_code="invalid_time",
                summary="Invalid event time.",
                technical_detail="This should not reach the append-only index.",
            )
        self.assertFalse((self.root / INDEX_FILENAME).exists())


class ApplicationArchiveForensicCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.repository = self.base / "repository"
        self.repository.mkdir(mode=0o700)
        self.forensic_root = self.base / "forensics"
        self.source = self.base / "capture.bin"
        self.body = b"SENTINEL-SECRET-PAYLOAD\x00\xff\x10" + bytes(range(256))
        self.source.write_bytes(self.body)
        self.source.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "career_automation.application_archive",
                "--repository-root",
                str(self.repository),
                *arguments,
            ],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parents[1]),
        )

    def test_cli_record_list_verify_round_trip_hides_payload(self) -> None:
        record_arguments = (
            "forensic-record",
            "--root", str(self.forensic_root),
            "--recorded-at", "2026-09-26T00:00:00Z",
            "--cycle-id", "cycle-001",
            "--stage", "ats_preflight",
            "--issue-code", "bot_challenge",
            "--summary", "SUMMARY-SENTINEL wording",
            "--technical-detail", "DETAIL-SENTINEL wording",
            str(self.source),
        )
        first = self._run(*record_arguments)
        self.assertEqual(0, first.returncode, first.stderr)
        repeat = self._run(*record_arguments)
        self.assertEqual(0, repeat.returncode, repeat.stderr)
        self.assertEqual(first.stdout, repeat.stdout)
        safe = json.loads(first.stdout)
        self.assertEqual(
            {
                "sequence",
                "event_sha256",
                "evidence_receipt_sha256",
                "exact_evidence_sha256",
            },
            set(safe),
        )
        self.assertEqual(1, safe["sequence"])

        changed = self._run(
            "forensic-record",
            "--root", str(self.forensic_root),
            "--recorded-at", "2026-09-26T00:01:00Z",
            "--cycle-id", "cycle-001",
            "--stage", "ats_preflight",
            "--issue-code", "bot_challenge_review",
            "--summary", "reviewed wording",
            "--technical-detail", "reviewed detail",
            str(self.source),
        )
        self.assertEqual(0, changed.returncode, changed.stderr)
        self.assertEqual(2, json.loads(changed.stdout)["sequence"])

        listed = self._run("forensic-list", "--root", str(self.forensic_root))
        self.assertEqual(0, listed.returncode, listed.stderr)
        rows = json.loads(listed.stdout)
        self.assertEqual([1, 2], [row["sequence"] for row in rows])
        self.assertEqual(safe["event_sha256"], rows[0]["event_sha256"])

        verified = self._run(
            "forensic-verify",
            "--root", str(self.forensic_root),
            safe["evidence_receipt_sha256"],
        )
        self.assertEqual(0, verified.returncode, verified.stderr)
        receipt = json.loads(verified.stdout)
        self.assertEqual(hashlib.sha256(self.body).hexdigest(), receipt["exact_sha256"])
        self.assertEqual(len(self.body), receipt["exact_size_bytes"])
        self.assertTrue(receipt["credentials_may_be_present"])
        self.assertFalse(receipt["submission_authority"])

        for output in (first.stdout, listed.stdout, verified.stdout):
            self.assertNotIn("SENTINEL", output)
            self.assertNotIn(str(self.source), output)

        _, artifact = verify_exact_canary_evidence(
            self.forensic_root, self.repository, safe["evidence_receipt_sha256"]
        )
        self.assertEqual(self.body, artifact)

    def test_cli_rejects_missing_root_and_invalid_event_before_writes(self) -> None:
        missing = self._run(
            "forensic-record",
            "--recorded-at", "2026-09-26T00:00:00Z",
            "--cycle-id", "cycle-001",
            "--stage", "stage_one",
            "--issue-code", "issue_one",
            "--summary", "wording",
            "--technical-detail", "detail",
            str(self.source),
        )
        self.assertNotEqual(0, missing.returncode)
        self.assertFalse(self.forensic_root.exists())

        invalid = self._run(
            "forensic-record",
            "--root", str(self.forensic_root),
            "--recorded-at", "yesterday",
            "--cycle-id", "cycle-001",
            "--stage", "stage_one",
            "--issue-code", "issue_one",
            "--summary", "wording",
            "--technical-detail", "detail",
            str(self.source),
        )
        self.assertEqual(2, invalid.returncode, invalid.stderr)
        self.assertFalse((self.forensic_root / INDEX_FILENAME).exists())

    def test_cli_preserves_existing_query_behaviour(self) -> None:
        archive_root = self.base / "release-archive"
        archive_root.mkdir(mode=0o700)
        (archive_root / "attempts").mkdir(mode=0o700)
        (archive_root / "objects").mkdir(mode=0o700)
        queried = self._run("--root", str(archive_root), "query")
        self.assertEqual(0, queried.returncode, queried.stderr)
        self.assertEqual([], json.loads(queried.stdout))


if __name__ == "__main__":
    unittest.main()
