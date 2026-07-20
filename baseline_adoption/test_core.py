from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from baseline_adoption import core


class BaselineAdoptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.specs = []
        for name in ("raw", "career"):
            relative = f"inputs/{name}.sqlite3"
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
                connection.execute("INSERT INTO records(value) VALUES ('locked')")
                connection.commit()
            with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as connection:
                rows = core._schema_rows(connection)
            self.specs.append(core.BaselineSpec(
                name, relative, f"databases/{name}.sqlite3", path.stat().st_size,
                core._hash_file(path), hashlib.sha256(core._canonical_bytes(rows)).hexdigest(),
                len(rows), {"records": 1}))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _adopt(self) -> tuple[Path, Path]:
        data = self.root / "local-data"
        repository = self.root / "repository"
        repository.mkdir(exist_ok=True)
        with patch.object(core, "BASELINES", tuple(self.specs)), \
             patch.object(core, "_runtime_versions", return_value={"python": "test"}), \
             patch.object(core, "_repository_revision", return_value="a" * 40):
            receipt = core.adopt(self.source, data, repository=repository,
                                 secret_references=["ATS_API_TOKEN"])
        return data, receipt

    def test_adopt_reconcile_and_rollback_manifest(self) -> None:
        data, receipt = self._adopt()
        document = json.loads(receipt.read_text())
        self.assertEqual(document["content"]["secret_references"], ["ATS_API_TOKEN"])
        self.assertNotIn(str(self.root), receipt.read_text())
        with patch.object(core, "BASELINES", tuple(self.specs)):
            self.assertEqual(core.reconcile(receipt, data)["status"], "ok")
            manifest = core.rollback_manifest(receipt, data)
        self.assertEqual(len(manifest["actions"]), 2)
        self.assertTrue(all(item["action"] == "remove_adopted_copy" for item in manifest["actions"]))

    def test_altered_source_fails_before_any_copy(self) -> None:
        path = self.source / self.specs[0].source_relative
        with path.open("ab") as stream:
            stream.write(b"altered")
        data = self.root / "local-data"
        repository = self.root / "repository"
        repository.mkdir(exist_ok=True)
        with patch.object(core, "BASELINES", tuple(self.specs)), \
             patch.object(core, "_runtime_versions", return_value={}), \
             patch.object(core, "_repository_revision", return_value="a" * 40):
            with self.assertRaisesRegex(core.AdoptionError, "byte size mismatch"):
                core.adopt(self.source, data, repository=repository)
        self.assertFalse((data / "databases").exists())

    def test_refuses_overwrite_and_historical_destination(self) -> None:
        data, _ = self._adopt()
        repository = self.root / "repository"
        with patch.object(core, "BASELINES", tuple(self.specs)), \
             patch.object(core, "_runtime_versions", return_value={}), \
             patch.object(core, "_repository_revision", return_value="a" * 40):
            with self.assertRaisesRegex(core.AdoptionError, "overwrite"):
                core.adopt(self.source, data, repository=repository)
        with self.assertRaisesRegex(core.AdoptionError, "historical"):
            core._validate_roots(
                self.source, self.root / "giga-user/market-aligner/data", repository
            )

    def test_reconcile_detects_dirty_copy_and_receipt(self) -> None:
        data, receipt = self._adopt()
        destination = data / self.specs[0].destination_relative
        with destination.open("ab") as stream:
            stream.write(b"dirty")
        with patch.object(core, "BASELINES", tuple(self.specs)):
            with self.assertRaises(core.AdoptionError):
                core.reconcile(receipt, data)
        receipt.rename(receipt.with_name("migration-" + "0" * 64 + ".json"))
        with self.assertRaisesRegex(core.AdoptionError, "filename mismatch"):
            core._load_receipt(receipt.with_name("migration-" + "0" * 64 + ".json"))

    def test_missing_dependency_fails_loudly(self) -> None:
        with patch.object(core, "REQUIRED_DISTRIBUTIONS", ("certainly-not-installed-jaa",)):
            with self.assertRaisesRegex(core.AdoptionError, "missing runtime dependencies"):
                core._runtime_versions()

    def test_canonical_marker_rejects_historical_or_implicit_import_contracts(self) -> None:
        repository = self.root / "repository"
        repository.mkdir()
        with self.assertRaisesRegex(core.AdoptionError, "marker"):
            core._validate_canonical_marker(repository)
        marker = {
            "schema_version": 1,
            "canonical_repository": {
                "id": "market-aligner", "product_name": "Market Aligner", "status": "active"
            },
            "brownfield_import_contract": {
                "implicit_host_paths": True,
                "required_operator_paths": ["source_root", "runtime_data_root", "repository_root"],
            },
        }
        (repository / core.CANONICAL_MARKER).write_text(json.dumps(marker), encoding="utf-8")
        with self.assertRaisesRegex(core.AdoptionError, "active Market Aligner"):
            core._validate_canonical_marker(repository)

    def test_dirty_sqlite_sidecar_is_rejected(self) -> None:
        sidecar = Path(str(self.source / self.specs[0].source_relative) + "-wal")
        sidecar.touch()
        with self.assertRaisesRegex(core.AdoptionError, "live or dirty"):
            core._verify_database(self.source / self.specs[0].source_relative, self.specs[0])

    def test_online_backup_freezes_live_wal_and_preserves_historical_observation(self) -> None:
        writers = []
        try:
            for spec in self.specs:
                path = self.source / spec.source_relative
                writer = sqlite3.connect(path)
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("INSERT INTO records(value) VALUES ('newly-observed')")
                writer.commit()
                writers.append(writer)

            data = self.root / "online-data"
            repository = self.root / "repository"
            repository.mkdir(exist_ok=True)
            with patch.object(core, "BASELINES", tuple(self.specs)), \
                 patch.object(core, "_runtime_versions", return_value={"python": "test"}), \
                 patch.object(core, "_repository_revision", return_value="b" * 40):
                receipt = core.adopt_online(self.source, data, repository=repository)
                document = json.loads(receipt.read_text())
                self.assertEqual(document["content"]["format"],
                                 "jaa-00-online-snapshot-receipt/v2")
                for spec in self.specs:
                    record = document["content"]["databases"][spec.name]
                    self.assertEqual(record["historical_observation"]["observed_table_counts"],
                                     {"records": 1})
                    self.assertEqual(record["frozen_snapshot"]["table_counts"], {"records": 2})
                    self.assertEqual(record["capture"]["method"], "sqlite-online-backup")
                    self.assertEqual(record["capture"]["source_identities_start"]["wal"]["label"],
                                     f"source:{spec.name}:wal")
                    self.assertNotIn(str(self.root), json.dumps(record))
                self.assertEqual(core.reconcile(receipt, data)["status"], "ok")

            with patch.object(core, "BASELINES", tuple(self.specs)):
                with self.assertRaisesRegex(core.AdoptionError, "live or dirty"):
                    core._verify_database(
                        self.source / self.specs[0].source_relative, self.specs[0]
                    )
        finally:
            for writer in writers:
                writer.close()


if __name__ == "__main__":
    unittest.main()
