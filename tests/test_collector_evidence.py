from __future__ import annotations

import base64
import io
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import quote

from market_aligner.applications.canonical import ContractValidationError, digest_bytes
from market_aligner.assessment.geography import LocationFacts
from market_aligner.collectors import scrapling_worker
from market_aligner.collectors.engine import Collector
from market_aligner.collectors.evidence import (
    sanitized_attempts,
    sanitized_transport_receipt,
    sanitized_worker_response,
    validate_handoff_listing_evidence,
    validate_public_listing_url,
)
from market_aligner.collectors.scrapling_client import (
    ScraplingClient,
    ScraplingError,
    ScraplingFetchError,
)
from market_aligner.collectors.scrapling_worker import _response_to_dict
from market_aligner.domain.contracts import JobUrl, RawPosting
from market_aligner.state.vacancies import JobDatabase


AUTH_CANARY = "Bearer AUTHORIZATION_CANARY_1234567890"
COOKIE_CANARY = "session=COOKIE_CANARY_1234567890"
REDIRECT_CANARY = "https://redirect.example.test/REDIRECT_CANARY"
XHR_CANARY = "XHR_CANARY_1234567890"
META_CANARY = "TRANSPORT_META_CANARY_1234567890"
CREDENTIAL_URL_CANARY = (
    "https://jobs.example.test/vacancies/unsafe?access_token=CREDENTIAL_URL_CANARY_1234567890"
)
EXCEPTION_CANARY = "EXCEPTION_CANARY_1234567890"


def _percent_layers(value: str, count: int) -> bytes:
    for _ in range(count):
        value = quote(value, safe="")
    return value.encode("ascii")


EMBEDDED_URL_CANARIES = (
    (
        "http_userinfo",
        b'<a href="http://alice:session-secret@example.test/vacancy">vacancy</a>',
    ),
    (
        "http_query_secret",
        b"http://jobs.example.test/vacancy?access_token=URL_CANARY_1234567890",
    ),
    (
        "http_fragment_secret",
        b"http://jobs.example.test/vacancy#token=URL_CANARY_1234567890",
    ),
    (
        "protocol_relative_userinfo",
        b"//alice:session-secret@example.test/vacancy",
    ),
    (
        "protocol_relative_backslash_userinfo",
        br"\\alice:session-secret@example.test/vacancy",
    ),
    (
        "protocol_relative_four_backslashes_userinfo",
        br"\\\\alice:session-secret@example.test/vacancy",
    ),
    (
        "protocol_relative_mixed_slashes_userinfo",
        br"\\/alice:session-secret@example.test/vacancy",
    ),
    (
        "percent_protocol_relative_backslash_userinfo",
        b"%5C%5Calice%3Asession-secret%40example.test/vacancy",
    ),
    (
        "html_protocol_relative_backslash_userinfo",
        b"&#92;&#92;alice&#58;session-secret&#64;example.test/vacancy",
    ),
    (
        "json_unicode_protocol_relative_backslash_userinfo",
        br"\u005c\u005calice:session-secret@example.test/vacancy",
    ),
    (
        "nested_protocol_relative_backslash_userinfo",
        b"%255C%255Calice%253Asession-secret%2540example.test/vacancy",
    ),
    (
        "mixed_case_userinfo",
        b"HtTpS://alice:session-secret@example.test/vacancy",
    ),
    (
        "html_escaped_userinfo",
        b"https&#58;//alice:session-secret@example.test/vacancy",
    ),
    (
        "json_escaped_userinfo",
        br"https:\/\/alice:session-secret@example.test/vacancy",
    ),
    (
        "percent_escaped_userinfo",
        b"https%3A%2F%2Falice%3Asession-secret%40example.test/vacancy",
    ),
    (
        "single_label_protocol_relative_userinfo",
        b"//alice:session-secret@intranet/vacancy",
    ),
    (
        "unicode_protocol_relative_userinfo",
        "//alice:session-secret@例え/vacancy".encode(),
    ),
    (
        "nested_credential_url",
        b"https://jobs.example.test/v?next=http://alice:session-secret@example.test/private",
    ),
    (
        "double_percent_nested_credential_url",
        b"https://jobs.example.test/v?next=http%253A%252F%252Falice%253Asession-secret%2540example.test/private",
    ),
    (
        "empty_userinfo",
        b"https://@example.test/vacancy",
    ),
    (
        "backslash_authority",
        br"https:\\alice:session-secret@example.test/vacancy",
    ),
    (
        "html_control_userinfo",
        b"https&#58;&#47;&#47;alice&#9;&#58;session-secret&#64;example.test/vacancy",
    ),
    (
        "percent_control_userinfo",
        b"https%3A%2F%2Falice%09%3Asession-secret%40example.test/vacancy",
    ),
    (
        "five_layer_percent_userinfo",
        _percent_layers(
            "https://alice:session-secret@example.test/vacancy", 5
        ),
    ),
    (
        "six_layer_percent_userinfo",
        _percent_layers(
            "https://alice:session-secret@example.test/vacancy", 6
        ),
    ),
    (
        "decode_bound_percent_userinfo",
        _percent_layers(
            "https://alice:session-secret@example.test/vacancy", 33
        ),
    ),
    (
        "semicolon_query_secret",
        b"https://jobs.example.test/v?ref=public;access_token=x",
    ),
    (
        "semicolon_fragment_secret",
        b"https://jobs.example.test/v#ref=public;token=x",
    ),
    (
        "matrix_path_secret",
        b"https://jobs.example.test/v;access_token=x",
    ),
)


def _canary_values(protected_root: Path) -> tuple[str, ...]:
    return (
        AUTH_CANARY,
        COOKIE_CANARY,
        REDIRECT_CANARY,
        XHR_CANARY,
        META_CANARY,
        CREDENTIAL_URL_CANARY,
        str(protected_root.resolve()),
        EXCEPTION_CANARY,
    )


def _assert_canaries_absent(
    case: unittest.TestCase, data: bytes | str, protected_root: Path
) -> None:
    blob = data.encode("utf-8") if isinstance(data, str) else data
    for value in _canary_values(protected_root):
        case.assertNotIn(value.encode("utf-8"), blob)


def _response_with_transport_canaries(body: bytes, protected_root: Path) -> SimpleNamespace:
    return SimpleNamespace(
        body=body,
        status=200,
        encoding="latin-1",
        url=CREDENTIAL_URL_CANARY,
        headers={"Set-Cookie": COOKIE_CANARY},
        request_headers={"Authorization": AUTH_CANARY},
        cookies={"session": COOKIE_CANARY},
        history=[{"url": REDIRECT_CANARY}],
        captured_xhr=[{"body": XHR_CANARY}],
        meta={"runtime_path": str(protected_root), "value": META_CANARY},
    )


def _malicious_worker_mapping(body: bytes, protected_root: Path) -> dict[str, object]:
    captured = _response_to_dict(_response_with_transport_canaries(body, protected_root))
    return {
        **captured,
        "url": CREDENTIAL_URL_CANARY,
        "headers": {"Set-Cookie": COOKIE_CANARY},
        "request_headers": {"Authorization": AUTH_CANARY},
        "cookies": {"session": COOKIE_CANARY},
        "history": [{"url": REDIRECT_CANARY}],
        "captured_xhr": [{"body": XHR_CANARY}],
        "meta": {"runtime_path": str(protected_root), "value": META_CANARY},
        "text": EXCEPTION_CANARY,
    }


class CollectorEvidenceBoundaryTests(unittest.TestCase):
    def test_embedded_url_forms_are_scanned_at_every_public_evidence_boundary(
        self,
    ) -> None:
        for name, exact in EMBEDDED_URL_CANARIES:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                worker_response = {
                    "body_base64": base64.b64encode(exact).decode("ascii"),
                    "body_bytes": len(exact),
                    "encoding": "utf-8",
                    "status": 200,
                }
                with self.assertRaises(ContractValidationError):
                    sanitized_worker_response(worker_response)

                database = JobDatabase(root / "vacancies.sqlite3")
                job = JobUrl(
                    "capture",
                    "url-canary",
                    "https://jobs.example.test/vacancies/url-canary",
                    discovered_at="2026-08-10T09:59:00Z",
                )
                database.upsert_discovered(job)
                with self.assertRaises(ContractValidationError):
                    database.store_raw(
                        RawPosting(
                            board=job.board,
                            job_id=job.job_id,
                            url=job.url,
                            fetched_at="2026-08-10T10:00:00Z",
                            content_type="text/html",
                            http_status=200,
                            public_content_base64=base64.b64encode(exact).decode(
                                "ascii"
                            ),
                        )
                    )
                with database.connect() as connection:
                    self.assertEqual(
                        (0, 0),
                        (
                            connection.execute(
                                "SELECT COUNT(*) FROM posting_raw_snapshots"
                            ).fetchone()[0],
                            connection.execute(
                                "SELECT COUNT(*) FROM posting_raw_snapshot_heads"
                            ).fetchone()[0],
                        ),
                    )

                evidence = {
                    "adapter": job.board,
                    "canonical_url": job.url,
                    "content_base64": base64.b64encode(exact).decode("ascii"),
                    "content_sha256": digest_bytes(exact),
                    "fetched_at": "2026-08-10T10:00:00Z",
                    "job_key": "job_" + "0" * 64,
                    "schema_version": "market-aligner.raw-listing-evidence.v1",
                    "source_job_id": job.job_id,
                }
                with self.assertRaises(ContractValidationError):
                    validate_handoff_listing_evidence(evidence, protected_roots=(root,))

        safe_controls = (
            b'<a href="https://jobs.example.test/vacancy?ref=public#description">role</a>',
            b"See https://[2606:4700:4700::1111].",
            b"https://jobs.example.test/vacancy?ref=ordinary%20public%20value",
            b"Safe prose about HTTP 2, arithmetic 1 // 2, and the C++ // operator.",
            br"Safe Windows path C:\Users\candidate\notes.txt.",
            br"Safe UNC prose \\fileserver\shared-folder.",
        )
        for exact in safe_controls:
            with self.subTest(safe=exact), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                worker_response = {
                    "body_base64": base64.b64encode(exact).decode("ascii"),
                    "body_bytes": len(exact),
                    "encoding": "utf-8",
                    "status": 200,
                }
                self.assertEqual(
                    exact,
                    base64.b64decode(
                        sanitized_worker_response(worker_response)["body_base64"]
                    ),
                )
                database = JobDatabase(root / "vacancies.sqlite3")
                job = JobUrl(
                    "capture",
                    "safe-url-text",
                    "https://jobs.example.test/vacancies/safe-url-text",
                    discovered_at="2026-08-10T09:59:00Z",
                )
                database.upsert_discovered(job)
                database.store_raw(
                    RawPosting(
                        board=job.board,
                        job_id=job.job_id,
                        url=job.url,
                        fetched_at="2026-08-10T10:00:00Z",
                        content_type="text/html",
                        http_status=200,
                        public_content_base64=base64.b64encode(exact).decode("ascii"),
                    )
                )
                stored = database.load_current_raw_snapshot(job.key)
                evidence = {
                    "adapter": job.board,
                    "canonical_url": job.url,
                    "content_base64": stored.public_content_base64,
                    "content_sha256": digest_bytes(exact),
                    "fetched_at": stored.fetched_at,
                    "job_key": "job_" + "0" * 64,
                    "schema_version": "market-aligner.raw-listing-evidence.v1",
                    "source_job_id": job.job_id,
                }
                self.assertEqual(
                    exact,
                    validate_handoff_listing_evidence(
                        evidence, protected_roots=(root,)
                    ),
                )

    def test_discovery_url_rejects_normalized_credentials_and_malformed_authority(
        self,
    ) -> None:
        unsafe = (
            "https://alice%3Asession-secret%40example.test/v",
            "https://alice:session-secret%40example.test/v",
            "https://jobs.example.test/v#token%3Dsecret-value",
            "https://@example.test/v",
            "https://:443/v",
            "https://localhost/v",
            "https://127.0.0.1/v",
            "https://[::1]/v",
            r"https:\\alice:session-secret@example.test/v",
            "https://jobs.example.test/v?next=http%253A%252F%252Falice%253Asession-secret%2540example.test/private",
            _percent_layers(
                "https://alice:session-secret@example.test/v", 5
            ).decode("ascii"),
            _percent_layers(
                "https://jobs.example.test/v#token=secret-value", 6
            ).decode("ascii"),
            _percent_layers(
                "https://alice:session-secret@example.test/v", 33
            ).decode("ascii"),
            "https://jobs.example.test/v?ref=public;access_token=x",
            "https://jobs.example.test/v#ref=public;token=x",
            "https://jobs.example.test/v;access_token=x",
            "https://exa mple.test/v",
            r"https://example.test\x00.evil/v",
        )
        for url in unsafe:
            with self.subTest(url=url):
                with self.assertRaises(ContractValidationError):
                    validate_public_listing_url(url)

        with tempfile.TemporaryDirectory() as temporary:
            database = JobDatabase(Path(temporary) / "vacancies.sqlite3")
            for index, url in enumerate(unsafe):
                with self.subTest(persistence_url=url):
                    with self.assertRaises(ContractValidationError):
                        database.upsert_discovered(
                            JobUrl(
                                "unsafe",
                                f"url-{index}",
                                url,
                                discovered_at="2026-08-10T09:59:00Z",
                            )
                        )
            with database.connect() as connection:
                self.assertEqual(
                    0,
                    connection.execute("SELECT COUNT(*) FROM postings").fetchone()[0],
                )

        for url in (
            "https://jobs.example.test/v?ref=ordinary%20public%20value",
            "https://jobs.example.test/v?next=https%3A%2F%2Fsafe.example.test%2Fpublic",
            "https://jobs.example.test./vacancy",
            "https://[2606:4700:4700::1111]/vacancy",
        ):
            with self.subTest(url=url):
                validate_public_listing_url(url)

    def test_capture_allowlist_retains_exact_public_bytes_and_digest(self) -> None:
        public_bytes = b"\xff<html><body>Public vacancy evidence.</body></html>"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            captured = _response_to_dict(_response_with_transport_canaries(public_bytes, root))
            self.assertEqual(
                {"body_base64", "body_bytes", "encoding", "status", "text"},
                set(captured),
            )
            self.assertEqual(public_bytes, base64.b64decode(captured["body_base64"]))
            safe = sanitized_worker_response(_malicious_worker_mapping(public_bytes, root))
            self.assertEqual(captured, safe)
            receipt = sanitized_transport_receipt(safe, engine="static")
            self.assertEqual(digest_bytes(public_bytes), receipt["content_sha256"])
            self.assertEqual(len(public_bytes), receipt["body_bytes"])
            _assert_canaries_absent(
                self, json.dumps({"response": safe, "receipt": receipt}), root
            )

    def test_plaintext_redirect_and_xhr_markers_fail_at_capture_and_persistence(self) -> None:
        for exact in (
            b"redirect_history=https://redirect.example.test/next",
            b"captured_xhr: POST https://api.example.test/private body=profile",
        ):
            with self.subTest(exact=exact), tempfile.TemporaryDirectory() as temporary:
                worker_response = {
                    "body_base64": base64.b64encode(exact).decode("ascii"),
                    "body_bytes": len(exact),
                    "encoding": "utf-8",
                    "status": 200,
                }
                with self.assertRaisesRegex(
                    ContractValidationError, "plaintext transport diagnostics"
                ):
                    sanitized_worker_response(worker_response)

                database = JobDatabase(Path(temporary) / "vacancies.sqlite3")
                job = JobUrl(
                    "capture",
                    "42",
                    "https://jobs.example.test/vacancies/42",
                    discovered_at="2026-08-10T09:59:00Z",
                )
                database.upsert_discovered(job)
                with self.assertRaisesRegex(
                    ContractValidationError, "plaintext transport diagnostics"
                ):
                    database.store_raw(
                        RawPosting(
                            board=job.board,
                            job_id=job.job_id,
                            url=job.url,
                            fetched_at="2026-08-10T10:00:00Z",
                            content_type="text/plain",
                            http_status=200,
                            public_content_base64=base64.b64encode(exact).decode("ascii"),
                        )
                    )
                with database.connect() as connection:
                    self.assertEqual(
                        0,
                        connection.execute(
                            "SELECT COUNT(*) FROM posting_raw_snapshots"
                        ).fetchone()[0],
                    )

    def test_protected_path_in_public_body_fails_at_worker_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            exact = str(root).encode("utf-8")
            worker_response = {
                "body_base64": base64.b64encode(exact).decode("ascii"),
                "body_bytes": len(exact),
                "encoding": "utf-8",
                "status": 200,
            }
            with self.assertRaisesRegex(
                ContractValidationError, "protected local path"
            ):
                sanitized_worker_response(worker_response, protected_roots=(root,))

    def test_worker_and_client_errors_expose_only_fixed_codes(self) -> None:
        public_bytes = b"<html>Public vacancy.</html>"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = io.StringIO()
            with (
                mock.patch.object(
                    scrapling_worker,
                    "execute",
                    side_effect=RuntimeError(EXCEPTION_CANARY),
                ),
                mock.patch.object(scrapling_worker.sys, "stdin", io.StringIO("{}")),
                mock.patch.object(scrapling_worker.sys, "stdout", output),
            ):
                self.assertEqual(1, scrapling_worker.main())
            self.assertIn('"error":"worker_error"', output.getvalue())
            _assert_canaries_absent(self, output.getvalue(), root)

            client = ScraplingClient(
                root,
                {
                    "fallback_chain": [{"engine": "static", "kwargs": {}}],
                    "minimum_body_bytes": 1,
                },
            )
            malicious = _malicious_worker_mapping(public_bytes, root)
            with mock.patch.object(client, "execute", return_value=malicious):
                result = client.fetch_with_chain("https://jobs.example.test/vacancies/42")
            safe_blob = json.dumps(
                {"attempts": result.attempts, "response": result.response}, sort_keys=True
            )
            _assert_canaries_absent(self, safe_blob, root)
            self.assertEqual(public_bytes, base64.b64decode(result.response["body_base64"]))
            self.assertEqual(result.attempts, sanitized_attempts(list(result.attempts)))
            dirty_attempt = {
                **result.attempts[0],
                "headers": {"Authorization": AUTH_CANARY},
                "redirect": REDIRECT_CANARY,
                "runtime_path": str(root),
            }
            self.assertEqual(result.attempts, sanitized_attempts([dirty_attempt]))

            protected_body = _malicious_worker_mapping(
                str(root.resolve()).encode("utf-8"), root
            )
            with mock.patch.object(client, "execute", return_value=protected_body):
                with self.assertRaises(ScraplingFetchError) as protected_error:
                    client.fetch_with_chain("https://jobs.example.test/vacancies/42")
            self.assertEqual(
                "invalid_worker_response",
                protected_error.exception.attempts[0]["error_code"],
            )

            with mock.patch.object(
                client, "execute", side_effect=ScraplingError(EXCEPTION_CANARY)
            ):
                with self.assertRaises(ScraplingFetchError) as raised:
                    client.fetch_with_chain("https://jobs.example.test/vacancies/42")
            error_blob = json.dumps(
                {"message": str(raised.exception), "attempts": raised.exception.attempts}
            )
            self.assertIn("worker_error", error_blob)
            _assert_canaries_absent(self, error_blob, root)

    def test_cycle_persists_exact_public_bytes_without_transport_data(self) -> None:
        public_bytes = b"\xff<html><body>Public vacancy evidence retained exactly.</body></html>"

        class FallbackAdapter:
            def discover(self, _terms, live=False):
                self.live = live
                yield JobUrl(
                    "capture",
                    "42",
                    "https://jobs.example.test/vacancies/42",
                )

            def fetch(self, _row, live=False):
                raise RuntimeError(EXCEPTION_CANARY)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs: list[str] = []
            collector = Collector(
                {
                    "boards": {"enabled": ["capture"]},
                    "capture": {"minimum_poll_minutes": 0},
                    "collection": {"fetch_workers": 1, "source_workers": 1},
                },
                root,
                log=logs.append,
            )
            client = ScraplingClient(
                root,
                {
                    "fallback_chain": [{"engine": "static", "kwargs": {}}],
                    "minimum_body_bytes": 1,
                },
            )
            collector.scrapling = client
            malicious = _malicious_worker_mapping(public_bytes, root)
            with (
                mock.patch(
                    "market_aligner.collectors.engine.load_adapter",
                    return_value=FallbackAdapter(),
                ),
                mock.patch.object(client, "execute", return_value=malicious),
            ):
                result = collector.cycle()

            self.assertEqual(1, result["fetched"])
            self.assertEqual(0, result["errors"])
            expected_digest = digest_bytes(public_bytes)
            stored = collector.db.load_raw_snapshot("capture:42", expected_digest)
            self.assertEqual(
                public_bytes,
                base64.b64decode(stored.public_content_base64, validate=True),
            )
            with collector.db.connect() as conn:
                posting = conn.execute(
                    "SELECT content_hash,fetch_error,fetch_status FROM postings WHERE key=?",
                    ("capture:42",),
                ).fetchone()
            self.assertEqual((expected_digest, None, "fetched"), posting)

            raw_files = list((root / "raw" / "vacancies").rglob("*.json"))
            self.assertEqual(1, len(raw_files))
            raw_value = json.loads(raw_files[0].read_text(encoding="utf-8"))
            self.assertEqual(expected_digest, raw_value["content_sha256"])
            self.assertEqual(
                public_bytes,
                base64.b64decode(raw_value["public_content_base64"], validate=True),
            )

            handoff_evidence = {
                "adapter": "capture",
                "canonical_url": raw_value["url"],
                "content_base64": raw_value["public_content_base64"],
                "content_sha256": raw_value["content_sha256"],
                "fetched_at": raw_value["fetched_at"],
                "job_key": "capture:42",
                "schema_version": "market-aligner.raw-listing-evidence.v1",
                "source_job_id": "42",
            }
            self.assertEqual(
                public_bytes,
                validate_handoff_listing_evidence(
                    handoff_evidence, protected_roots=(root,)
                ),
            )

            receipt_files = list((root / "state" / "transport-receipts").rglob("*.json"))
            self.assertEqual(1, len(receipt_files))
            receipt = json.loads(receipt_files[0].read_text(encoding="utf-8"))
            self.assertEqual(expected_digest, receipt["attempts"][0]["content_sha256"])
            corpus = b"".join(
                path.read_bytes() for path in root.rglob("*") if path.is_file()
            )
            _assert_canaries_absent(self, corpus, root)
            _assert_canaries_absent(self, "\n".join(logs), root)

    def test_forbidden_capture_fails_before_downstream_state(self) -> None:
        class ForbiddenAdapter:
            def __init__(self, protected_root: Path) -> None:
                self.protected_root = protected_root

            def discover(self, _terms, live=False):
                yield JobUrl("unsafe", "credential-url", CREDENTIAL_URL_CANARY)
                yield JobUrl(
                    "unsafe", "transport-payload", "https://jobs.example.test/safe"
                )

            def fetch(self, row, live=False):
                return RawPosting(
                    row.board,
                    row.job_id,
                    row.url,
                    "2026-08-10T10:00:00Z",
                    raw_json={
                        "request_headers": {"Authorization": AUTH_CANARY},
                        "cookies": [COOKIE_CANARY],
                        "redirects": [REDIRECT_CANARY],
                        "captured_xhr": [XHR_CANARY],
                        "browser_meta": {
                            "canary": META_CANARY,
                            "runtime_path": str(self.protected_root),
                        },
                        "exception": EXCEPTION_CANARY,
                    },
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            logs: list[str] = []
            collector = Collector(
                {
                    "boards": {"enabled": ["unsafe"]},
                    "unsafe": {"minimum_poll_minutes": 0},
                    "collection": {"fetch_workers": 1, "source_workers": 1},
                },
                root,
                log=logs.append,
            )
            with mock.patch(
                "market_aligner.collectors.engine.load_adapter",
                return_value=ForbiddenAdapter(root),
            ):
                result = collector.cycle()
            self.assertEqual(0, result["fetched"])
            self.assertEqual(2, result["errors"])
            with collector.db.connect() as conn:
                self.assertEqual(1, conn.execute("SELECT COUNT(*) FROM postings").fetchone()[0])
                self.assertEqual(
                    0,
                    conn.execute(
                        "SELECT COUNT(*) FROM posting_raw_snapshots"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    0, conn.execute("SELECT COUNT(*) FROM normalised_jobs").fetchone()[0]
                )
                self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM scores").fetchone()[0])
                state = conn.execute(
                    "SELECT fetch_status,fetch_error FROM postings"
                ).fetchone()
            self.assertEqual(("error", "fetch_error"), state)
            self.assertFalse((root / "raw" / "vacancies").exists())
            corpus = b"".join(
                path.read_bytes() for path in root.rglob("*") if path.is_file()
            )
            _assert_canaries_absent(self, corpus, root)
            _assert_canaries_absent(self, "\n".join(logs), root)

    def test_handoff_boundary_rejects_transport_or_nonpublic_evidence(self) -> None:
        public_bytes = b'{"description":"Public vacancy"}'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = {
                "adapter": "synthetic",
                "canonical_url": "https://jobs.example.test/vacancies/42",
                "content_base64": base64.b64encode(public_bytes).decode("ascii"),
                "content_sha256": digest_bytes(public_bytes),
                "fetched_at": "2026-08-10T10:00:00Z",
                "job_key": "synthetic:42",
                "schema_version": "market-aligner.raw-listing-evidence.v1",
                "source_job_id": "42",
            }
            self.assertEqual(
                public_bytes,
                validate_handoff_listing_evidence(payload, protected_roots=(root,)),
            )

            transport_payload = deepcopy(payload)
            transport_payload["transport_meta"] = META_CANARY
            credential_payload = deepcopy(payload)
            credential_payload["canonical_url"] = CREDENTIAL_URL_CANARY
            protected_bytes = str(root.resolve()).encode("utf-8")
            protected_payload = deepcopy(payload)
            protected_payload["content_base64"] = base64.b64encode(protected_bytes).decode(
                "ascii"
            )
            protected_payload["content_sha256"] = digest_bytes(protected_bytes)
            secret_bytes = AUTH_CANARY.encode("utf-8")
            secret_payload = deepcopy(payload)
            secret_payload["content_base64"] = base64.b64encode(secret_bytes).decode("ascii")
            secret_payload["content_sha256"] = digest_bytes(secret_bytes)
            digest_payload = deepcopy(payload)
            digest_payload["content_sha256"] = "0" * 64

            decoded_canary_payloads = []
            for decoded in (
                {"cookies": [COOKIE_CANARY]},
                {"request_headers": {"Authorization": AUTH_CANARY}},
                {"redirects": [REDIRECT_CANARY]},
                {"captured_xhr": [{"body": XHR_CANARY}]},
                {"listing_url": CREDENTIAL_URL_CANARY},
            ):
                exact = json.dumps(decoded, sort_keys=True).encode("utf-8")
                candidate = deepcopy(payload)
                candidate["content_base64"] = base64.b64encode(exact).decode("ascii")
                candidate["content_sha256"] = digest_bytes(exact)
                decoded_canary_payloads.append(candidate)

            for exact in (
                b"redirect_history=https://redirect.example.test/next",
                b"captured_xhr: POST https://api.example.test/private body=profile",
            ):
                candidate = deepcopy(payload)
                candidate["content_base64"] = base64.b64encode(exact).decode("ascii")
                candidate["content_sha256"] = digest_bytes(exact)
                decoded_canary_payloads.append(candidate)

            for bad in (
                transport_payload,
                credential_payload,
                protected_payload,
                secret_payload,
                digest_payload,
                *decoded_canary_payloads,
            ):
                with self.subTest(keys=sorted(bad)):
                    with self.assertRaises(ContractValidationError):
                        validate_handoff_listing_evidence(bad, protected_roots=(root,))


class LocationSourcePointerTests(unittest.TestCase):
    @staticmethod
    def _facts(pointer: str) -> LocationFacts:
        return LocationFacts(
            "GB",
            "",
            "",
            "United Kingdom remote",
            "remote",
            "explicit",
            pointer,
        )

    def test_typed_json_pointer_and_public_byte_span_are_accepted(self) -> None:
        for pointer in (
            "json:/job/location",
            "json:/job/~0escaped/~1slash",
            "text:bytes=0-21",
        ):
            with self.subTest(pointer=pointer):
                self.assertEqual(pointer, self._facts(pointer).source_pointer)

    def test_untyped_or_malformed_source_pointer_is_rejected(self) -> None:
        for pointer in (
            "/job/location",
            "json:job/location",
            "json:/job/~2invalid",
            "text:0-21",
            "text:bytes=01-21",
            "text:bytes=21-21",
            "text:bytes=22-21",
        ):
            with self.subTest(pointer=pointer):
                with self.assertRaisesRegex(ContractValidationError, "source_pointer"):
                    self._facts(pointer)


if __name__ == "__main__":
    unittest.main()
