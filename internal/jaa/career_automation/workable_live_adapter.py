"""Certified one-use Workable form execution.

Inventory and prefill are non-consequential and produce a hash-only review.
The final click requires an exact JAA-08 release authority, clean committed
source identity, unchanged DOM, and a durable one-use journal.  No state after
``click_started`` is retryable without risking a duplicate application.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping
from urllib.parse import parse_qsl, urlsplit

from playwright.sync_api import Page

from .ashby_live_adapter import JAA08ReleaseAuthority
from .provider_observation_capture import exact_clean_head


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
SOURCE_PATHS = ("career_automation/workable_live_adapter.py",)


class WorkableBoundaryError(RuntimeError):
    """The browser or policy left the exact Workable application boundary."""


class WorkableSchemaError(RuntimeError):
    """The live form differs from its reviewed field contract."""


class WorkableCircuitError(RuntimeError):
    """The durable one-use circuit rejected a transition."""


class WorkableSubmissionIndeterminateError(RuntimeError):
    """A click may have occurred and the application must not be retried."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _content_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or HEX_64.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _regular_file(path: Path, expected_sha256: str) -> Path:
    _digest(expected_sha256, "upload hash")
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("approved upload is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("approved upload must be a regular non-symlink file")
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    after = path.lstat()
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
    )
    if identity(before) != identity(after) or digest != expected_sha256:
        raise ValueError("approved upload differs from its bound bytes")
    return resolved


def _source_identity(repository_root: Path) -> tuple[str, tuple[tuple[str, str], ...]]:
    head = exact_clean_head(repository_root)
    prefix_process = subprocess.run(
        ["git", "-C", str(repository_root), "rev-parse", "--show-prefix"],
        check=True,
        capture_output=True,
        text=True,
    )
    prefix = prefix_process.stdout.strip()
    if prefix and not prefix.endswith("/"):
        raise ValueError("Workable source prefix is invalid")
    rows: list[tuple[str, str]] = []
    for relative in SOURCE_PATHS:
        committed = subprocess.run(
            ["git", "-C", str(repository_root), "show", f"{head}:{prefix}{relative}"],
            check=True,
            capture_output=True,
        ).stdout
        if committed != (repository_root / relative).read_bytes():
            raise ValueError("Workable executor differs from exact clean HEAD")
        rows.append((relative, hashlib.sha256(committed).hexdigest()))
    return head, tuple(rows)


@dataclass(frozen=True)
class WorkableField:
    name: str
    field_type: str
    required: bool
    label: str

    def __post_init__(self) -> None:
        if SAFE_COMPONENT.fullmatch(self.name) is None:
            raise ValueError("Workable field name is unsafe")
        if self.field_type not in {"text", "email", "url", "tel", "textarea", "select", "checkbox", "file"}:
            raise ValueError("Workable field type is unsupported")
        if not self.label.strip():
            raise ValueError("Workable field label is required")

    def document(self) -> dict[str, object]:
        return {
            "field_type": self.field_type,
            "label": self.label,
            "name": self.name,
            "required": self.required,
        }


@dataclass(frozen=True)
class WorkablePolicy:
    tenant: str
    vacancy_id: str
    fields: tuple[WorkableField, ...]
    submit_label: str = "Submit application"
    success_marker: str = "Your application has been submitted successfully."
    version: str = "v1"

    def __post_init__(self) -> None:
        if SAFE_COMPONENT.fullmatch(self.tenant) is None or SAFE_COMPONENT.fullmatch(self.vacancy_id) is None:
            raise ValueError("Workable policy route identity is invalid")
        if not self.fields or len({row.name for row in self.fields}) != len(self.fields):
            raise ValueError("Workable policy field inventory is invalid")
        if not self.submit_label.strip() or not self.success_marker.strip():
            raise ValueError("Workable policy provider semantics are absent")

    @property
    def application_url(self) -> str:
        return f"https://apply.workable.com/{self.tenant}/j/{self.vacancy_id}/apply/"

    @property
    def inventory_sha256(self) -> str:
        return _content_hash([row.document() for row in self.fields])

    @property
    def policy_sha256(self) -> str:
        return _content_hash(
            {
                "application_url": self.application_url,
                "inventory_sha256": self.inventory_sha256,
                "submit_label": self.submit_label,
                "success_marker_sha256": hashlib.sha256(self.success_marker.encode()).hexdigest(),
                "version": self.version,
            }
        )


@dataclass(frozen=True)
class WorkableUpload:
    path: Path = field(repr=False)
    sha256: str

    def __post_init__(self) -> None:
        _regular_file(self.path, self.sha256)


@dataclass(frozen=True)
class WorkableApplication:
    application_package: bytes = field(repr=False)
    answers: Mapping[str, str | bool] = field(repr=False)
    uploads: Mapping[str, WorkableUpload] = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.application_package, bytes) or not self.application_package:
            raise ValueError("Workable application package must contain exact bytes")
        for name, value in self.answers.items():
            if SAFE_COMPONENT.fullmatch(name) is None or not isinstance(value, (str, bool)):
                raise ValueError("Workable form answer is invalid")
            if isinstance(value, str) and (not value or "\x00" in value or "\r" in value):
                raise ValueError("Workable text answer is invalid")
        if any(SAFE_COMPONENT.fullmatch(name) is None for name in self.uploads):
            raise ValueError("Workable upload field is invalid")
        if any(not isinstance(value, WorkableUpload) for value in self.uploads.values()):
            raise TypeError("Workable uploads must be byte-bound")

    @property
    def package_sha256(self) -> str:
        return hashlib.sha256(self.application_package).hexdigest()

    @property
    def answers_sha256(self) -> str:
        return _content_hash(
            {
                "answers": {
                    name: hashlib.sha256(str(value).encode()).hexdigest()
                    for name, value in sorted(self.answers.items())
                },
                "uploads": {
                    name: value.sha256 for name, value in sorted(self.uploads.items())
                },
            }
        )

    def package_document(self) -> dict[str, object]:
        try:
            document = json.loads(self.application_package)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Workable application package is invalid JSON") from exc
        if (
            not isinstance(document, dict)
            or self.application_package
            != (_canonical_json(document) + "\n").encode("utf-8")
        ):
            raise ValueError("Workable application package is not canonical JSON")
        return document


@dataclass(frozen=True)
class WorkablePreflightReview:
    policy_sha256: str
    package_sha256: str
    answers_sha256: str
    inventory_sha256: str
    dom_sha256: str
    source_head: str
    source_sha256s: tuple[tuple[str, str], ...]
    diagnostic_only: bool = True
    consequential_click_authority: bool = False

    def __post_init__(self) -> None:
        for value in (
            self.policy_sha256,
            self.package_sha256,
            self.answers_sha256,
            self.inventory_sha256,
            self.dom_sha256,
        ):
            _digest(value, "Workable preflight identity")
        if not re.fullmatch(r"[0-9a-f]{40}", self.source_head):
            raise ValueError("Workable source HEAD is invalid")
        if not self.diagnostic_only or self.consequential_click_authority:
            raise ValueError("Workable preflight cannot confer click authority")


@dataclass(frozen=True)
class WorkableSuccessReceipt:
    receipt_sha256: str
    document: Mapping[str, object]

    def __post_init__(self) -> None:
        _digest(self.receipt_sha256, "Workable receipt hash")
        if _content_hash(dict(self.document)) != self.receipt_sha256:
            raise ValueError("Workable receipt differs from its content")


class WorkableOneUseCircuit:
    """Durable state machine plus append-only hash-chained transition journal."""

    STATES = {
        "ready",
        "prepared",
        "release_consumption_started",
        "release_consumed",
        "click_started",
        "succeeded",
        "blocked",
    }

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS workable_circuit (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    state TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    binding_sha256 TEXT,
                    release_manifest_sha256 TEXT,
                    token_sha256 TEXT,
                    reason_code TEXT
                );
                CREATE TABLE IF NOT EXISTS workable_journal (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_sha256 TEXT NOT NULL UNIQUE,
                    document_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS workable_receipt (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    receipt_sha256 TEXT NOT NULL UNIQUE,
                    document_json TEXT NOT NULL
                );
                INSERT OR IGNORE INTO workable_circuit(singleton,state,version)
                VALUES(1,'ready',0);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def snapshot(self) -> dict[str, object | None]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM workable_circuit WHERE singleton=1").fetchone()
        if row is None or str(row["state"]) not in self.STATES:
            raise WorkableCircuitError("Workable circuit state is invalid")
        return dict(row)

    def journal(self) -> tuple[dict[str, object], ...]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM workable_journal ORDER BY sequence").fetchall()
        result: list[dict[str, object]] = []
        previous: str | None = None
        for row in rows:
            document = json.loads(str(row["document_json"]))
            if document.get("previous_event_sha256") != previous or _content_hash(document) != row["event_sha256"]:
                raise WorkableCircuitError("Workable circuit journal is invalid")
            previous = str(row["event_sha256"])
            result.append(document)
        return tuple(result)

    def _transition(
        self,
        expected: str,
        target: str,
        *,
        binding_sha256: str,
        release_manifest_sha256: str | None = None,
        token_sha256: str | None = None,
        reason_code: str | None = None,
    ) -> None:
        _digest(binding_sha256, "Workable binding hash")
        if expected not in self.STATES or target not in self.STATES:
            raise ValueError("Workable transition is unsupported")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM workable_circuit WHERE singleton=1").fetchone()
            if row is None or row["state"] != expected:
                raise WorkableCircuitError("Workable circuit is no longer retryable")
            if row["binding_sha256"] not in {None, binding_sha256}:
                raise WorkableCircuitError("Workable circuit binding changed")
            prior = connection.execute(
                "SELECT event_sha256 FROM workable_journal ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            document = {
                "binding_sha256": binding_sha256,
                "from_state": expected,
                "previous_event_sha256": None if prior is None else str(prior[0]),
                "reason_code": reason_code,
                "release_manifest_sha256": release_manifest_sha256,
                "to_state": target,
                "token_sha256": token_sha256,
                "version": int(row["version"]) + 1,
            }
            event_sha256 = _content_hash(document)
            connection.execute(
                "INSERT INTO workable_journal(event_sha256,document_json) VALUES(?,?)",
                (event_sha256, _canonical_json(document)),
            )
            changed = connection.execute(
                """UPDATE workable_circuit SET state=?,version=version+1,
                   binding_sha256=COALESCE(binding_sha256,?),
                   release_manifest_sha256=COALESCE(release_manifest_sha256,?),
                   token_sha256=COALESCE(token_sha256,?),reason_code=?
                   WHERE singleton=1 AND state=? AND version=?""",
                (
                    target,
                    binding_sha256,
                    release_manifest_sha256,
                    token_sha256,
                    reason_code,
                    expected,
                    int(row["version"]),
                ),
            ).rowcount
            if changed != 1:
                raise WorkableCircuitError("Workable transition lost its lease")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def prepare(self, binding: str) -> None:
        self._transition("ready", "prepared", binding_sha256=binding)

    def consumption_started(self, binding: str) -> None:
        self._transition("prepared", "release_consumption_started", binding_sha256=binding)

    def release_consumed(self, binding: str, manifest: str, token: str) -> None:
        self._transition(
            "release_consumption_started",
            "release_consumed",
            binding_sha256=binding,
            release_manifest_sha256=_digest(manifest, "release manifest"),
            token_sha256=_digest(token, "release token"),
        )

    def click_started(self, binding: str) -> None:
        self._transition(
            "release_consumed",
            "click_started",
            binding_sha256=binding,
            reason_code="submit_result_indeterminate_until_receipt",
        )

    def block(self, binding: str, reason: str) -> None:
        state = str(self.snapshot()["state"])
        if state in {"blocked", "succeeded", "click_started"}:
            return
        self._transition(state, "blocked", binding_sha256=binding, reason_code=reason)

    def succeed(self, binding: str, receipt: WorkableSuccessReceipt) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM workable_circuit WHERE singleton=1").fetchone()
            if row is None or row["state"] != "click_started" or row["binding_sha256"] != binding:
                raise WorkableCircuitError("Workable receipt has no matching started click")
            prior = connection.execute(
                "SELECT event_sha256 FROM workable_journal ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            event = {
                "binding_sha256": binding,
                "from_state": "click_started",
                "previous_event_sha256": None if prior is None else str(prior[0]),
                "reason_code": None,
                "release_manifest_sha256": None,
                "receipt_sha256": receipt.receipt_sha256,
                "to_state": "succeeded",
                "token_sha256": None,
                "version": int(row["version"]) + 1,
            }
            connection.execute(
                "INSERT INTO workable_journal(event_sha256,document_json) VALUES(?,?)",
                (_content_hash(event), _canonical_json(event)),
            )
            connection.execute(
                "INSERT INTO workable_receipt VALUES(1,?,?)",
                (receipt.receipt_sha256, _canonical_json(dict(receipt.document))),
            )
            connection.execute(
                "UPDATE workable_circuit SET state='succeeded',version=version+1,reason_code=NULL WHERE singleton=1"
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


class WorkableLiveAdapter:
    def __init__(self, circuit: WorkableOneUseCircuit, repository_root: Path) -> None:
        self.circuit = circuit
        self.repository_root = Path(repository_root)

    @staticmethod
    def _assert_route(page: Page, policy: WorkablePolicy, *, success: bool = False) -> None:
        parsed = urlsplit(page.url)
        expected = urlsplit(policy.application_url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "apply.workable.com"
            or parsed.port is not None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != expected.path
            or parsed.fragment
            or (query != [("success", "")] if success else bool(query))
        ):
            raise WorkableBoundaryError("page left the exact Workable application route")

    @staticmethod
    def inventory(page: Page) -> tuple[WorkableField, ...]:
        rows = page.locator("input:not([type=submit]), textarea, select").evaluate_all(
            """controls => controls.map(control => {
              const label = control.id
                ? document.querySelector(`label[for="${CSS.escape(control.id)}"]`)
                : null;
              return {
                name: control.name || '',
                field_type: control.tagName.toLowerCase() === 'textarea'
                  ? 'textarea'
                  : (control.tagName.toLowerCase() === 'select'
                    ? 'select' : (control.type || 'text')),
                required: Boolean(control.required),
                label: label ? (label.innerText || '').trim().replace(/\\s+/g, ' ') : ''
              };
            })"""
        )
        try:
            return tuple(
                WorkableField(
                    str(row["name"]),
                    str(row["field_type"]),
                    bool(row["required"]),
                    str(row["label"]),
                )
                for row in rows
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkableSchemaError("Workable inventory cannot be normalized") from exc

    @classmethod
    def _assert_schema(cls, page: Page, policy: WorkablePolicy) -> None:
        cls._assert_route(page, policy)
        if cls.inventory(page) != policy.fields:
            raise WorkableSchemaError("Workable inventory differs from policy")
        submit = page.get_by_role("button", name=policy.submit_label, exact=True)
        if submit.count() != 1 or not submit.is_visible() or not submit.is_enabled():
            raise WorkableSchemaError("Workable submit control is not uniquely actionable")

    @staticmethod
    def _control(page: Page, name: str):
        locator = page.locator(f'[name="{name}"]')
        if locator.count() != 1:
            raise WorkableSchemaError("Workable mapped control is not unique")
        return locator

    @classmethod
    def _fill(cls, page: Page, policy: WorkablePolicy, application: WorkableApplication) -> None:
        answer_fields = {row.name for row in policy.fields if row.field_type != "file"}
        upload_fields = {row.name for row in policy.fields if row.field_type == "file"}
        if set(application.answers) != answer_fields or set(application.uploads) != upload_fields:
            raise WorkableSchemaError("Workable answers differ from the exact field contract")
        for row in policy.fields:
            control = cls._control(page, row.name)
            if row.field_type == "file":
                upload = application.uploads[row.name]
                control.set_input_files(str(_regular_file(upload.path, upload.sha256)))
                if control.evaluate("el => el.files ? el.files.length : 0") != 1:
                    raise WorkableSchemaError("Workable upload was not retained")
                continue
            value = application.answers[row.name]
            if row.field_type == "checkbox":
                if not isinstance(value, bool):
                    raise WorkableSchemaError("Workable checkbox answer is not boolean")
                control.check() if value else control.uncheck()
                if control.is_checked() != value:
                    raise WorkableSchemaError("Workable checkbox answer was not retained")
            elif row.field_type == "select":
                control.select_option(label=str(value))
                if control.locator("option:checked").inner_text() != str(value):
                    raise WorkableSchemaError("Workable select answer was not retained")
            else:
                if not isinstance(value, str):
                    raise WorkableSchemaError("Workable text answer is not text")
                control.fill(value)
                if control.input_value() != value:
                    raise WorkableSchemaError("Workable text answer was not retained")

    @classmethod
    def _assert_values(
        cls,
        page: Page,
        policy: WorkablePolicy,
        application: WorkableApplication,
    ) -> None:
        """Revalidate browser-resident answers without writing to the page."""
        for row in policy.fields:
            control = cls._control(page, row.name)
            if row.field_type == "file":
                upload = application.uploads[row.name]
                expected = _regular_file(upload.path, upload.sha256)
                observed = control.evaluate(
                    "el => el.files && el.files.length === 1 "
                    "? {name: el.files[0].name, size: el.files[0].size} : null"
                )
                if observed != {"name": expected.name, "size": expected.stat().st_size}:
                    raise WorkableSchemaError("Workable upload binding changed")
                continue
            expected_answer = application.answers[row.name]
            if row.field_type == "checkbox":
                if control.is_checked() != expected_answer:
                    raise WorkableSchemaError("Workable checkbox answer changed")
            elif row.field_type == "select":
                if control.locator("option:checked").inner_text() != expected_answer:
                    raise WorkableSchemaError("Workable select answer changed")
            elif control.input_value() != expected_answer:
                raise WorkableSchemaError("Workable text answer changed")

    def prepare_review(
        self,
        page: Page,
        *,
        policy: WorkablePolicy,
        application: WorkableApplication,
    ) -> WorkablePreflightReview:
        """Inventory and prefill only; the returned object cannot authorize a click."""
        self._assert_schema(page, policy)
        self._fill(page, policy, application)
        self._assert_schema(page, policy)
        self._assert_values(page, policy, application)
        head, sources = _source_identity(self.repository_root)
        return WorkablePreflightReview(
            policy.policy_sha256,
            application.package_sha256,
            application.answers_sha256,
            policy.inventory_sha256,
            hashlib.sha256(page.content().encode()).hexdigest(),
            head,
            sources,
        )

    @staticmethod
    def _assert_package(
        policy: WorkablePolicy,
        application: WorkableApplication,
        authority: JAA08ReleaseAuthority,
    ) -> None:
        source = authority.source
        expected_job_key = f"workable:{policy.tenant}:{policy.vacancy_id}"
        document = application.package_document()
        if (
            document.get("schema_version")
            != "jaa.workable-application-package.v1"
            or document.get("job_key") != expected_job_key
            or document.get("application_url") != policy.application_url
            or document.get("form_answers_sha256") != application.answers_sha256
            or document.get("vacancy_sha256")
            != getattr(source, "vacancy_sha256", None)
            or document.get("application_source_sha256")
            != getattr(source, "content_sha256", None)
            or getattr(source, "job_key", None) != expected_job_key
        ):
            raise WorkableSchemaError(
                "Workable package, vacancy, answers, and release source differ"
            )

    @staticmethod
    def _binding(
        policy: WorkablePolicy,
        application: WorkableApplication,
        review: WorkablePreflightReview,
        authority: JAA08ReleaseAuthority,
    ) -> str:
        return _content_hash(
            {
                "answers_sha256": application.answers_sha256,
                "application_package_sha256": application.package_sha256,
                "application_url": policy.application_url,
                "dom_sha256": review.dom_sha256,
                "inventory_sha256": policy.inventory_sha256,
                "policy_sha256": policy.policy_sha256,
                "release_manifest_sha256": authority.release_manifest_sha256,
                "source_head": review.source_head,
                "source_sha256s": dict(review.source_sha256s),
                "tenant": policy.tenant,
                "token_sha256": authority.token_sha256,
                "vacancy_id": policy.vacancy_id,
            }
        )

    def submit(
        self,
        page: Page,
        *,
        policy: WorkablePolicy,
        application: WorkableApplication,
        review: WorkablePreflightReview,
        authority: JAA08ReleaseAuthority,
    ) -> WorkableSuccessReceipt:
        """Consume one release token and dispatch at most one final click."""
        if type(review) is not WorkablePreflightReview or type(authority) is not JAA08ReleaseAuthority:
            raise TypeError("Workable submit requires certified review and JAA-08 authority")
        state = str(self.circuit.snapshot()["state"])
        if state == "click_started":
            raise WorkableSubmissionIndeterminateError(
                "Workable click already started; retry is forbidden"
            )
        if state != "ready":
            raise WorkableCircuitError("Workable circuit is no longer retryable")
        self._assert_package(policy, application, authority)
        self._assert_schema(page, policy)
        head, sources = _source_identity(self.repository_root)
        expected = (
            policy.policy_sha256,
            application.package_sha256,
            application.answers_sha256,
            policy.inventory_sha256,
            hashlib.sha256(page.content().encode()).hexdigest(),
            head,
            sources,
        )
        observed = (
            review.policy_sha256,
            review.package_sha256,
            review.answers_sha256,
            review.inventory_sha256,
            review.dom_sha256,
            review.source_head,
            review.source_sha256s,
        )
        if observed != expected:
            raise WorkableSchemaError("Workable preflight binding changed")
        self._assert_values(page, policy, application)
        submit = page.get_by_role("button", name=policy.submit_label, exact=True)
        submit.click(trial=True, timeout=1_000)
        binding = self._binding(policy, application, review, authority)
        self.circuit.prepare(binding)
        clicked = False
        try:
            self.circuit.consumption_started(binding)
            try:
                consumed = authority.consume()
            except Exception as exc:
                raise WorkableSubmissionIndeterminateError(
                    "Workable release-token consumption is indeterminate"
                ) from exc
            if (
                getattr(consumed, "release_manifest_sha256", None) != authority.release_manifest_sha256
                or getattr(consumed, "token_sha256", None) != authority.token_sha256
            ):
                raise WorkableSubmissionIndeterminateError("release receipt differs from authority")
            self.circuit.release_consumed(
                binding,
                authority.release_manifest_sha256,
                authority.token_sha256,
            )
            self._assert_schema(page, policy)
            self._assert_values(page, policy, application)
            if hashlib.sha256(page.content().encode()).hexdigest() != review.dom_sha256:
                raise WorkableSchemaError("Workable DOM changed immediately before click")
            self.circuit.click_started(binding)
            submit.click()
            clicked = True
            self._assert_route(page, policy, success=True)
            marker = page.get_by_text(policy.success_marker, exact=True)
            if marker.count() != 1 or not marker.is_visible():
                raise WorkableSubmissionIndeterminateError("Workable success marker is absent")
            if page.get_by_role("button", name=policy.submit_label, exact=True).count() != 0:
                raise WorkableSubmissionIndeterminateError("Workable submit remains after success")
            document = {
                "answers_sha256": application.answers_sha256,
                "application_package_sha256": application.package_sha256,
                "binding_sha256": binding,
                "dom_sha256": hashlib.sha256(page.content().encode()).hexdigest(),
                "policy_sha256": policy.policy_sha256,
                "release_manifest_sha256": authority.release_manifest_sha256,
                "route_sha256": hashlib.sha256(page.url.encode()).hexdigest(),
                "schema_version": "jaa.workable-success-receipt.v1",
                "source_head": head,
                "token_sha256": authority.token_sha256,
            }
            receipt = WorkableSuccessReceipt(_content_hash(document), document)
            self.circuit.succeed(binding, receipt)
            return receipt
        except WorkableSubmissionIndeterminateError:
            if not clicked and self.circuit.snapshot()["state"] != "click_started":
                self.circuit.block(binding, "release_or_preclick_indeterminate")
            raise
        except Exception as exc:
            if clicked or self.circuit.snapshot()["state"] == "click_started":
                raise WorkableSubmissionIndeterminateError(
                    "Workable result is indeterminate after click start"
                ) from exc
            self.circuit.block(binding, "pre_submit_validation_failed")
            raise


__all__ = [
    "WorkableApplication",
    "WorkableBoundaryError",
    "WorkableCircuitError",
    "WorkableField",
    "WorkableLiveAdapter",
    "WorkableOneUseCircuit",
    "WorkablePolicy",
    "WorkablePreflightReview",
    "WorkableSchemaError",
    "WorkableSubmissionIndeterminateError",
    "WorkableSuccessReceipt",
    "WorkableUpload",
]
