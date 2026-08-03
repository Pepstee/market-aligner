"""Production-bounded Recruitee adapter for the single JAA-11 canary.

The adapter is deliberately vacancy-specific.  It will operate only on the
frozen Decoded application route and only while the complete, known form
inventory remains byte-for-byte equivalent to the inventory captured during
the operator-approved canary review.  It persists no applicant values.  The
only durable applicant bindings are SHA-256 digests.

The irreversible boundary is ordered as follows::

    validate and fill -> persist consumption-started -> consume JAA-08 token
    -> persist token-consumed -> persist click-started/indeterminate -> click
    -> verify official success page -> persist content-addressed receipt

A process loss after ``click_started`` is intentionally unrecoverable.  The
adapter will never repeat the click to discover whether the first one worked.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

from playwright.sync_api import Page

from .application_compiler import ApplicationSource, CandidateContact
from .release_gate import ReleaseGateStore
from .rendering import ApplicationArtifacts


ADAPTER_ID = "jaa11.decoded-recruitee-live"
ADAPTER_VERSION = "v1"
APPLICATION_HOST = "decoded.recruitee.com"
APPLICATION_PATH = "/o/associate-teacher-apac-data-analytics-remote-2/c/new"
APPLICATION_URL = f"https://{APPLICATION_HOST}{APPLICATION_PATH}"
SUCCESS_MARKERS = (
    "All done!",
    "Your application has been successfully submitted!",
)
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^jaa08\.([0-9a-f]{64})\.[A-Za-z0-9_-]+$")


class RecruiteeBoundaryError(RuntimeError):
    """The browser or page left the exact approved production boundary."""


class RecruiteeSchemaError(RuntimeError):
    """The live form no longer matches the reviewed deterministic schema."""


class RecruiteeCircuitError(RuntimeError):
    """The one-use circuit no longer permits a consequential attempt."""


class RecruiteeSubmissionIndeterminateError(RuntimeError):
    """A submit may have occurred and must never be repeated automatically."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _content_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _required(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} is required")
    clean = value.strip()
    if not clean or clean != value or "\x00" in value or "\r" in value:
        raise ValueError(f"{label} must be normalized non-empty text")
    return clean


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_file(path: str | Path, expected_sha256: str, label: str) -> Path:
    _digest(expected_sha256, f"{label} hash")
    candidate = Path(path)
    try:
        status_before = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(status_before.st_mode) or not stat.S_ISREG(status_before.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file")
    actual = _sha256_file(resolved)
    status_after = candidate.lstat()
    before = (
        status_before.st_dev,
        status_before.st_ino,
        status_before.st_mode,
        status_before.st_size,
        status_before.st_mtime_ns,
    )
    after = (
        status_after.st_dev,
        status_after.st_ino,
        status_after.st_mode,
        status_after.st_size,
        status_after.st_mtime_ns,
    )
    if before != after or actual != expected_sha256:
        raise ValueError(f"{label} differs from its approved bytes")
    return resolved


def _exact_application_url(value: str) -> bool:
    parsed = urlsplit(value)
    return (
        parsed.scheme == "https"
        and parsed.hostname == APPLICATION_HOST
        and parsed.port is None
        and parsed.username is None
        and parsed.password is None
        and parsed.path == APPLICATION_PATH
        and not parsed.query
        and not parsed.fragment
    )


@dataclass(frozen=True)
class InventoryEntry:
    field_type: str
    name: str
    required: bool
    label: str
    option_value: str = ""

    def document(self) -> dict[str, object]:
        return {
            "field_type": self.field_type,
            "name": self.name,
            "required": self.required,
            "label": self.label,
            "option_value": self.option_value,
        }


EXPECTED_FORM_INVENTORY = (
    InventoryEntry("text", "candidate.name", True, "Full name *"),
    InventoryEntry("email", "candidate.email", True, "Email address *"),
    InventoryEntry("tel", "candidate.phone", True, "Phone number *"),
    InventoryEntry("file", "candidate.photo", False, ""),
    InventoryEntry("file", "candidate.cv", True, "CV or resume *"),
    InventoryEntry("file", "candidate.coverLetterFile", False, "Cover letter"),
    InventoryEntry(
        "text",
        "candidate.openQuestionAnswers.5042660.content",
        True,
        "LinkedIn Profile *",
    ),
    InventoryEntry(
        "text",
        "candidate.openQuestionAnswers.5042661.content",
        True,
        "Where are you located? *",
    ),
    InventoryEntry(
        "text",
        "candidate.openQuestionAnswers.5043399.content",
        True,
        "Do you have full rights to work where you are located? *",
    ),
    InventoryEntry(
        "text",
        "candidate.openQuestionAnswers.5043397.content",
        True,
        (
            "Are you happy to travel for in-person workshop deliveries in "
            "the UK and wider EMEA? *"
        ),
    ),
    InventoryEntry(
        "radio",
        "candidate.openQuestionAnswers.5042665.flag",
        True,
        "Yes",
        "true",
    ),
    InventoryEntry(
        "radio",
        "candidate.openQuestionAnswers.5042665.flag",
        True,
        "No",
        "false",
    ),
    InventoryEntry(
        "radio",
        "candidate.openQuestionAnswers.5042666.flag",
        True,
        "Yes",
        "true",
    ),
    InventoryEntry(
        "radio",
        "candidate.openQuestionAnswers.5042666.flag",
        True,
        "No",
        "false",
    ),
    InventoryEntry(
        "textarea",
        "candidate.openQuestionAnswers.5043438.content",
        True,
        (
            "In a short sentence or paragraph, please explain your knowledge "
            "of and interest in technology. *"
        ),
    ),
    InventoryEntry(
        "textarea",
        "candidate.openQuestionAnswers.5141816.content",
        True,
        ("Are you fluent in any language in any Language other than English? *"),
    ),
)
FORM_SCHEMA_SHA256 = _content_hash(
    [entry.document() for entry in EXPECTED_FORM_INVENTORY]
)

TEXT_FIELD_NAMES: Mapping[str, str] = {
    "full_name": "candidate.name",
    "email": "candidate.email",
    "phone": "candidate.phone",
    "linkedin": "candidate.openQuestionAnswers.5042660.content",
    "location": "candidate.openQuestionAnswers.5042661.content",
    "work_rights": "candidate.openQuestionAnswers.5043399.content",
    "travel": "candidate.openQuestionAnswers.5043397.content",
    "technology_interest": ("candidate.openQuestionAnswers.5043438.content"),
    "languages": "candidate.openQuestionAnswers.5141816.content",
}
RADIO_FIELD_NAMES: Mapping[str, str] = {
    "public_speaking": "candidate.openQuestionAnswers.5042665.flag",
    "facilitation_window": "candidate.openQuestionAnswers.5042666.flag",
}

FORBIDDEN_SELECTORS = (
    'input[type="password"]',
    'input[autocomplete="one-time-code"]',
    'iframe[src*="captcha" i]',
    "[data-sitekey]",
    'input[name*="captcha" i]',
    'input[type="checkbox"][required]',
    'input[name*="payment" i]',
    'input[autocomplete^="cc-"]',
)
FORBIDDEN_PAGE_PHRASES = (
    "captcha",
    "enter the verification code",
    "multi-factor authentication",
    "sign in to apply",
    "log in to apply",
    "payment required",
    "credit card required",
)
LEGAL_ATTESTATION_MARKERS = (
    "i certify",
    "i attest",
    "i agree to the terms",
    "legally binding",
)
HIDDEN_CAPTCHA_MARKERS = (
    "captchatoken",
    "captcha-base.recruiteecdn.com",
    "captcha-assets.recruiteecdn.com",
    "captcha-imgs.recruiteecdn.com",
    "captcha-report.recruiteecdn.com",
    '"hcaptcha":true',
    "&quot;hcaptcha&quot;:true",
    '"sitekey"',
    "&quot;sitekey&quot;",
)


@dataclass(frozen=True)
class RecruiteeApplication:
    full_name: str = field(repr=False)
    email: str = field(repr=False)
    phone: str = field(repr=False)
    linkedin: str = field(repr=False)
    location: str = field(repr=False)
    work_rights: str = field(repr=False)
    travel: str = field(repr=False)
    public_speaking: bool
    facilitation_window: bool
    technology_interest: str = field(repr=False)
    languages: str = field(repr=False)
    cv_path: Path = field(repr=False)
    cv_sha256: str
    cover_letter_path: Path | None = field(default=None, repr=False)
    cover_letter_sha256: str | None = None

    def __post_init__(self) -> None:
        for value, label in (
            (self.full_name, "full name"),
            (self.email, "email"),
            (self.phone, "phone"),
            (self.linkedin, "LinkedIn URL"),
            (self.location, "location"),
            (self.work_rights, "work-rights answer"),
            (self.travel, "travel answer"),
            (self.technology_interest, "technology answer"),
            (self.languages, "languages answer"),
        ):
            _required(value, label)
        if "@" not in self.email or "\n" in self.email:
            raise ValueError("email is invalid")
        parsed = urlsplit(self.linkedin)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in {"linkedin.com", "www.linkedin.com"}
            or not parsed.path.startswith("/in/")
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("LinkedIn URL is outside the approved profile route")
        _regular_file(self.cv_path, self.cv_sha256, "CV")
        if (self.cover_letter_path is None) != (self.cover_letter_sha256 is None):
            raise ValueError("cover-letter path and hash must appear together")
        if self.cover_letter_path is not None:
            _regular_file(
                self.cover_letter_path,
                str(self.cover_letter_sha256),
                "cover letter",
            )

    @property
    def payload_sha256(self) -> str:
        # Applicant values are admitted to the binding only as hashes.
        return _content_hash(
            {
                "text_value_sha256s": {
                    key: hashlib.sha256(value.encode()).hexdigest()
                    for key, value in self.text_values().items()
                },
                "public_speaking": self.public_speaking,
                "facilitation_window": self.facilitation_window,
                "cv_sha256": self.cv_sha256,
                "cover_letter_sha256": self.cover_letter_sha256,
            }
        )

    def text_values(self) -> dict[str, str]:
        return {
            "full_name": self.full_name,
            "email": self.email,
            "phone": self.phone,
            "linkedin": self.linkedin,
            "location": self.location,
            "work_rights": self.work_rights,
            "travel": self.travel,
            "technology_interest": self.technology_interest,
            "languages": self.languages,
        }


@dataclass(frozen=True)
class JAA08ReleaseAuthority:
    gate: ReleaseGateStore = field(repr=False)
    release_token: str = field(repr=False)
    source: ApplicationSource = field(repr=False)
    artifacts: ApplicationArtifacts = field(repr=False)
    contact: CandidateContact = field(repr=False)
    questions: dict[str, tuple[str, str]] | None = field(repr=False)
    artifact_root: Path
    repository_root: Path
    jurisdiction: str
    contract_type: str
    consumed_at: datetime

    def __post_init__(self) -> None:
        match = TOKEN.fullmatch(self.release_token)
        if match is None:
            raise ValueError("release authority token format is invalid")
        if self.consumed_at.tzinfo is None or self.consumed_at.utcoffset() is None:
            raise ValueError("release consumption time must include a timezone")
        _required(self.jurisdiction, "jurisdiction")
        _required(self.contract_type, "contract type")

    @property
    def release_manifest_sha256(self) -> str:
        match = TOKEN.fullmatch(self.release_token)
        if match is None:  # guarded in __post_init__; keeps the property total.
            raise ValueError("release authority token format is invalid")
        return match.group(1)

    @property
    def token_sha256(self) -> str:
        return hashlib.sha256(self.release_token.encode()).hexdigest()

    def consume(self) -> object:
        return self.gate.consume_release_token(
            release_token=self.release_token,
            source=self.source,
            artifacts=self.artifacts,
            contact=self.contact,
            questions=self.questions,
            artifact_root=self.artifact_root,
            repository_root=self.repository_root,
            jurisdiction=self.jurisdiction,
            contract_type=self.contract_type,
            consumed_at=self.consumed_at,
        )


@dataclass(frozen=True)
class OfficialSuccessReceipt:
    receipt_sha256: str
    document: Mapping[str, object]

    def __post_init__(self) -> None:
        _digest(self.receipt_sha256, "receipt hash")
        if _content_hash(dict(self.document)) != self.receipt_sha256:
            raise ValueError("receipt content differs from its identity")


@dataclass(frozen=True)
class RecruiteePreflightReview:
    """Hash-only review evidence; this object carries no submit authority."""

    review_sha256: str
    document: Mapping[str, object]

    def __post_init__(self) -> None:
        _digest(self.review_sha256, "preflight-review hash")
        if _content_hash(dict(self.document)) != self.review_sha256:
            raise ValueError("preflight review differs from its identity")

    @property
    def eligible_for_submit(self) -> bool:
        return bool(self.document.get("eligible_for_submit", False))

    @property
    def reason_codes(self) -> tuple[str, ...]:
        raw = self.document.get("reason_codes", ())
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            raise ValueError("preflight reason codes are invalid")
        return tuple(raw)


class RecruiteeOneUseCircuit:
    """SQLite-backed one-attempt circuit with no automatic reset path."""

    STATES = {
        "ready",
        "prepared",
        "release_consumption_started",
        "release_consumed",
        "click_started",
        "succeeded",
        "blocked",
    }

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS recruitee_circuit (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    state TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK(version>=0),
                    binding_sha256 TEXT,
                    release_manifest_sha256 TEXT,
                    token_sha256 TEXT,
                    reason_code TEXT,
                    CHECK(state IN (
                        'ready','prepared','release_consumption_started',
                        'release_consumed','click_started','succeeded','blocked'
                    ))
                );
                CREATE TABLE IF NOT EXISTS recruitee_receipt (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    receipt_sha256 TEXT NOT NULL UNIQUE,
                    document_json TEXT NOT NULL
                );
                INSERT OR IGNORE INTO recruitee_circuit(
                    singleton,state,version
                ) VALUES(1,'ready',0);
                """
            )

    def snapshot(self) -> dict[str, object | None]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM recruitee_circuit WHERE singleton=1"
            ).fetchone()
        if row is None or str(row["state"]) not in self.STATES:
            raise RecruiteeCircuitError("durable circuit state is invalid")
        return dict(row)

    def _transition(
        self,
        expected: str,
        target: str,
        *,
        binding_sha256: str | None = None,
        release_manifest_sha256: str | None = None,
        token_sha256: str | None = None,
        reason_code: str | None = None,
    ) -> None:
        if expected not in self.STATES or target not in self.STATES:
            raise ValueError("circuit transition state is unsupported")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM recruitee_circuit WHERE singleton=1"
            ).fetchone()
            if row is None or str(row["state"]) != expected:
                raise RecruiteeCircuitError(
                    "one-use circuit is no longer in the expected state"
                )
            current_binding = row["binding_sha256"]
            if current_binding is not None and binding_sha256 not in {
                None,
                str(current_binding),
            }:
                raise RecruiteeCircuitError("circuit binding changed")
            changed = connection.execute(
                """UPDATE recruitee_circuit
                   SET state=?,version=version+1,
                       binding_sha256=COALESCE(binding_sha256,?),
                       release_manifest_sha256=COALESCE(
                           release_manifest_sha256,?
                       ),
                       token_sha256=COALESCE(token_sha256,?),
                       reason_code=?
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
                raise RecruiteeCircuitError("circuit transition lost its lease")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def prepare(self, binding_sha256: str) -> None:
        _digest(binding_sha256, "application binding hash")
        self._transition("ready", "prepared", binding_sha256=binding_sha256)

    def consumption_started(self, binding_sha256: str) -> None:
        self._transition(
            "prepared",
            "release_consumption_started",
            binding_sha256=binding_sha256,
        )

    def release_consumed(
        self,
        binding_sha256: str,
        release_manifest_sha256: str,
        token_sha256: str,
    ) -> None:
        _digest(release_manifest_sha256, "release-manifest hash")
        _digest(token_sha256, "release-token hash")
        self._transition(
            "release_consumption_started",
            "release_consumed",
            binding_sha256=binding_sha256,
            release_manifest_sha256=release_manifest_sha256,
            token_sha256=token_sha256,
        )

    def click_started(self, binding_sha256: str) -> None:
        self._transition(
            "release_consumed",
            "click_started",
            binding_sha256=binding_sha256,
            reason_code="submit_result_indeterminate_until_receipt",
        )

    def block(self, reason_code: str) -> None:
        reason = _required(reason_code, "reason code")
        state = str(self.snapshot()["state"])
        if state in {"succeeded", "blocked"}:
            return
        if state == "click_started":
            # click_started is the durable indeterminate state.  Preserve it.
            return
        self._transition(state, "blocked", reason_code=reason)

    def succeed(self, receipt: OfficialSuccessReceipt) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM recruitee_circuit WHERE singleton=1"
            ).fetchone()
            if row is None or str(row["state"]) != "click_started":
                raise RecruiteeCircuitError(
                    "receipt cannot close a circuit without a started click"
                )
            document_json = _canonical_json(dict(receipt.document))
            connection.execute(
                """INSERT INTO recruitee_receipt(
                       singleton,receipt_sha256,document_json
                   ) VALUES(1,?,?)""",
                (receipt.receipt_sha256, document_json),
            )
            changed = connection.execute(
                """UPDATE recruitee_circuit
                   SET state='succeeded',version=version+1,reason_code=NULL
                   WHERE singleton=1 AND state='click_started' AND version=?""",
                (int(row["version"]),),
            ).rowcount
            if changed != 1:
                raise RecruiteeCircuitError("receipt transition lost its lease")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def receipt(self) -> OfficialSuccessReceipt | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM recruitee_receipt WHERE singleton=1"
            ).fetchone()
        if row is None:
            return None
        try:
            document = json.loads(str(row["document_json"]))
        except json.JSONDecodeError as exc:
            raise RecruiteeCircuitError("durable receipt is invalid JSON") from exc
        if not isinstance(document, dict):
            raise RecruiteeCircuitError("durable receipt is not an object")
        return OfficialSuccessReceipt(str(row["receipt_sha256"]), document)


class RecruiteeLiveAdapter:
    """Fill and submit the one exact operator-approved Recruitee form."""

    def __init__(self, circuit: RecruiteeOneUseCircuit) -> None:
        self.circuit = circuit

    @staticmethod
    def _inventory(page: Page) -> tuple[InventoryEntry, ...]:
        rows = page.locator("input:not([type=hidden]),textarea,select").evaluate_all(
            """els => els.map(e => ({
              field_type: e.tagName.toLowerCase() === 'textarea'
                ? 'textarea' : (e.getAttribute('type') || 'select'),
              name: e.getAttribute('name') || '',
              required: Boolean(e.required) ||
                e.getAttribute('aria-required') === 'true',
              label: Array.from(e.labels || [])
                .map(x => (x.innerText || '').trim().replace(/\\s+/g, ' '))
                .join(' | '),
              option_value: (e.getAttribute('type') || '') === 'radio'
                ? (e.getAttribute('value') || '') : ''
            }))"""
        )
        try:
            return tuple(
                InventoryEntry(
                    str(row["field_type"]),
                    str(row["name"]),
                    bool(row["required"]),
                    str(row["label"]),
                    str(row["option_value"]),
                )
                for row in rows
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RecruiteeSchemaError(
                "form inventory could not be normalized"
            ) from exc

    @staticmethod
    def _assert_boundary(page: Page) -> None:
        if not _exact_application_url(page.url):
            raise RecruiteeBoundaryError(
                "page is outside the exact approved Recruitee route"
            )

    @staticmethod
    def _blocking_reasons(page: Page) -> tuple[str, ...]:
        reasons: set[str] = set()
        for selector in FORBIDDEN_SELECTORS:
            if page.locator(selector).count() != 0:
                reasons.add("prohibited_control_present")
        body = page.locator("body").inner_text().casefold()
        if any(marker in body for marker in FORBIDDEN_PAGE_PHRASES):
            reasons.add("prohibited_visible_boundary_present")
        html = page.content().casefold().replace(" ", "")
        if any(marker in html for marker in HIDDEN_CAPTCHA_MARKERS):
            reasons.add("captcha_configuration_present")
        required_labels = "\n".join(
            entry.label.casefold()
            for entry in RecruiteeLiveAdapter._inventory(page)
            if entry.required
        )
        if any(marker in required_labels for marker in LEGAL_ATTESTATION_MARKERS):
            reasons.add("unapproved_legal_attestation_present")
        return tuple(sorted(reasons))

    @classmethod
    def _assert_schema(cls, page: Page) -> None:
        cls._assert_boundary(page)
        actual = cls._inventory(page)
        if actual != EXPECTED_FORM_INVENTORY:
            raise RecruiteeSchemaError(
                "live form inventory differs from the reviewed schema"
            )
        submit = page.get_by_role("button", name="Send", exact=True)
        if submit.count() != 1:
            raise RecruiteeSchemaError("final submit control is not unique")

    @staticmethod
    def _named(page: Page, name: str, *, value: str | None = None):
        escaped_name = name.replace('"', '\\"')
        selector = f'[name="{escaped_name}"]'
        if value is not None:
            escaped_value = value.replace('"', '\\"')
            selector += f'[value="{escaped_value}"]'
        locator = page.locator(selector)
        if locator.count() != 1:
            raise RecruiteeSchemaError("mapped form control is not unique")
        return locator

    @classmethod
    def _fill(cls, page: Page, application: RecruiteeApplication) -> None:
        for key, value in application.text_values().items():
            locator = cls._named(page, TEXT_FIELD_NAMES[key])
            locator.fill(value)
            if locator.input_value() != value:
                raise RecruiteeSchemaError("filled field did not retain its value")

        for key, answer in (
            ("public_speaking", application.public_speaking),
            ("facilitation_window", application.facilitation_window),
        ):
            locator = cls._named(
                page,
                RADIO_FIELD_NAMES[key],
                value="true" if answer else "false",
            )
            locator.check()
            if not locator.is_checked():
                raise RecruiteeSchemaError("radio answer was not retained")

        cv = _regular_file(application.cv_path, application.cv_sha256, "CV")
        cv_input = cls._named(page, "candidate.cv")
        cv_input.set_input_files(str(cv))
        if cv_input.evaluate("el => el.files ? el.files.length : 0") != 1:
            raise RecruiteeSchemaError("CV upload did not bind exactly one file")

        if application.cover_letter_path is not None:
            cover = _regular_file(
                application.cover_letter_path,
                str(application.cover_letter_sha256),
                "cover letter",
            )
            cover_input = cls._named(page, "candidate.coverLetterFile")
            cover_input.set_input_files(str(cover))
            if cover_input.evaluate("el => el.files ? el.files.length : 0") != 1:
                raise RecruiteeSchemaError(
                    "cover-letter upload did not bind exactly one file"
                )

    @staticmethod
    def _binding(
        application: RecruiteeApplication,
        authority: JAA08ReleaseAuthority,
    ) -> str:
        return _content_hash(
            {
                "adapter_id": ADAPTER_ID,
                "adapter_version": ADAPTER_VERSION,
                "application_route_sha256": hashlib.sha256(
                    APPLICATION_URL.encode()
                ).hexdigest(),
                "form_schema_sha256": FORM_SCHEMA_SHA256,
                "application_payload_sha256": application.payload_sha256,
                "release_manifest_sha256": authority.release_manifest_sha256,
                "token_sha256": authority.token_sha256,
            }
        )

    @staticmethod
    def _receipt(
        page: Page,
        *,
        binding_sha256: str,
        authority: JAA08ReleaseAuthority,
    ) -> OfficialSuccessReceipt:
        for marker in SUCCESS_MARKERS:
            locator = page.get_by_text(marker, exact=True)
            if locator.count() != 1 or not locator.is_visible():
                raise RecruiteeSubmissionIndeterminateError(
                    "official success receipt is missing"
                )
        if not _exact_application_url(page.url):
            raise RecruiteeSubmissionIndeterminateError(
                "success page left the exact approved route"
            )
        dom_sha256 = hashlib.sha256(page.content().encode()).hexdigest()
        screenshot_sha256 = hashlib.sha256(page.screenshot(full_page=True)).hexdigest()
        title_sha256 = hashlib.sha256(page.title().encode()).hexdigest()
        document = {
            "schema_version": "jaa11.recruitee-official-receipt.v1",
            "adapter_id": ADAPTER_ID,
            "adapter_version": ADAPTER_VERSION,
            "binding_sha256": binding_sha256,
            "release_manifest_sha256": authority.release_manifest_sha256,
            "token_sha256": authority.token_sha256,
            "route_sha256": hashlib.sha256(APPLICATION_URL.encode()).hexdigest(),
            "form_schema_sha256": FORM_SCHEMA_SHA256,
            "success_marker_sha256s": [
                hashlib.sha256(marker.encode()).hexdigest()
                for marker in SUCCESS_MARKERS
            ],
            "dom_sha256": dom_sha256,
            "screenshot_sha256": screenshot_sha256,
            "title_sha256": title_sha256,
            "release_consumed_at": authority.consumed_at.isoformat(),
        }
        return OfficialSuccessReceipt(_content_hash(document), document)

    def prepare_review(
        self,
        page: Page,
        *,
        application: RecruiteeApplication,
    ) -> RecruiteePreflightReview:
        """Fill for operator review without touching any release authority.

        The result explicitly parks forms that expose a visible or serialized
        CAPTCHA, login, MFA, payment, or legal-attestation boundary.  It never
        consumes a token and never clicks the final control.
        """
        self._assert_schema(page)
        # Prohibited boundaries are checked before applicant data is entered.
        # This matters for real Recruitee pages where CAPTCHA configuration can
        # be serialized into otherwise innocuous-looking HTML.
        reasons = self._blocking_reasons(page)
        if reasons:
            document = {
                "schema_version": "jaa11.recruitee-preflight-review.v1",
                "adapter_id": ADAPTER_ID,
                "adapter_version": ADAPTER_VERSION,
                "route_sha256": hashlib.sha256(
                    APPLICATION_URL.encode()
                ).hexdigest(),
                "form_schema_sha256": FORM_SCHEMA_SHA256,
                "application_payload_sha256": application.payload_sha256,
                "eligible_for_submit": False,
                "reason_codes": list(reasons),
                "dom_sha256": hashlib.sha256(page.content().encode()).hexdigest(),
                "screenshot_sha256": hashlib.sha256(
                    page.screenshot(full_page=True)
                ).hexdigest(),
            }
            return RecruiteePreflightReview(_content_hash(document), document)

        self._fill(page, application)
        self._assert_schema(page)
        reasons = self._blocking_reasons(page)
        document = {
            "schema_version": "jaa11.recruitee-preflight-review.v1",
            "adapter_id": ADAPTER_ID,
            "adapter_version": ADAPTER_VERSION,
            "route_sha256": hashlib.sha256(APPLICATION_URL.encode()).hexdigest(),
            "form_schema_sha256": FORM_SCHEMA_SHA256,
            "application_payload_sha256": application.payload_sha256,
            "eligible_for_submit": not reasons,
            "reason_codes": list(reasons),
            "dom_sha256": hashlib.sha256(page.content().encode()).hexdigest(),
            "screenshot_sha256": hashlib.sha256(
                page.screenshot(full_page=True)
            ).hexdigest(),
        }
        return RecruiteePreflightReview(_content_hash(document), document)

    def submit(
        self,
        page: Page,
        *,
        application: RecruiteeApplication,
        authority: JAA08ReleaseAuthority,
    ) -> OfficialSuccessReceipt:
        """Perform at most one final click and return only hashed evidence."""
        binding = self._binding(application, authority)
        self.circuit.prepare(binding)
        try:
            review = self.prepare_review(page, application=application)
            if not review.eligible_for_submit:
                raise RecruiteeSchemaError(
                    "preflight parked a prohibited consequential boundary"
                )
            submit = page.get_by_role("button", name="Send", exact=True)

            self.circuit.consumption_started(binding)
            try:
                consumed = authority.consume()
            except Exception as exc:
                self.circuit.block("release_token_consumption_failed")
                raise RecruiteeSubmissionIndeterminateError(
                    "release-token consumption did not complete safely"
                ) from exc
            if (
                getattr(consumed, "release_manifest_sha256", None)
                != authority.release_manifest_sha256
                or getattr(consumed, "token_sha256", None) != authority.token_sha256
            ):
                self.circuit.block("release_token_receipt_mismatch")
                raise RecruiteeSubmissionIndeterminateError(
                    "release-token consumption result differs from authority"
                )
            self.circuit.release_consumed(
                binding,
                authority.release_manifest_sha256,
                authority.token_sha256,
            )
            # click_started means indeterminate until a receipt commits.  This
            # transition is durable and precedes the only click.
            self.circuit.click_started(binding)
            submit.click()
            receipt = self._receipt(
                page,
                binding_sha256=binding,
                authority=authority,
            )
            self.circuit.succeed(receipt)
            return receipt
        except RecruiteeSubmissionIndeterminateError:
            raise
        except Exception:
            self.circuit.block("pre_submit_validation_failed")
            raise


__all__ = [
    "ADAPTER_ID",
    "ADAPTER_VERSION",
    "APPLICATION_URL",
    "EXPECTED_FORM_INVENTORY",
    "FORM_SCHEMA_SHA256",
    "JAA08ReleaseAuthority",
    "OfficialSuccessReceipt",
    "RecruiteeApplication",
    "RecruiteeBoundaryError",
    "RecruiteeCircuitError",
    "RecruiteeLiveAdapter",
    "RecruiteeOneUseCircuit",
    "RecruiteePreflightReview",
    "RecruiteeSchemaError",
    "RecruiteeSubmissionIndeterminateError",
]
