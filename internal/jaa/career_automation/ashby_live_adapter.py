"""Production-bounded Ashby adapter for the single Vega JAA-11 canary.

This module is intentionally vacancy-specific.  It accepts only Vega's exact
Ashby application origin/path and only the reviewed form inventory.  Applicant
values are never persisted; durable state and receipts contain hashes only.

The consequential ordering is fail-closed::

    validate/fill -> persist release-consumption-started -> consume JAA-08
    token -> persist token-consumed -> persist click-started/indeterminate
    -> one click -> verify official success proof -> persist hashed receipt

There is no retry from any state after release consumption begins.  In
particular, a process loss after ``click_started`` remains indeterminate rather
than risking a duplicate application.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import stat
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

from playwright.sync_api import Page

from .application_compiler import ApplicationSource, CandidateContact
from .release_gate import ReleaseGateStore
from .rendering import ApplicationArtifacts


ADAPTER_ID = "jaa11.vega-ashby-live"
ADAPTER_VERSION = "v1"
APPLICATION_HOST = "jobs.ashbyhq.com"
APPLICATION_PATH = (
    "/vega/ebce385f-d4d3-4a39-a999-e048877a81e4/application"
)
APPLICATION_URL = f"https://{APPLICATION_HOST}{APPLICATION_PATH}"
ROLE_TITLE = "Product Operations Intern @ Vega"
SUBMIT_LABEL = "Submit Application"
SUCCESS_MARKER = (
    "Your application was successfully submitted. We'll contact you if "
    "there are next steps."
)

HEX_64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^jaa08\.([0-9a-f]{64})\.[A-Za-z0-9_-]+$")


class AshbyBoundaryError(RuntimeError):
    """The page left the exact approved Vega/Ashby boundary."""


class AshbySchemaError(RuntimeError):
    """The live form differs from the reviewed deterministic schema."""


class AshbyCircuitError(RuntimeError):
    """The durable one-use circuit forbids this attempt."""


class AshbySubmissionIndeterminateError(RuntimeError):
    """A consequential step may have occurred and must not be retried."""


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


def _digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _required(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} is required")
    clean = value.strip()
    if not clean or clean != value or "\x00" in value or "\r" in value:
        raise ValueError(f"{label} must be normalized non-empty text")
    return clean


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
        before = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file")
    actual = _sha256_file(resolved)
    after = candidate.lstat()
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    )
    if identity_before != identity_after or actual != expected_sha256:
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
    field_path: str
    field_type: str
    name: str
    control_id: str
    required: bool
    label: str
    placeholder: str = ""
    button_labels: tuple[str, ...] = ()

    def document(self) -> dict[str, object]:
        return {
            "field_path": self.field_path,
            "field_type": self.field_type,
            "name": self.name,
            "control_id": self.control_id,
            "required": self.required,
            "label": self.label,
            "placeholder": self.placeholder,
            "button_labels": self.button_labels,
        }


EXPECTED_FORM_INVENTORY = (
    InventoryEntry(
        "_systemfield_name",
        "text",
        "_systemfield_name",
        "_systemfield_name",
        True,
        "Full name",
        "Type here...",
    ),
    InventoryEntry(
        "_systemfield_email",
        "email",
        "_systemfield_email",
        "_systemfield_email",
        True,
        "Email",
        "hello@example.com...",
    ),
    InventoryEntry(
        "bb738f7d-543d-45f8-9119-29bc615bf9cf",
        "url",
        "bb738f7d-543d-45f8-9119-29bc615bf9cf",
        "bb738f7d-543d-45f8-9119-29bc615bf9cf",
        True,
        "LinkedIn Profile",
        "https://example.com...",
    ),
    InventoryEntry(
        "_systemfield_resume",
        "file",
        "",
        "_systemfield_resume",
        True,
        "Resume",
        button_labels=("Upload File",),
    ),
    InventoryEntry(
        "8ff73809-7ebc-4964-9ed0-aa50b9b0073d",
        "checkbox",
        "8ff73809-7ebc-4964-9ed0-aa50b9b0073d",
        "",
        True,
        "Do you have the legal right to work in the UK?",
        button_labels=("Yes", "No"),
    ),
    InventoryEntry(
        "249396a8-8fdc-4a7d-be1b-3c20aae99bf4",
        "number",
        "249396a8-8fdc-4a7d-be1b-3c20aae99bf4",
        "249396a8-8fdc-4a7d-be1b-3c20aae99bf4",
        True,
        "What's your annual total comp expectation?",
        "Type here...",
    ),
    InventoryEntry(
        "99206d94-7c0e-4611-b24c-73f408ea631d",
        "text",
        "",
        "",
        False,
        "Next available starting date",
        "Pick date...",
    ),
)
FORM_SCHEMA_SHA256 = _content_hash(
    [entry.document() for entry in EXPECTED_FORM_INVENTORY]
)

LINKEDIN_FIELD_ID = "bb738f7d-543d-45f8-9119-29bc615bf9cf"
WORK_RIGHT_FIELD_PATH = "8ff73809-7ebc-4964-9ed0-aa50b9b0073d"
COMPENSATION_FIELD_ID = "249396a8-8fdc-4a7d-be1b-3c20aae99bf4"

FORBIDDEN_SELECTORS = (
    'input[type="password"]',
    'input[autocomplete="one-time-code"]',
    'iframe[src*="captcha" i]',
    'iframe[title*="captcha" i]',
    '[data-sitekey]',
    'textarea[name*="captcha" i]',
    'input[name*="captcha" i]',
    'input[name*="payment" i]',
    'input[autocomplete^="cc-"]',
)
FORBIDDEN_VISIBLE_PHRASES = (
    "create an account to apply",
    "sign in to apply",
    "log in to apply",
    "enter the verification code",
    "multi-factor authentication",
    "payment required",
    "credit card required",
)
FORBIDDEN_HTML_MARKERS = (
    "g-recaptcha-response",
    "grecaptcha-badge",
    "recaptchapublicsitekey",
    "recaptcha.net/recaptcha",
    "google.com/recaptcha",
    "hcaptcha",
    "turnstile",
    "sitekey",
)
FORBIDDEN_REQUIRED_LABEL_MARKERS = (
    "i certify",
    "i attest",
    "i agree",
    "consent to",
    "marketing",
    "newsletter",
    "criminal record",
    "security clearance",
    "export control",
    "identity verification",
)


@dataclass(frozen=True)
class CompensationBinding:
    """Deterministically derived annual GBP answer with source identities."""

    annual_total_comp_gbp: int
    market_low_gbp: int
    market_high_gbp: int
    statutory_floor_gbp: int
    market_evidence_sha256: str
    statutory_evidence_sha256: str
    as_of: date
    derivation_policy: str = "max-floor-nearest-1000-midpoint/v1"

    def __post_init__(self) -> None:
        for value, label in (
            (self.market_low_gbp, "market lower bound"),
            (self.market_high_gbp, "market upper bound"),
            (self.statutory_floor_gbp, "statutory floor"),
            (self.annual_total_comp_gbp, "annual compensation"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{label} must be a positive integer GBP amount")
        if self.market_low_gbp > self.market_high_gbp:
            raise ValueError("market compensation interval is invalid")
        _digest(self.market_evidence_sha256, "market evidence hash")
        _digest(self.statutory_evidence_sha256, "statutory evidence hash")
        expected = self.derive_amount(
            self.market_low_gbp,
            self.market_high_gbp,
            self.statutory_floor_gbp,
        )
        if self.annual_total_comp_gbp != expected:
            raise ValueError("compensation differs from deterministic policy")
        if self.derivation_policy != "max-floor-nearest-1000-midpoint/v1":
            raise ValueError("compensation derivation policy is unsupported")

    @staticmethod
    def derive_amount(low: int, high: int, floor: int) -> int:
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in (low, high, floor)
        ) or low > high:
            raise ValueError("compensation evidence values are invalid")
        # Integer half-up rounding of the interval midpoint avoids any
        # platform-dependent floating-point representation.
        nearest_thousand = ((low + high + 1000) // 2000) * 1000
        return max(floor, nearest_thousand)

    @classmethod
    def derive(
        cls,
        *,
        market_low_gbp: int,
        market_high_gbp: int,
        statutory_floor_gbp: int,
        market_evidence_sha256: str,
        statutory_evidence_sha256: str,
        as_of: date,
    ) -> CompensationBinding:
        amount = cls.derive_amount(
            market_low_gbp,
            market_high_gbp,
            statutory_floor_gbp,
        )
        return cls(
            amount,
            market_low_gbp,
            market_high_gbp,
            statutory_floor_gbp,
            market_evidence_sha256,
            statutory_evidence_sha256,
            as_of,
        )

    def document(self) -> dict[str, object]:
        return {
            "annual_total_comp_gbp": self.annual_total_comp_gbp,
            "market_low_gbp": self.market_low_gbp,
            "market_high_gbp": self.market_high_gbp,
            "statutory_floor_gbp": self.statutory_floor_gbp,
            "market_evidence_sha256": self.market_evidence_sha256,
            "statutory_evidence_sha256": self.statutory_evidence_sha256,
            "as_of": self.as_of.isoformat(),
            "currency": "GBP",
            "period": "annual_total_comp",
            "derivation_policy": self.derivation_policy,
        }


@dataclass(frozen=True)
class AshbyApplication:
    full_name: str = field(repr=False)
    email: str = field(repr=False)
    linkedin: str = field(repr=False)
    resume_path: Path = field(repr=False)
    resume_sha256: str
    work_rights_uk: bool
    compensation: CompensationBinding

    def __post_init__(self) -> None:
        _required(self.full_name, "full name")
        _required(self.email, "email")
        _required(self.linkedin, "LinkedIn URL")
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
        if self.work_rights_uk is not True:
            raise ValueError("the selected canary requires evidenced UK work rights")
        if not isinstance(self.compensation, CompensationBinding):
            raise TypeError("application requires a compensation binding")
        _regular_file(self.resume_path, self.resume_sha256, "resume")

    @property
    def payload_sha256(self) -> str:
        return _content_hash(
            {
                "text_value_sha256s": {
                    "full_name": hashlib.sha256(
                        self.full_name.encode()
                    ).hexdigest(),
                    "email": hashlib.sha256(self.email.encode()).hexdigest(),
                    "linkedin": hashlib.sha256(
                        self.linkedin.encode()
                    ).hexdigest(),
                },
                "resume_sha256": self.resume_sha256,
                "work_rights_uk": self.work_rights_uk,
                "compensation_binding_sha256": _content_hash(
                    self.compensation.document()
                ),
                "optional_start_date": "deliberately_omitted",
            }
        )


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
        if TOKEN.fullmatch(self.release_token) is None:
            raise ValueError("release authority token format is invalid")
        if self.consumed_at.tzinfo is None or self.consumed_at.utcoffset() is None:
            raise ValueError("release consumption time must include a timezone")
        _required(self.jurisdiction, "jurisdiction")
        _required(self.contract_type, "contract type")

    @property
    def release_manifest_sha256(self) -> str:
        match = TOKEN.fullmatch(self.release_token)
        if match is None:
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
class AshbyPreflightReview:
    """Hash-only review record with no release or click capability."""

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


class AshbyOneUseCircuit:
    """SQLite one-use circuit; terminal states have no reset API."""

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
                CREATE TABLE IF NOT EXISTS ashby_circuit (
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
                CREATE TABLE IF NOT EXISTS ashby_receipt (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    receipt_sha256 TEXT NOT NULL UNIQUE,
                    document_json TEXT NOT NULL
                );
                INSERT OR IGNORE INTO ashby_circuit(
                    singleton,state,version
                ) VALUES(1,'ready',0);
                """
            )

    def snapshot(self) -> dict[str, object | None]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM ashby_circuit WHERE singleton=1"
            ).fetchone()
        if row is None or str(row["state"]) not in self.STATES:
            raise AshbyCircuitError("durable circuit state is invalid")
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
            raise ValueError("circuit transition is unsupported")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM ashby_circuit WHERE singleton=1"
            ).fetchone()
            if row is None or str(row["state"]) != expected:
                raise AshbyCircuitError(
                    "one-use circuit is no longer in the expected state"
                )
            existing_binding = row["binding_sha256"]
            if existing_binding is not None and binding_sha256 not in {
                None,
                str(existing_binding),
            }:
                raise AshbyCircuitError("circuit binding changed")
            changed = connection.execute(
                """UPDATE ashby_circuit
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
                raise AshbyCircuitError("circuit transition lost its lease")
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
        if state in {"succeeded", "blocked", "click_started"}:
            return
        self._transition(state, "blocked", reason_code=reason)

    def succeed(self, receipt: OfficialSuccessReceipt) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM ashby_circuit WHERE singleton=1"
            ).fetchone()
            if row is None or str(row["state"]) != "click_started":
                raise AshbyCircuitError(
                    "receipt cannot close a circuit without a started click"
                )
            connection.execute(
                """INSERT INTO ashby_receipt(
                       singleton,receipt_sha256,document_json
                   ) VALUES(1,?,?)""",
                (receipt.receipt_sha256, _canonical_json(dict(receipt.document))),
            )
            changed = connection.execute(
                """UPDATE ashby_circuit
                   SET state='succeeded',version=version+1,reason_code=NULL
                   WHERE singleton=1 AND state='click_started' AND version=?""",
                (int(row["version"]),),
            ).rowcount
            if changed != 1:
                raise AshbyCircuitError("receipt transition lost its lease")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def receipt(self) -> OfficialSuccessReceipt | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM ashby_receipt WHERE singleton=1"
            ).fetchone()
        if row is None:
            return None
        try:
            document = json.loads(str(row["document_json"]))
        except json.JSONDecodeError as exc:
            raise AshbyCircuitError("durable receipt is invalid JSON") from exc
        if not isinstance(document, dict):
            raise AshbyCircuitError("durable receipt is not an object")
        return OfficialSuccessReceipt(str(row["receipt_sha256"]), document)


class AshbyLiveAdapter:
    """Fill/review and, only with JAA-08 authority, submit the Vega form."""

    def __init__(self, circuit: AshbyOneUseCircuit) -> None:
        self.circuit = circuit

    @staticmethod
    def _inventory(page: Page) -> tuple[InventoryEntry, ...]:
        rows = page.locator(
            ".ashby-application-form-field-entry"
        ).evaluate_all(
            """entries => entries.map(entry => {
              const control = entry.querySelector('input,textarea,select');
              const label = entry.querySelector(
                '.ashby-application-form-question-title'
              );
              return {
                field_path: entry.getAttribute('data-field-path') || '',
                field_type: control
                  ? (control.getAttribute('type') ||
                     control.tagName.toLowerCase()) : '',
                name: control ? (control.getAttribute('name') || '') : '',
                control_id: control ? (control.id || '') : '',
                required: Boolean(control && control.required) ||
                  Boolean(label && String(label.className).includes('required')),
                label: label
                  ? (label.innerText || '').trim().replace(/\\s+/g, ' ') : '',
                placeholder: control
                  ? (control.getAttribute('placeholder') || '') : '',
                button_labels: Array.from(entry.querySelectorAll('button'))
                  .map(button => (button.innerText || '').trim()
                    .replace(/\\s+/g, ' '))
              };
            })"""
        )
        try:
            return tuple(
                InventoryEntry(
                    str(row["field_path"]),
                    str(row["field_type"]),
                    str(row["name"]),
                    str(row["control_id"]),
                    bool(row["required"]),
                    str(row["label"]),
                    str(row["placeholder"]),
                    tuple(str(value) for value in row["button_labels"]),
                )
                for row in rows
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AshbySchemaError(
                "form inventory could not be normalized"
            ) from exc

    @staticmethod
    def _assert_boundary(page: Page) -> None:
        if not _exact_application_url(page.url):
            raise AshbyBoundaryError(
                "page is outside the exact approved Vega/Ashby route"
            )
        if page.title() != ROLE_TITLE:
            raise AshbyBoundaryError("page title differs from the approved vacancy")

    @classmethod
    def _assert_schema(cls, page: Page) -> None:
        cls._assert_boundary(page)
        if cls._inventory(page) != EXPECTED_FORM_INVENTORY:
            raise AshbySchemaError(
                "live form inventory differs from the reviewed schema"
            )
        submit = page.get_by_role("button", name=SUBMIT_LABEL, exact=True)
        if submit.count() != 1:
            raise AshbySchemaError("final submit control is not unique")

    @classmethod
    def _blocking_reasons(cls, page: Page) -> tuple[str, ...]:
        reasons: set[str] = set()
        for selector in FORBIDDEN_SELECTORS:
            if page.locator(selector).count() != 0:
                reasons.add("prohibited_control_present")
        body = page.locator("body").inner_text().casefold()
        if any(marker in body for marker in FORBIDDEN_VISIBLE_PHRASES):
            reasons.add("prohibited_visible_boundary_present")
        html = page.content().casefold().replace(" ", "")
        if any(marker in html for marker in FORBIDDEN_HTML_MARKERS):
            reasons.add("captcha_configuration_present")
        required_labels = "\n".join(
            entry.label.casefold()
            for entry in cls._inventory(page)
            if entry.required
        )
        if any(
            marker in required_labels
            for marker in FORBIDDEN_REQUIRED_LABEL_MARKERS
        ):
            reasons.add("unapproved_legal_or_marketing_boundary_present")
        return tuple(sorted(reasons))

    @staticmethod
    def _control(page: Page, selector: str):
        locator = page.locator(selector)
        if locator.count() != 1:
            raise AshbySchemaError("mapped form control is not unique")
        return locator

    @classmethod
    def _id(cls, page: Page, control_id: str):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", control_id):
            raise AshbySchemaError("mapped control ID is unsafe")
        return cls._control(page, f'[id="{control_id}"]')

    @classmethod
    def _fill(cls, page: Page, application: AshbyApplication) -> None:
        for control_id, value in (
            ("_systemfield_name", application.full_name),
            ("_systemfield_email", application.email),
            (LINKEDIN_FIELD_ID, application.linkedin),
            (
                COMPENSATION_FIELD_ID,
                str(application.compensation.annual_total_comp_gbp),
            ),
        ):
            control = cls._id(page, control_id)
            control.fill(value)
            if control.input_value() != value:
                raise AshbySchemaError("filled field did not retain its value")

        resume = _regular_file(
            application.resume_path,
            application.resume_sha256,
            "resume",
        )
        resume_control = cls._id(page, "_systemfield_resume")
        resume_control.set_input_files(str(resume))
        if resume_control.evaluate("el => el.files ? el.files.length : 0") != 1:
            raise AshbySchemaError("resume upload did not bind exactly one file")

        field = cls._control(
            page,
            f'[data-field-path="{WORK_RIGHT_FIELD_PATH}"]',
        )
        yes = field.get_by_role("button", name="Yes", exact=True)
        no = field.get_by_role("button", name="No", exact=True)
        if yes.count() != 1 or no.count() != 1:
            raise AshbySchemaError("work-right controls are not exact")
        yes.click()
        checkbox = cls._control(
            page,
            f'[name="{WORK_RIGHT_FIELD_PATH}"]',
        )
        if not checkbox.is_checked():
            raise AshbySchemaError("work-right answer was not retained")

    @staticmethod
    def _binding(
        application: AshbyApplication,
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
        marker = page.get_by_text(SUCCESS_MARKER, exact=True)
        if marker.count() != 1 or not marker.is_visible():
            raise AshbySubmissionIndeterminateError(
                "official Ashby success proof is missing"
            )
        if not _exact_application_url(page.url):
            raise AshbySubmissionIndeterminateError(
                "success page left the exact approved route"
            )
        if page.title() != ROLE_TITLE:
            raise AshbySubmissionIndeterminateError(
                "success page title differs from the approved vacancy"
            )
        submit = page.get_by_role("button", name=SUBMIT_LABEL, exact=True)
        if submit.count() != 0:
            raise AshbySubmissionIndeterminateError(
                "submit control remains present after claimed success"
            )
        document = {
            "schema_version": "jaa11.ashby-official-receipt.v1",
            "adapter_id": ADAPTER_ID,
            "adapter_version": ADAPTER_VERSION,
            "binding_sha256": binding_sha256,
            "release_manifest_sha256": authority.release_manifest_sha256,
            "token_sha256": authority.token_sha256,
            "route_sha256": hashlib.sha256(APPLICATION_URL.encode()).hexdigest(),
            "form_schema_sha256": FORM_SCHEMA_SHA256,
            "success_marker_sha256": hashlib.sha256(
                SUCCESS_MARKER.encode()
            ).hexdigest(),
            "dom_sha256": hashlib.sha256(page.content().encode()).hexdigest(),
            "screenshot_sha256": hashlib.sha256(
                page.screenshot(full_page=True)
            ).hexdigest(),
            "title_sha256": hashlib.sha256(page.title().encode()).hexdigest(),
            "release_consumed_at": authority.consumed_at.isoformat(),
        }
        return OfficialSuccessReceipt(_content_hash(document), document)

    def prepare_review(
        self,
        page: Page,
        *,
        application: AshbyApplication,
    ) -> AshbyPreflightReview:
        """Inspect/fill for review without a token, durable transition or submit.

        Prohibited controls and serialized CAPTCHA configuration are evaluated
        before applicant data is entered.  A parked review therefore performs
        no field population or upload either.
        """
        self._assert_schema(page)
        reasons = self._blocking_reasons(page)
        if not reasons:
            self._fill(page, application)
            self._assert_schema(page)
            reasons = self._blocking_reasons(page)
        document = {
            "schema_version": "jaa11.ashby-preflight-review.v1",
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
        return AshbyPreflightReview(_content_hash(document), document)

    def submit(
        self,
        page: Page,
        *,
        application: AshbyApplication,
        authority: JAA08ReleaseAuthority,
    ) -> OfficialSuccessReceipt:
        """Perform at most one final click and retain only hashed evidence."""
        binding = self._binding(application, authority)
        self.circuit.prepare(binding)
        try:
            review = self.prepare_review(page, application=application)
            if not review.eligible_for_submit:
                raise AshbySchemaError(
                    "preflight parked a prohibited consequential boundary"
                )
            submit = page.get_by_role("button", name=SUBMIT_LABEL, exact=True)

            self.circuit.consumption_started(binding)
            try:
                consumed = authority.consume()
            except Exception as exc:
                self.circuit.block("release_token_consumption_failed")
                raise AshbySubmissionIndeterminateError(
                    "release-token consumption did not complete safely"
                ) from exc
            if (
                getattr(consumed, "release_manifest_sha256", None)
                != authority.release_manifest_sha256
                or getattr(consumed, "token_sha256", None)
                != authority.token_sha256
            ):
                self.circuit.block("release_token_receipt_mismatch")
                raise AshbySubmissionIndeterminateError(
                    "release-token consumption result differs from authority"
                )
            self.circuit.release_consumed(
                binding,
                authority.release_manifest_sha256,
                authority.token_sha256,
            )
            self.circuit.click_started(binding)
            submit.click()
            receipt = self._receipt(
                page,
                binding_sha256=binding,
                authority=authority,
            )
            self.circuit.succeed(receipt)
            return receipt
        except AshbySubmissionIndeterminateError:
            raise
        except Exception:
            self.circuit.block("pre_submit_validation_failed")
            raise


__all__ = [
    "ADAPTER_ID",
    "ADAPTER_VERSION",
    "APPLICATION_URL",
    "AshbyApplication",
    "AshbyBoundaryError",
    "AshbyCircuitError",
    "AshbyLiveAdapter",
    "AshbyOneUseCircuit",
    "AshbyPreflightReview",
    "AshbySchemaError",
    "AshbySubmissionIndeterminateError",
    "CompensationBinding",
    "EXPECTED_FORM_INVENTORY",
    "FORM_SCHEMA_SHA256",
    "InventoryEntry",
    "JAA08ReleaseAuthority",
    "OfficialSuccessReceipt",
    "ROLE_TITLE",
    "SUBMIT_LABEL",
    "SUCCESS_MARKER",
]
