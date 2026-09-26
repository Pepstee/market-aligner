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

The same owner also hosts the vacancy-generic, strictly non-release
preparation path (:class:`AshbyNonReleasePreparator`).  It is bound to an
exact existing :class:`CanarySelectionContract`: the selection's vacancy
URL/identity/content-hash must equal the boundary route and the exact
application source before any page access.  The applicant form inventory is
scoped exactly to controls inside ``.ashby-application-form-field-entry``
elements; anonymous out-of-entry upload plumbing is not applicant authority.
Whole-page scans still refuse credential, payment, MFA and active CAPTCHA
challenge boundaries before applicant data, while static CAPTCHA
configuration signals are recorded as ``anti_bot_signals`` and never
interacted with.  Every plan is compiled through the pure ATS
answer-compilation seam, only those compiled entries are executed, and the
result is the canonical :class:`AtsApplicationAuthority`.  That path never
touches a submit control or a CAPTCHA control, never creates release
authority and never transitions the one-use circuit.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import stat
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Mapping, NoReturn
from urllib.parse import urlsplit

from playwright.sync_api import Page

from .application_artifacts import (
    PublishedArtifactReceipt,
    verify_application_artifact_receipt,
)
from .application_compiler import (
    ApplicationSource,
    CandidateContact,
    verify_application_source,
)
from .ats_application_authority import (
    AtsAnswerEntry,
    AtsApplicationAuthority,
    AtsFieldOption,
    AtsFieldPlan,
    AtsFormInventory,
    AtsObservedField,
    build_ats_application_authority,
    compile_ats_answer_entries,
    is_ats_omitted_value_empty,
)
from .release_gate import ReleaseGateStore
from .live_canary_authority import (
    FROZEN_LIVE_CANARY_AUTHORITY,
    CanarySelectionContract,
)
from .rendering import (
    ApplicationArtifacts,
    verify_application_artifacts,
)


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


class AshbyPreparationRefused(RuntimeError):
    """Stable fail-closed refusal raised before any applicant data is used."""

    def __init__(
        self,
        reason_codes: str | tuple[str, ...],
        message: str | None = None,
    ) -> None:
        codes = (
            (reason_codes,) if isinstance(reason_codes, str) else tuple(reason_codes)
        )
        if not codes or any(not isinstance(code, str) or not code for code in codes):
            raise ValueError("refusal reason codes must be non-empty text")
        self.reason_codes = tuple(sorted(codes))
        joined = ",".join(self.reason_codes)
        super().__init__(f"{joined}: {message}" if message else f"Ashby preparation refused: {joined}")


def _refuse(
    reason_codes: str | tuple[str, ...],
    message: str | None = None,
) -> NoReturn:
    raise AshbyPreparationRefused(reason_codes, message)


@dataclass(frozen=True)
class AshbyApplicationBoundary:
    """Closed typed route/title boundary for one public Ashby application.

    The boundary is derived from an exact :class:`CanarySelectionContract`
    plus the exact :class:`ApplicationSource` via
    ``from_selection_contract``; preparation re-binds the boundary to that
    same selection before any page access, so caller-authored arbitrary
    routes cannot be substituted.  Any HTTPS host other than the public
    Ashby jobs host is rejected.
    """

    application_url: str
    page_title: str

    def __post_init__(self) -> None:
        if not isinstance(self.application_url, str):
            raise TypeError("boundary application URL must be text")
        parsed = urlsplit(self.application_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != APPLICATION_HOST
            or parsed.port is not None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or ASHBY_APPLICATION_ROUTE.fullmatch(parsed.path) is None
        ):
            raise ValueError(
                "boundary URL must be an exact public HTTPS Ashby "
                "job/application route"
            )
        _required(self.page_title, "boundary page title")

    @classmethod
    def from_selection_contract(
        cls,
        selection: CanarySelectionContract,
        source: ApplicationSource,
    ) -> AshbyApplicationBoundary:
        if type(selection) is not CanarySelectionContract:
            raise TypeError(
                "boundary requires the exact CanarySelectionContract type"
            )
        if type(source) is not ApplicationSource:
            raise TypeError(
                "boundary requires the exact application source type"
            )
        if selection.vacancy_identity != source.vacancy_source_identity:
            raise ValueError(
                "selection vacancy identity differs from the application source"
            )
        if selection.vacancy_content_sha256 != source.vacancy_sha256:
            raise ValueError(
                "selection vacancy hash differs from the application source"
            )
        return cls(
            application_url=selection.vacancy_url,
            page_title=f"{source.role_title} @ {source.company_name}",
        )


ASHBY_APPLICATION_ROUTE = re.compile(
    r"^/[A-Za-z0-9][A-Za-z0-9_-]{0,99}"
    r"(?:/[A-Za-z0-9][A-Za-z0-9_.-]{0,149}){1,2}$"
)

_CAPTURE_SELECTOR = (
    ".ashby-application-form-field-entry input, "
    ".ashby-application-form-field-entry textarea, "
    ".ashby-application-form-field-entry select"
)
_FILE_COUNT_SCRIPT = "el => el.files ? el.files.length : 0"
_PDF_MIME_TYPE = "application/pdf"
_UPLOAD_PAYLOAD_NAMES = {
    "artifact.cv": "cv.pdf",
    "artifact.cover_letter": "cover-letter.pdf",
}
_HONEYPOT_MARKER = re.compile(
    r"honeypot|robot|bot[-_]?field|trap|hp[-_]", re.IGNORECASE
)
_CAPTCHA_SIGNAL_SELECTORS = frozenset(
    {
        'textarea[name*="captcha" i]',
        'input[name*="captcha" i]',
    }
)
# Generic-path credential/payment selectors.  CAPTCHA iframes are excluded:
# static anchor configuration and challenge frames are distinguished by
# exact frame inspection below.  A serialized site-key mount point is
# static configuration and is recorded as a signal, not a blocker.
_SITEKEY_SIGNAL_SELECTOR = "[data-sitekey]"
_GENERIC_BOUNDARY_SELECTORS = tuple(
    selector
    for selector in FORBIDDEN_SELECTORS
    if selector not in _CAPTCHA_SIGNAL_SELECTORS
    and not selector.startswith("iframe[")
    and selector != _SITEKEY_SIGNAL_SELECTOR
)
_IFRAME_SELECTOR = "iframe"
_IFRAME_INVENTORY_SCRIPT = """() => Array.from(
  document.querySelectorAll('iframe')
).map((frame) => ({
  src: (frame.getAttribute('src') || ''),
  title: (frame.getAttribute('title') || ''),
  visible: Boolean(
    frame.offsetParent || frame.getClientRects().length
  ),
}))"""
_CAPTCHA_FRAME_FAMILY = re.compile(
    r"recaptcha|hcaptcha|turnstile|captcha", re.IGNORECASE
)
_ASHBY_CONTROL_KINDS = {
    "text": "text",
    "email": "email",
    "tel": "tel",
    "url": "url",
    "number": "number",
    "textarea": "textarea",
    "select": "select",
    "checkbox": "checkbox",
    "radio": "radio",
    "file": "file",
    "hidden": "hidden",
}
_SOURCE_FIELD_BINDINGS = (
    ("full name", frozenset({"text"}), "contact.full_name"),
    ("email", frozenset({"email"}), "contact.email"),
    ("email address", frozenset({"email"}), "contact.email"),
    ("phone", frozenset({"tel"}), "contact.phone"),
    ("phone number", frozenset({"tel"}), "contact.phone"),
    ("location", frozenset({"text"}), "contact.city"),
    ("city", frozenset({"text"}), "contact.city"),
    ("cv", frozenset({"file"}), "artifact.cv"),
    ("resume", frozenset({"file"}), "artifact.cv"),
    ("cover letter", frozenset({"file"}), "artifact.cover_letter"),
)

_ASHBY_CAPTURE_SCRIPT = """() => Array.from(
  document.querySelectorAll(
    '.ashby-application-form-field-entry input, '
    + '.ashby-application-form-field-entry textarea, '
    + '.ashby-application-form-field-entry select'
  )
).map((control) => {
  const tag = control.tagName.toLowerCase();
  const inputType = tag === 'input'
    ? (control.getAttribute('type') || 'text').toLowerCase()
    : tag;
  const entry = control.closest('.ashby-application-form-field-entry');
  const title = entry
    ? entry.querySelector('.ashby-application-form-question-title')
    : null;
  const buttons = entry
    ? Array.from(entry.querySelectorAll('button')).map((button) => ({
        label: (button.innerText || '').trim().replace(/\\s+/g, ' '),
        visible: Boolean(
          button.offsetParent || button.getClientRects().length
        ),
      }))
    : [];
  let options = [];
  if (tag === 'select') {
    options = Array.from(control.options).map((option) => ({
      value: option.value,
      label: (option.label || '').trim(),
    }));
  }
  let currentValue = null;
  if (inputType === 'checkbox') currentValue = control.checked;
  else if (inputType === 'radio') {
    currentValue = control.checked ? control.value : null;
  } else if (inputType !== 'file') currentValue = control.value;
  return {
    input_type: inputType,
    id: control.id || '',
    name: control.getAttribute('name') || '',
    field_path: entry
      ? (entry.getAttribute('data-field-path') || '')
      : '',
    required: Boolean(control.required) || Boolean(
      title && String(title.className).includes('required')
    ),
    visible: inputType === 'hidden'
      ? false
      : Boolean(control.offsetParent || control.getClientRects().length),
    disabled: Boolean(control.disabled),
    read_only: Boolean(control.readOnly),
    multiple: Boolean(control.multiple),
    value_attribute: control.value === undefined ? '' : String(
      control.value
    ),
    options,
    buttons,
    current_value: currentValue,
    role: (control.getAttribute('role') || ''),
    aria_autocomplete: (control.getAttribute('aria-autocomplete') || ''),
    label: title
      ? (title.innerText || '').trim().replace(/\\s+/g, ' ')
      : (control.getAttribute('aria-label') || '').trim(),
    file_count: control.files ? control.files.length : 0,
  };
})"""


def _utc_now_second() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _verify_selection_contract_identity(
    selection: CanarySelectionContract,
) -> None:
    """Re-derive the exact contract hash so bypassed state fails closed."""
    document = selection.document(include_hash=False)
    if _content_hash(document) != selection.contract_sha256:
        raise ValueError("selection contract hash is invalid")
    if (
        selection.authority_record_sha256
        != FROZEN_LIVE_CANARY_AUTHORITY.record_sha256
        or selection.operational_release != "withheld"
        or selection.external_action_capability is not False
        or selection.schema_version != "jaa11.live-canary-selection.v1"
    ):
        raise ValueError("selection contract scope differs from the frozen authority")


@dataclass(frozen=True)
class _ControlRecord:
    kind: str
    label: str
    required: bool
    visible: bool
    disabled: bool
    read_only: bool
    multiple: bool
    options: tuple[tuple[str, str], ...]
    button_labels: tuple[str, ...]
    buttons_visible: bool
    current_value: object
    value_attribute: str
    file_count: int
    identity: str
    origin_kind: str
    is_combobox: bool


@dataclass(frozen=True)
class _AshbyCapturedField:
    field: AtsObservedField
    selector_origin: tuple[str, str]
    file_count: int
    combobox: bool


def _captured_text(row: Mapping[str, object], key: str) -> str:
    value = row.get(key, "")
    if not isinstance(value, str):
        _refuse("unstable_field_identity", f"captured {key} is not text")
    return value


def _parse_control_row(row: Mapping[str, object]) -> _ControlRecord:
    kind = _ASHBY_CONTROL_KINDS.get(_captured_text(row, "input_type"))
    if kind is None:
        _refuse(
            "unsupported_control_kind",
            f"unsupported control {_captured_text(row, 'input_type')!r}",
        )
    for key in ("required", "visible", "disabled", "read_only", "multiple"):
        if not isinstance(row.get(key), bool):
            _refuse("unsupported_control_state", f"captured {key} flag is invalid")
    options_raw = row.get("options")
    if not isinstance(options_raw, list):
        _refuse("unsupported_control_state", "captured options are malformed")
    options: list[tuple[str, str]] = []
    for option in options_raw:
        if not isinstance(option, dict) or not isinstance(
            option.get("value"), str
        ) or not isinstance(option.get("label"), str):
            _refuse("unsupported_control_state", "captured option is malformed")
        options.append((str(option["value"]), str(option["label"])))
    buttons_raw = row.get("buttons")
    if not isinstance(buttons_raw, list):
        _refuse("unsupported_control_state", "captured buttons are malformed")
    button_labels: list[str] = []
    buttons_visible = False
    for button in buttons_raw:
        if not isinstance(button, dict) or not isinstance(
            button.get("label"), str
        ):
            _refuse("unsupported_control_state", "captured button is malformed")
        if button["label"]:
            button_labels.append(str(button["label"]))
        buttons_visible = buttons_visible or bool(button.get("visible"))
    current_value = row.get("current_value")
    if current_value is not None and not isinstance(
        current_value, (str, bool, int)
    ):
        _refuse("unsupported_control_state", "captured value has an invalid type")
    file_count = row.get("file_count")
    if isinstance(file_count, bool) or not isinstance(file_count, int):
        _refuse("unsupported_control_state", "captured file count is invalid")
    path_attr = _captured_text(row, "field_path")
    id_attr = _captured_text(row, "id")
    name_attr = _captured_text(row, "name")
    identity = path_attr or id_attr or name_attr
    if not identity:
        _refuse("unstable_field_identity", "a form control has no stable ID")
    if any(character in identity for character in ('"', "\\", "\r", "\n", "\x00")):
        _refuse(
            "unstable_field_identity",
            f"control identity {identity!r} is unsafe for stable selection",
        )
    origin_kind = "path" if path_attr else ("id" if id_attr else "name")
    role_attribute = _captured_text(row, "role")
    aria_autocomplete = _captured_text(row, "aria_autocomplete")
    return _ControlRecord(
        kind=kind,
        label=_captured_text(row, "label"),
        required=bool(row["required"]),
        visible=bool(row["visible"]),
        disabled=bool(row["disabled"]),
        read_only=bool(row["read_only"]),
        multiple=bool(row["multiple"]),
        options=tuple(options),
        button_labels=tuple(button_labels),
        buttons_visible=buttons_visible,
        current_value=current_value,
        value_attribute=_captured_text(row, "value_attribute"),
        file_count=int(file_count),
        identity=identity,
        origin_kind=origin_kind,
        is_combobox=(
            role_attribute == "combobox" or bool(aria_autocomplete)
        ),
    )


def _dedupe(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _classify_captcha_frames(
    rows: object,
) -> tuple[set[str], set[str]]:
    """Classify captured iframe elements into blockers and signals.

    Every record's ``visible`` flag must be an exact boolean; anything else
    refuses before inventory.  A static invisible reCAPTCHA anchor
    (``/api2/anchor`` with ``size=invisible``) is configuration only: it
    records the exact ``captcha_configuration_present`` signal regardless
    of the visibility heuristic.  An actual challenge frame
    (``api2/bframe`` or a title containing ``challenge``) and any other
    CAPTCHA-family frame block pre-data only when reported visible;
    hidden/preloaded occurrences are recorded as the same configuration
    signal instead.
    """
    blockers: set[str] = set()
    signals: set[str] = set()
    if not isinstance(rows, list):
        _refuse(
            "captcha_frame_inspection_failed",
            "frame inventory is malformed",
        )
    for row in rows:
        if not isinstance(row, dict):
            _refuse(
                "captcha_frame_inspection_failed",
                "frame record is malformed",
            )
        src = row.get("src")
        title = row.get("title")
        visible = row.get("visible")
        if not isinstance(src, str) or not isinstance(title, str):
            _refuse(
                "captcha_frame_inspection_failed",
                "frame src/title are malformed",
            )
        if type(visible) is not bool:
            _refuse(
                "captcha_frame_inspection_failed",
                "frame visible flag must be an exact boolean",
            )
        src_text = src.casefold()
        frame_text = f"{src} {title}".casefold()
        if "api2/bframe" in src_text or "challenge" in frame_text:
            if visible:
                blockers.add("active_captcha_challenge_present")
            else:
                signals.add("captcha_configuration_present")
        elif "/api2/anchor" in src_text and "size=invisible" in src_text:
            signals.add("captcha_configuration_present")
        elif _CAPTCHA_FRAME_FAMILY.search(frame_text):
            if visible:
                blockers.add("prohibited_control_present")
            else:
                signals.add("captcha_configuration_present")
    return blockers, signals


def _normalize_ashby_capture(rows: object) -> tuple[_AshbyCapturedField, ...]:
    """Normalize raw capture rows into closed typed observed fields."""
    if not isinstance(rows, list):
        _refuse("unstable_field_identity", "form capture is not a control list")
    groups: dict[str, list[_ControlRecord]] = {}
    for row in rows:
        if not isinstance(row, dict):
            _refuse("unstable_field_identity", "form capture row is malformed")
        record = _parse_control_row(row)
        groups.setdefault(record.identity, []).append(record)
    captured: list[_AshbyCapturedField] = []
    for identity, records in groups.items():
        kinds = {record.kind for record in records}
        if len(records) > 1 and (len(kinds) != 1 or not kinds <= {"radio", "checkbox"}):
            _refuse(
                "ambiguous_field_identity",
                f"controls share the unstable identity {identity!r}",
            )
        kind = next(iter(kinds))
        first = records[0]
        label = next((record.label for record in records if record.label), "")
        required = any(record.required for record in records)
        visible = any(record.visible for record in records) or any(
            record.buttons_visible for record in records
        )
        disabled = any(record.disabled for record in records)
        read_only = any(record.read_only for record in records)
        multiple = any(record.multiple for record in records)
        button_labels = _dedupe(
            tuple(
                label_text
                for record in records
                for label_text in record.button_labels
            )
        )
        file_count = sum(record.file_count for record in records)
        current_value: object
        option_pairs: tuple[tuple[str, str], ...] = ()
        if kind == "hidden":
            current_value = first.current_value
        elif kind == "file":
            current_value = None
        elif kind == "checkbox":
            if len(records) != 1:
                _refuse(
                    "unsupported_control_state",
                    f"multi-checkbox group {identity!r} is unsupported",
                )
            # Exact DOM truth: an unchecked checkbox keeps its exact False
            # state in observed and reviewed inventories; True must reject.
            current_value = bool(first.current_value)
            option_pairs = tuple((row, row) for row in button_labels)
        elif kind == "radio":
            checked = next(
                (record for record in records if record.current_value), None
            )
            current_value = None if checked is None else checked.current_value
            if button_labels:
                option_pairs = tuple((row, row) for row in button_labels)
            else:
                values = _dedupe(
                    tuple(record.value_attribute for record in records)
                )
                option_pairs = tuple((value, value) for value in values)
        elif kind == "select":
            current_value = first.current_value
            option_pairs = first.options
        else:
            current_value = first.current_value
        if (disabled or read_only) and kind != "hidden":
            _refuse(
                "unsupported_control_state",
                f"non-actionable applicant control {identity!r}",
            )
        if kind == "hidden":
            haystack = " ".join((identity, label)).casefold()
            role = (
                "honeypot"
                if _HONEYPOT_MARKER.search(haystack)
                else "provider_managed"
            )
        elif not visible:
            role = "provider_managed"
        else:
            role = "applicant"
        multiple = multiple and kind in {"file", "select", "checkbox"}
        unique_options: dict[str, AtsFieldOption] = {}
        for value, option_label in option_pairs:
            if value in unique_options:
                _refuse(
                    "ambiguous_field_identity",
                    f"duplicate option value on {identity!r}",
                )
            unique_options[value] = AtsFieldOption(value, option_label)
        try:
            observed = AtsObservedField(
                field_id=identity,
                control_kind=kind,
                label=label,
                required=required,
                visible=visible,
                automation_role=role,
                disabled=disabled,
                read_only=read_only,
                multiple=multiple,
                options=tuple(unique_options.values()),
                current_value=current_value,
            )
        except (TypeError, ValueError) as exc:
            _refuse(
                "unsupported_control_state",
                f"control {identity!r} cannot be represented exactly: {exc}",
            )
        captured.append(
            _AshbyCapturedField(
                field=observed,
                selector_origin=(first.origin_kind, identity),
                file_count=file_count,
                combobox=any(record.is_combobox for record in records),
            )
        )
    return tuple(captured)


@dataclass(frozen=True)
class AshbyNonReleasePreparation:
    """Exact reviewed preparation with no release or submission capability."""

    authority: AtsApplicationAuthority
    observed_inventory: AtsFormInventory
    reviewed_inventory: AtsFormInventory
    answers: tuple[AtsAnswerEntry, ...]
    filled_field_ids: tuple[str, ...]
    uploaded_field_ids: tuple[str, ...]
    uploaded_sha256s: tuple[str, ...]
    anti_bot_signals: tuple[str, ...]
    submit_clicks: int


class AshbyNonReleasePreparator:
    """Generic non-release Ashby preparation bound to the ATS authority.

    The route is bound to an exact :class:`CanarySelectionContract` before
    any page access.  Applicant inventory is scoped to Ashby field entries;
    whole-page scans refuse credential/payment/MFA and active CAPTCHA
    challenge boundaries before applicant data while static CAPTCHA
    configuration is recorded as an ``anti_bot_signals`` observation that is
    never interacted with.  Every plan is compiled through the pure
    answer-compilation seam; only those compiled entries are executed; the
    form is then re-captured, re-verified and bound into the canonical
    non-release :class:`AtsApplicationAuthority`.
    """

    def __init__(self) -> None:
        self.value_writes = 0
        self.upload_writes = 0

    @property
    def submit_clicks(self) -> int:
        return 0

    def prepare(
        self,
        page: Page,
        *,
        boundary: AshbyApplicationBoundary,
        selection: CanarySelectionContract,
        candidate_authority_sha256: str,
        source: ApplicationSource,
        artifacts: ApplicationArtifacts,
        publication_receipt: PublishedArtifactReceipt,
    ) -> AshbyNonReleasePreparation:
        self._validate_inputs(
            boundary,
            selection,
            candidate_authority_sha256,
            source,
            artifacts,
            publication_receipt,
        )
        # Route/title is the minimum boundary check and must precede every
        # other page inspection: a URL mismatch performs no locator, body,
        # content, frame, capture, screenshot, fill or upload access.
        self._assert_page_boundary(page, boundary)
        anti_bot_signals = self._pre_data_boundary(page)
        observed_fields, observed_meta = self._capture_fields(page)
        self._assert_required_label_boundary(observed_fields)
        observed_inventory = self._build_inventory(
            page, boundary, observed_fields
        )
        plans = self._compile_plans(observed_meta)
        try:
            entries = compile_ats_answer_entries(
                inventory=observed_inventory,
                plans=plans,
                source=source,
                artifacts=artifacts,
            )
        except (TypeError, ValueError) as exc:
            _refuse("answer_compilation_refused", str(exc))
        filled, uploaded = self._execute(
            page, entries, observed_fields, observed_meta, artifacts
        )
        reviewed_fields, reviewed_meta = self._capture_fields(page)
        if [row.field.shape_document() for row in reviewed_meta] != [
            row.field.shape_document() for row in observed_meta
        ]:
            _refuse(
                "schema_drift_after_fill",
                "live form shape changed while filling",
            )
        reviewed_rows = self._reconcile_reviewed_fields(entries, reviewed_meta)
        self._verify_reviewed_values_exact(
            observed_fields, reviewed_rows, entries
        )
        reviewed_inventory = self._build_inventory(
            page, boundary, tuple(reviewed_rows)
        )
        try:
            authority = build_ats_application_authority(
                reviewed_at=max(_utc_now_second(), reviewed_inventory.captured_at),
                candidate_authority_sha256=candidate_authority_sha256,
                source=source,
                artifacts=artifacts,
                publication_receipt=publication_receipt,
                inventory=observed_inventory,
                reviewed_inventory=reviewed_inventory,
                plans=plans,
            )
        except (TypeError, ValueError) as exc:
            _refuse("authority_build_refused", str(exc))
        return AshbyNonReleasePreparation(
            authority=authority,
            observed_inventory=observed_inventory,
            reviewed_inventory=reviewed_inventory,
            answers=entries,
            filled_field_ids=filled,
            uploaded_field_ids=tuple(field_id for field_id, _ in uploaded),
            uploaded_sha256s=tuple(digest for _, digest in uploaded),
            anti_bot_signals=anti_bot_signals,
            submit_clicks=self.submit_clicks,
        )

    @staticmethod
    def _validate_inputs(
        boundary: object,
        selection: object,
        candidate_authority_sha256: object,
        source: object,
        artifacts: object,
        publication_receipt: object,
    ) -> None:
        if type(boundary) is not AshbyApplicationBoundary:
            raise TypeError("preparation requires the exact Ashby boundary type")
        if type(selection) is not CanarySelectionContract:
            raise TypeError(
                "preparation requires the exact CanarySelectionContract type"
            )
        if type(source) is not ApplicationSource:
            raise TypeError("preparation requires the exact application source type")
        if type(artifacts) is not ApplicationArtifacts:
            raise TypeError("preparation requires the exact artifact set type")
        if not isinstance(publication_receipt, PublishedArtifactReceipt):
            raise TypeError("preparation requires a typed publication receipt")
        try:
            _verify_selection_contract_identity(selection)
        except (TypeError, ValueError) as exc:
            _refuse("selection_contract_unverified", str(exc))
        if boundary.application_url != selection.vacancy_url:
            _refuse(
                "selection_boundary_mismatch",
                "boundary route differs from the selected vacancy URL",
            )
        if (
            selection.vacancy_identity != source.vacancy_source_identity
            or selection.vacancy_content_sha256 != source.vacancy_sha256
        ):
            _refuse(
                "selection_source_mismatch",
                "selected vacancy identity/hash differs from the "
                "application source",
            )
        if (
            not isinstance(candidate_authority_sha256, str)
            or HEX_64.fullmatch(candidate_authority_sha256) is None
        ):
            _refuse(
                "candidate_authority_identity_invalid",
                "candidate authority hash must be a lowercase SHA-256",
            )
        try:
            verify_application_source(source)
        except (TypeError, ValueError) as exc:
            _refuse("application_source_unverified", str(exc))
        try:
            verify_application_artifacts(artifacts)
        except (TypeError, ValueError) as exc:
            _refuse("artifacts_unverified", str(exc))
        try:
            verify_application_artifact_receipt(source, artifacts, publication_receipt)
        except (TypeError, ValueError) as exc:
            _refuse("publication_receipt_unverified", str(exc))
        expected_title = f"{source.role_title} @ {source.company_name}"
        if boundary.page_title != expected_title:
            _refuse(
                "boundary_source_mismatch",
                "boundary title differs from the exact application source identity",
            )

    @staticmethod
    def _matches_boundary(actual: str, expected: str) -> bool:
        left, right = urlsplit(actual), urlsplit(expected)
        return (
            left.scheme == "https"
            and left.hostname == right.hostname
            and left.port is None
            and right.port is None
            and left.username is None
            and left.password is None
            and left.path == right.path
            and left.query == ""
            and left.fragment == ""
        )

    @classmethod
    def _assert_page_boundary(
        cls,
        page: Page,
        boundary: AshbyApplicationBoundary,
    ) -> None:
        if not cls._matches_boundary(str(page.url), boundary.application_url):
            _refuse(
                "route_outside_approved_ashby_boundary",
                "page is outside the exact approved Ashby application route",
            )
        if page.title() != boundary.page_title:
            _refuse(
                "page_title_boundary_mismatch",
                "page title differs from the approved vacancy boundary",
            )

    @classmethod
    def _pre_data_boundary(cls, page: Page) -> tuple[str, ...]:
        """Refuse active boundaries; return recorded static CAPTCHA signals.

        Credential, payment, MFA and actively rendered challenge boundaries
        refuse before any applicant value or upload.  A hidden CAPTCHA
        response element, serialized provider CAPTCHA configuration, a
        serialized site-key mount point, and hidden/preloaded CAPTCHA
        frames are signals only; a static invisible reCAPTCHA anchor iframe
        is likewise configuration (``captcha_configuration_present``) while
        a challenge frame (``api2/bframe``/challenge title) blocks only
        when reported visible.  Signals are never interacted with.
        """
        blockers: set[str] = set()
        signals: set[str] = set()
        for selector in _GENERIC_BOUNDARY_SELECTORS:
            if page.locator(selector).count() != 0:
                blockers.add("prohibited_control_present")
        for selector in _CAPTCHA_SIGNAL_SELECTORS:
            if page.locator(selector).count() != 0:
                signals.add("captcha_hidden_response_present")
        if page.locator(_SITEKEY_SIGNAL_SELECTOR).count() != 0:
            signals.add("captcha_configuration_present")
        try:
            frames = page.locator(_IFRAME_SELECTOR).evaluate_all(
                _IFRAME_INVENTORY_SCRIPT
            )
        except Exception as exc:
            _refuse("captcha_frame_inspection_failed", str(exc))
        frame_blockers, frame_signals = _classify_captcha_frames(frames)
        blockers |= frame_blockers
        signals |= frame_signals
        body = page.locator("body").inner_text().casefold()
        if any(marker in body for marker in FORBIDDEN_VISIBLE_PHRASES):
            blockers.add("prohibited_visible_boundary_present")
        html = page.content().casefold().replace(" ", "")
        if any(marker in html for marker in FORBIDDEN_HTML_MARKERS):
            signals.add("captcha_configuration_present")
        if blockers:
            _refuse(
                tuple(sorted(blockers)),
                "active credential/payment/challenge boundary detected "
                "before inventory",
            )
        return tuple(sorted(signals))

    @staticmethod
    def _assert_required_label_boundary(
        fields: tuple[AtsObservedField, ...],
    ) -> None:
        joined = "\n".join(
            row.label.casefold() for row in fields if row.required
        )
        if any(marker in joined for marker in FORBIDDEN_REQUIRED_LABEL_MARKERS):
            _refuse(
                "unapproved_legal_or_marketing_boundary_present",
                "a required question cites an unapproved legal or marketing boundary",
            )

    @staticmethod
    def _capture_fields(
        page: Page,
    ) -> tuple[tuple[AtsObservedField, ...], tuple[_AshbyCapturedField, ...]]:
        try:
            rows = page.locator(_CAPTURE_SELECTOR).evaluate_all(
                _ASHBY_CAPTURE_SCRIPT
            )
        except Exception as exc:
            _refuse("form_capture_failed", str(exc))
        captured = _normalize_ashby_capture(rows)
        if not captured:
            _refuse("unsupported_form_shape", "no form controls were captured")
        return (
            tuple(row.field for row in captured),
            captured,
        )

    @staticmethod
    def _build_inventory(
        page: Page,
        boundary: AshbyApplicationBoundary,
        fields: tuple[AtsObservedField, ...],
    ) -> AtsFormInventory:
        snapshot = hashlib.sha256(page.content().encode()).hexdigest()
        screenshot = hashlib.sha256(
            page.screenshot(full_page=True)
        ).hexdigest()
        try:
            return AtsFormInventory(
                provider="ashby",
                application_url=boundary.application_url,
                captured_at=_utc_now_second(),
                page_snapshot_sha256=snapshot,
                screenshot_sha256s=(screenshot,),
                fields=fields,
            )
        except (TypeError, ValueError) as exc:
            _refuse("unsupported_form_shape", str(exc))

    @staticmethod
    def _binding_for(field: AtsObservedField) -> str | None:
        normalized = " ".join(field.label.split()).casefold()
        matches = {
            reference
            for label, kinds, reference in _SOURCE_FIELD_BINDINGS
            if normalized == label and field.control_kind in kinds
        }
        if len(matches) > 1:
            _refuse(
                "ambiguous_source_binding",
                f"label {field.label!r} binds several canonical sources",
            )
        return next(iter(matches), None)

    @classmethod
    def _compile_plans(
        cls,
        meta: tuple[_AshbyCapturedField, ...],
    ) -> tuple[AtsFieldPlan, ...]:
        plans: list[AtsFieldPlan] = []
        bound: dict[str, str] = {}
        unsupported: list[str] = []
        for row in meta:
            observed = row.field
            if row.combobox:
                # An autocomplete combobox can never be claimed from a text
                # fill: omit it untouched when optional, refuse when
                # required, before any applicant data is used.
                if observed.required:
                    unsupported.append(observed.field_id)
                else:
                    plans.append(
                        AtsFieldPlan(
                            observed.field_id,
                            "omit",
                            "none",
                            observed.current_value,
                        )
                    )
                continue
            actionable = (
                observed.control_kind != "hidden"
                and observed.automation_role == "applicant"
            )
            if not actionable:
                plans.append(
                    AtsFieldPlan(
                        observed.field_id, "omit", "none", observed.current_value
                    )
                )
                continue
            reference = cls._binding_for(observed)
            if reference is None:
                if observed.required:
                    unsupported.append(observed.field_id)
                    continue
                plans.append(
                    AtsFieldPlan(
                        observed.field_id, "omit", "none", observed.current_value
                    )
                )
                continue
            owner = bound.get(reference)
            if owner is not None:
                _refuse(
                    "ambiguous_source_binding",
                    f"{owner!r} and {observed.field_id!r} both bind {reference}",
                )
            bound[reference] = observed.field_id
            action = (
                "upload" if reference.startswith("artifact.") else "fill"
            )
            plans.append(
                AtsFieldPlan(
                    observed.field_id, action, reference, observed.current_value
                )
            )
        if unsupported:
            _refuse(
                "unsupported_required_field",
                "required ATS fields lack canonical source bindings "
                "(autocomplete/choice fields are never inferred): "
                + ", ".join(sorted(unsupported)),
            )
        return tuple(plans)

    @staticmethod
    def _selector_for(origin: tuple[str, str]) -> str:
        kind, value = origin
        return {
            "path": f'[data-field-path="{value}"]',
            "id": f'[id="{value}"]',
            "name": f'[name="{value}"]',
        }[kind]

    @classmethod
    def _unique_locator(cls, page: Page, origin: tuple[str, str]):
        locator = page.locator(cls._selector_for(origin))
        if locator.count() != 1:
            _refuse(
                "ambiguous_field_identity",
                f"mapped control {origin[1]!r} is not unique",
            )
        return locator

    def _execute(
        self,
        page: Page,
        entries: tuple[AtsAnswerEntry, ...],
        fields: tuple[AtsObservedField, ...],
        meta: tuple[_AshbyCapturedField, ...],
        artifacts: ApplicationArtifacts,
    ) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
        filled: list[str] = []
        uploaded: list[tuple[str, str]] = []
        for entry, observed, row in zip(entries, fields, meta, strict=True):
            if entry.action == "omit":
                continue
            locator = self._unique_locator(page, row.selector_origin)
            if entry.action == "fill":
                if observed.control_kind == "select":
                    value = str(entry.final_value)
                    locator.select_option(value)
                    if locator.input_value() != value:
                        _refuse(
                            "fill_not_retained",
                            f"provider did not retain the exact value for "
                            f"{observed.field_id!r}",
                        )
                elif observed.control_kind in {"radio", "checkbox"}:
                    wanted = str(entry.final_value)
                    option = next(
                        (
                            item
                            for item in observed.options
                            if item.value == wanted
                        ),
                        None,
                    )
                    if option is None:
                        _refuse(
                            "answer_compilation_refused",
                            f"{observed.field_id!r} lacks the exact option",
                        )
                    button = locator.get_by_role(
                        "button", name=option.label, exact=True
                    )
                    if button.count() != 1:
                        _refuse(
                            "unsupported_choice_control",
                            f"{observed.field_id!r} choice control is not exact",
                        )
                    button.click()
                else:
                    if not isinstance(entry.final_value, str):
                        _refuse(
                            "answer_compilation_refused",
                            f"{observed.field_id!r} lacks an exact text value",
                        )
                    locator.fill(entry.final_value)
                    if locator.input_value() != entry.final_value:
                        _refuse(
                            "fill_not_retained",
                            f"provider did not retain the exact value for "
                            f"{observed.field_id!r}",
                        )
                self.value_writes += 1
                filled.append(observed.field_id)
            elif entry.action == "upload":
                pdf = (
                    artifacts.cv_pdf
                    if entry.source_reference == "artifact.cv"
                    else artifacts.cover_letter_pdf
                )
                if entry.final_value != pdf.pdf_sha256:
                    _refuse(
                        "upload_binding_mismatch",
                        f"upload for {observed.field_id!r} differs from its "
                        "exact artifact bytes",
                    )
                locator.set_input_files(
                    [
                        {
                            "name": _UPLOAD_PAYLOAD_NAMES[
                                entry.source_reference
                            ],
                            "mimeType": _PDF_MIME_TYPE,
                            "buffer": pdf.pdf_bytes,
                        }
                    ]
                )
                if locator.evaluate(_FILE_COUNT_SCRIPT) != 1:
                    _refuse(
                        "upload_binding_failed",
                        f"upload for {observed.field_id!r} did not bind one file",
                    )
                self.upload_writes += 1
                uploaded.append((observed.field_id, pdf.pdf_sha256))
            else:
                _refuse(
                    "answer_compilation_refused",
                    f"unsupported compiled action for {observed.field_id!r}",
                )
        return tuple(filled), tuple(uploaded)

    @staticmethod
    def _reconcile_reviewed_fields(
        entries: tuple[AtsAnswerEntry, ...],
        meta: tuple[_AshbyCapturedField, ...],
    ) -> list[AtsObservedField]:
        reviewed: list[AtsObservedField] = []
        for entry, row in zip(entries, meta, strict=True):
            if entry.action == "upload":
                if row.file_count != 1:
                    _refuse(
                        "reviewed_value_drift",
                        f"upload {row.field.field_id!r} lost its bound file",
                    )
                reviewed.append(
                    replace(row.field, current_value=entry.final_value)
                )
            else:
                reviewed.append(row.field)
        return reviewed

    @staticmethod
    def _verify_reviewed_values_exact(
        observed: tuple[AtsObservedField, ...],
        reviewed: list[AtsObservedField],
        entries: tuple[AtsAnswerEntry, ...],
    ) -> None:
        for initial, final, entry in zip(observed, reviewed, entries, strict=True):
            if initial.automation_role == "provider_managed":
                drift = final.current_value != initial.current_value
                detail = "provider-managed state changed"
            elif initial.automation_role == "honeypot":
                drift = final.current_value not in (None, "")
                detail = "honeypot changed"
            elif entry.action in {"fill", "upload"}:
                drift = final.current_value != entry.final_value
                detail = "reviewed value differs from exact authority"
            elif not is_ats_omitted_value_empty(
                initial.control_kind, final.current_value
            ):
                drift = True
                detail = "omitted field holds an unapproved value"
            else:
                drift = False
                detail = ""
            if drift:
                _refuse(
                    "reviewed_value_drift",
                    f"{initial.field_id}: {detail}",
                )


__all__ = [
    "ADAPTER_ID",
    "ADAPTER_VERSION",
    "APPLICATION_URL",
    "AshbyApplication",
    "AshbyApplicationBoundary",
    "AshbyBoundaryError",
    "AshbyCircuitError",
    "AshbyLiveAdapter",
    "AshbyNonReleasePreparation",
    "AshbyNonReleasePreparator",
    "AshbyOneUseCircuit",
    "AshbyPreflightReview",
    "AshbyPreparationRefused",
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
