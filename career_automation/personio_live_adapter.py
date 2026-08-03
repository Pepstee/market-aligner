"""Production-bounded Personio adapter for the CloudCops JAA-11 canary.

The adapter is intentionally limited to the exact reviewed CloudCops vacancy
and current Personio form schema.  It cannot navigate to, or submit, any other
vacancy.  A caller must attach :class:`PersonioNetworkTrace` before navigation
so the preflight can inspect the complete request set as well as visible
controls, serialized DOM and script URLs.

The consequential ordering is fail closed::

    full boundary/schema/blocker/duplicate preflight -> fill review only
    -> persist release-consumption-started -> consume JAA-08 authority
    -> persist release-consumed -> persist click-started/indeterminate
    -> exactly one click -> verify official proof -> hash-only receipt

There is deliberately no reset or retry from any state after release
consumption starts.  A crash before or after the click is indeterminate.
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


ADAPTER_ID = "jaa11.cloudcops-personio-live"
ADAPTER_VERSION = "v1"
APPLICATION_HOST = "cloudcops.jobs.personio.com"
APPLICATION_PATH = "/job/2183016"
APPLICATION_QUERY = "language=en&apply"
APPLICATION_URL = (
    f"https://{APPLICATION_HOST}{APPLICATION_PATH}?{APPLICATION_QUERY}"
)
FORM_API_URL = (
    f"https://{APPLICATION_HOST}/api/v1/jobs/2183016/"
    "application-form?language=en"
)
ROLE_TITLE = "Junior DevOps / Cloud Engineer | Jobs at CloudCops GmbH"
EMPLOYER_KEY = "cloudcops-gmbh"
VACANCY_ID = "2183016"
FROZEN_KEY = (
    "himalayas:https://himalayas.app/companies/cloudcops/jobs/"
    "junior-devops-cloud-engineer-5760182217"
)
PERSONIO_ALIAS = "personio:cloudcops:2183016"
SUBMIT_LABEL = "Submit Application"
SUCCESS_MARKER = (
    "We have received your application and will contact you shortly!"
)

HEX_64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^jaa08\.([0-9a-f]{64})\.[A-Za-z0-9_-]+$")


class PersonioBoundaryError(RuntimeError):
    """The page or observation left the exact approved Personio boundary."""


class PersonioSchemaError(RuntimeError):
    """The live form differs from the exact reviewed Personio schema."""


class PersonioCircuitError(RuntimeError):
    """The durable one-use circuit forbids this attempt."""


class PersonioSubmissionIndeterminateError(RuntimeError):
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
    if not isinstance(value, str) or HEX_64.fullmatch(value) is None:
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
        and parsed.query == APPLICATION_QUERY
        and not parsed.fragment
    )


@dataclass(frozen=True)
class InventoryEntry:
    name: str
    control_id: str
    field_type: str
    required: bool
    label: str
    placeholder: str = ""
    accept: str = ""
    multiple: bool = False

    def document(self) -> dict[str, object]:
        return {
            "name": self.name,
            "control_id": self.control_id,
            "field_type": self.field_type,
            "required": self.required,
            "label": self.label,
            "placeholder": self.placeholder,
            "accept": self.accept,
            "multiple": self.multiple,
        }


DOCUMENT_ACCEPT = (
    ".pdf,.docx,.doc,.png,.jpg,.jpeg,.txt,.odt,.ods,.xlsx,.rtf,.xls,"
    ".pptx,.ppt,.gif,.tif,.tiff,.bmp,.csv,.rar,.gz,.zip,.7z,.mp4,.3gp,"
    ".mov,.avi,.wmv"
)
EXPECTED_FORM_INVENTORY = (
    InventoryEntry("first_name", "field-first_name", "text", True, "First", "First"),
    InventoryEntry("last_name", "field-last_name", "text", True, "Last", "Last"),
    InventoryEntry(
        "email",
        "field-email",
        "email",
        True,
        "Email",
        "yourmail@domain.com",
    ),
    InventoryEntry(
        "phone",
        "field-phone",
        "text",
        True,
        "Phone",
        "+49 176 123 4455",
    ),
    InventoryEntry(
        "custom_attribute_3737466",
        "field-custom_attribute_3737466",
        "text",
        False,
        "LinkedIn",
        "LinkedIn",
    ),
    InventoryEntry(
        "documents.cv",
        "doc-input-cv",
        "file",
        True,
        "CV",
        accept=DOCUMENT_ACCEPT,
        multiple=True,
    ),
    InventoryEntry(
        "documents.other",
        "doc-input-other",
        "file",
        False,
        "Other (Optional)",
        accept=DOCUMENT_ACCEPT,
        multiple=True,
    ),
)
FORM_SCHEMA_SHA256 = _content_hash(
    [entry.document() for entry in EXPECTED_FORM_INVENTORY]
)

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
FORBIDDEN_TEXT_MARKERS = (
    "captcha",
    "create an account to apply",
    "sign in to apply",
    "log in to apply",
    "enter the verification code",
    "multi-factor authentication",
    "two-factor authentication",
    "payment required",
    "credit card required",
    "identity verification",
)
FORBIDDEN_SERIALIZED_MARKERS = (
    "g-recaptcha-response",
    "recaptchapublicsitekey",
    "google.com/recaptcha",
    "recaptcha.net/recaptcha",
    "hcaptcha",
    "turnstile",
    "captcha-token",
    'type="password"',
    'autocomplete="one-time-code"',
    "create-account",
    "identity-verification",
)
FORBIDDEN_URL_MARKERS = (
    "captcha",
    "recaptcha",
    "hcaptcha",
    "turnstile",
    "/login",
    "/signin",
    "/sign-in",
    "create-account",
    "/account/create",
    "/mfa",
    "two-factor",
    "/payment",
    "identity-verification",
)


@dataclass
class PersonioNetworkTrace:
    """Request trace that must be attached before initial navigation."""

    urls: list[str] = field(default_factory=list)
    attached_before_navigation: bool = False

    def attach(self, page: Page) -> None:
        if self.attached_before_navigation or self.urls:
            raise ValueError("network trace cannot be attached twice")
        if page.url not in {"", "about:blank"}:
            raise PersonioBoundaryError(
                "network trace must be attached before initial navigation"
            )
        self.attached_before_navigation = True
        page.on("request", lambda request: self.urls.append(request.url))

    def snapshot(self) -> tuple[str, ...]:
        if not self.attached_before_navigation:
            raise PersonioBoundaryError("network trace was not attached")
        return tuple(self.urls)


@dataclass(frozen=True)
class ContactProfileBinding:
    """Authoritative contact-profile values bound to their approved hash."""

    first_name: str = field(repr=False)
    last_name: str = field(repr=False)
    email: str = field(repr=False)
    phone: str = field(repr=False)
    profile_sha256: str
    schema: str = "jaa.authoritative-contact-profile.v1"

    def __post_init__(self) -> None:
        for value, label in (
            (self.first_name, "first name"),
            (self.last_name, "last name"),
            (self.email, "email"),
            (self.phone, "phone"),
        ):
            _required(value, label)
        if "@" not in self.email or "\n" in self.email:
            raise ValueError("email is invalid")
        _digest(self.profile_sha256, "contact-profile hash")
        if self.profile_sha256 != _content_hash(self.document()):
            raise ValueError("contact values differ from authoritative profile hash")

    def document(self) -> dict[str, str]:
        return {
            "schema": self.schema,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "phone": self.phone,
        }


@dataclass(frozen=True)
class DuplicateCheck:
    """Content-addressed upstream duplicate-ledger decision."""

    employer_key: str
    vacancy_id: str
    official_url: str
    checked_aliases: tuple[str, ...]
    duplicate_found: bool
    ledger_snapshot_sha256: str
    checked_at: datetime
    check_sha256: str

    def __post_init__(self) -> None:
        if self.checked_at.tzinfo is None or self.checked_at.utcoffset() is None:
            raise ValueError("duplicate-check time must include a timezone")
        _digest(self.ledger_snapshot_sha256, "duplicate-ledger snapshot hash")
        _digest(self.check_sha256, "duplicate-check hash")
        if self.employer_key != EMPLOYER_KEY or self.vacancy_id != VACANCY_ID:
            raise ValueError("duplicate check is for a different vacancy")
        if self.official_url != APPLICATION_URL:
            raise ValueError("duplicate check is for a different official route")
        if len(set(self.checked_aliases)) != len(self.checked_aliases):
            raise ValueError("duplicate aliases must be unique")
        if not {FROZEN_KEY, PERSONIO_ALIAS}.issubset(set(self.checked_aliases)):
            raise ValueError("duplicate check omitted required vacancy aliases")
        if self.check_sha256 != _content_hash(self.document()):
            raise ValueError("duplicate check differs from its content identity")

    def document(self) -> dict[str, object]:
        return {
            "schema": "jaa11.duplicate-check.v1",
            "employer_key": self.employer_key,
            "vacancy_id": self.vacancy_id,
            "official_url": self.official_url,
            "checked_aliases": list(self.checked_aliases),
            "duplicate_found": self.duplicate_found,
            "ledger_snapshot_sha256": self.ledger_snapshot_sha256,
            "checked_at": self.checked_at.isoformat(),
        }


@dataclass(frozen=True)
class PersonioApplication:
    contact: ContactProfileBinding = field(repr=False)
    cv_path: Path = field(repr=False)
    cv_sha256: str
    duplicate_check: DuplicateCheck

    def __post_init__(self) -> None:
        if not isinstance(self.contact, ContactProfileBinding):
            raise TypeError("application requires an authoritative contact profile")
        if not isinstance(self.duplicate_check, DuplicateCheck):
            raise TypeError("application requires a duplicate check")
        if self.duplicate_check.duplicate_found:
            raise ValueError("duplicate application exists for this vacancy")
        _regular_file(self.cv_path, self.cv_sha256, "approved CV")

    @property
    def payload_sha256(self) -> str:
        return _content_hash(
            {
                "contact_profile_sha256": self.contact.profile_sha256,
                "cv_sha256": self.cv_sha256,
                "duplicate_check_sha256": self.duplicate_check.check_sha256,
                "linkedin": "deliberately_omitted",
                "additional_document": "deliberately_omitted",
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
        if self.receipt_sha256 != _content_hash(dict(self.document)):
            raise ValueError("receipt content differs from its identity")


@dataclass(frozen=True)
class PersonioPreflightReview:
    review_sha256: str
    document: Mapping[str, object]

    def __post_init__(self) -> None:
        _digest(self.review_sha256, "preflight-review hash")
        if self.review_sha256 != _content_hash(dict(self.document)):
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


class PersonioOneUseCircuit:
    """SQLite one-use circuit with no reset path."""

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
                CREATE TABLE IF NOT EXISTS personio_circuit (
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
                CREATE TABLE IF NOT EXISTS personio_receipt (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    receipt_sha256 TEXT NOT NULL UNIQUE,
                    document_json TEXT NOT NULL
                );
                INSERT OR IGNORE INTO personio_circuit(singleton,state,version)
                VALUES(1,'ready',0);
                """
            )

    def snapshot(self) -> dict[str, object | None]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM personio_circuit WHERE singleton=1"
            ).fetchone()
        if row is None or str(row["state"]) not in self.STATES:
            raise PersonioCircuitError("durable circuit state is invalid")
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
                "SELECT * FROM personio_circuit WHERE singleton=1"
            ).fetchone()
            if row is None or str(row["state"]) != expected:
                raise PersonioCircuitError(
                    "one-use circuit is no longer in the expected state"
                )
            existing = row["binding_sha256"]
            if existing is not None and binding_sha256 not in {None, str(existing)}:
                raise PersonioCircuitError("circuit binding changed")
            changed = connection.execute(
                """UPDATE personio_circuit
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
                raise PersonioCircuitError("circuit transition lost its lease")
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
            reason_code="release_result_indeterminate_until_consumed_receipt",
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
            reason_code=None,
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
                "SELECT * FROM personio_circuit WHERE singleton=1"
            ).fetchone()
            if row is None or str(row["state"]) != "click_started":
                raise PersonioCircuitError(
                    "receipt cannot close a circuit without a started click"
                )
            connection.execute(
                """INSERT INTO personio_receipt(
                       singleton,receipt_sha256,document_json
                   ) VALUES(1,?,?)""",
                (receipt.receipt_sha256, _canonical_json(dict(receipt.document))),
            )
            changed = connection.execute(
                """UPDATE personio_circuit
                   SET state='succeeded',version=version+1,reason_code=NULL
                   WHERE singleton=1 AND state='click_started' AND version=?""",
                (int(row["version"]),),
            ).rowcount
            if changed != 1:
                raise PersonioCircuitError("receipt transition lost its lease")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def receipt(self) -> OfficialSuccessReceipt | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM personio_receipt WHERE singleton=1"
            ).fetchone()
        if row is None:
            return None
        try:
            document = json.loads(str(row["document_json"]))
        except json.JSONDecodeError as exc:
            raise PersonioCircuitError("durable receipt is invalid JSON") from exc
        if not isinstance(document, dict):
            raise PersonioCircuitError("durable receipt is not an object")
        return OfficialSuccessReceipt(str(row["receipt_sha256"]), document)


class PersonioLiveAdapter:
    """Review and, only with JAA-08 authority, submit the CloudCops form."""

    def __init__(self, circuit: PersonioOneUseCircuit) -> None:
        self.circuit = circuit

    @staticmethod
    def _inventory(page: Page) -> tuple[InventoryEntry, ...]:
        rows = page.locator("form input:not([type=hidden])").evaluate_all(
            """controls => controls.map(control => {
              const visibleLabelText = element => {
                if (!element) return '';
                return Array.from(element.childNodes)
                  .filter(node => node.nodeType === Node.TEXT_NODE ||
                    (node.nodeType === Node.ELEMENT_NODE &&
                     String(node.className).includes('optionalText')))
                  .map(node => node.textContent || '').join('');
              };
              const directLabel = control.id
                ? document.querySelector(`label[for="${CSS.escape(control.id)}"]`)
                : null;
              const group = control.closest('[role="group"]');
              const groupLabelId = group
                ? (group.getAttribute('aria-labelledby') || '') : '';
              const groupLabel = groupLabelId
                ? document.getElementById(groupLabelId) : null;
              const wrapper = control.closest(
                '.name-group-container,.DynamicForm_fieldWrapper__bb5uT,' +
                '.document-field-wrapper,[role="group"]'
              );
              const wrapperText = wrapper ? (wrapper.innerText || '') : '';
              let label = visibleLabelText(directLabel);
              if (control.name === 'first_name') label = 'First';
              if (control.name === 'last_name') label = 'Last';
              if (control.type === 'file' && groupLabel) {
                label = visibleLabelText(groupLabel);
              }
              return {
                name: control.name || '',
                control_id: control.id || '',
                field_type: control.getAttribute('type') ||
                  control.tagName.toLowerCase(),
                required: wrapperText.includes('(required)'),
                label: label.trim().replace(/\\s+/g, ' '),
                placeholder: control.getAttribute('placeholder') || '',
                accept: control.getAttribute('accept') || '',
                multiple: Boolean(control.multiple)
              };
            })"""
        )
        try:
            return tuple(
                InventoryEntry(
                    str(row["name"]),
                    str(row["control_id"]),
                    str(row["field_type"]),
                    bool(row["required"]),
                    str(row["label"]),
                    str(row["placeholder"]),
                    str(row["accept"]),
                    bool(row["multiple"]),
                )
                for row in rows
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PersonioSchemaError(
                "Personio form inventory could not be normalized"
            ) from exc

    @staticmethod
    def _assert_boundary(page: Page) -> None:
        if not _exact_application_url(page.url):
            raise PersonioBoundaryError(
                "page is outside the exact approved CloudCops/Personio route"
            )
        if page.title() != ROLE_TITLE:
            raise PersonioBoundaryError("page title differs from approved vacancy")

    @classmethod
    def _assert_schema(cls, page: Page) -> None:
        cls._assert_boundary(page)
        if cls._inventory(page) != EXPECTED_FORM_INVENTORY:
            raise PersonioSchemaError(
                "live Personio inventory differs from reviewed schema"
            )
        submit = page.get_by_role("button", name=SUBMIT_LABEL, exact=True)
        if submit.count() != 1:
            raise PersonioSchemaError("final submit control is not unique")

    @classmethod
    def _blocking_reasons(
        cls,
        page: Page,
        *,
        network_urls: tuple[str, ...],
    ) -> tuple[str, ...]:
        reasons: set[str] = set()
        if APPLICATION_URL not in network_urls or FORM_API_URL not in network_urls:
            reasons.add("incomplete_network_observation")
        for selector in FORBIDDEN_SELECTORS:
            if page.locator(selector).count() != 0:
                reasons.add("prohibited_control_present")
        body = page.locator("body").inner_text().casefold()
        if any(marker in body for marker in FORBIDDEN_TEXT_MARKERS):
            reasons.add("prohibited_visible_boundary_present")
        html = page.content().casefold().replace(" ", "")
        if any(marker in html for marker in FORBIDDEN_SERIALIZED_MARKERS):
            reasons.add("prohibited_serialized_boundary_present")
        script_urls = tuple(
            str(url)
            for url in page.locator("script[src]").evaluate_all(
                "scripts => scripts.map(script => script.src)"
            )
        )
        all_urls = tuple(url.casefold() for url in (*script_urls, *network_urls))
        if any(
            marker in url
            for url in all_urls
            for marker in FORBIDDEN_URL_MARKERS
        ):
            reasons.add("prohibited_url_boundary_present")
        return tuple(sorted(reasons))

    @staticmethod
    def _fill(page: Page, application: PersonioApplication) -> None:
        mapping = {
            "first_name": application.contact.first_name,
            "last_name": application.contact.last_name,
            "email": application.contact.email,
            "phone": application.contact.phone,
        }
        for name, value in mapping.items():
            control = page.locator(f'[name="{name}"]')
            control.fill(value)
            if control.input_value() != value:
                raise PersonioSchemaError(f"Personio field {name} did not bind")
        page.locator('[name="documents.cv"]').set_input_files(
            str(_regular_file(application.cv_path, application.cv_sha256, "approved CV"))
        )
        if page.locator('[name="documents.cv"]').evaluate(
            "input => input.files ? input.files.length : 0"
        ) != 1:
            raise PersonioSchemaError("approved CV upload did not bind exactly once")
        # Optional fields are intentionally blank and never synthesized.
        if page.locator('[name="custom_attribute_3737466"]').input_value() != "":
            raise PersonioSchemaError("optional LinkedIn field was not blank")
        if page.locator('[name="documents.other"]').evaluate(
            "input => input.files ? input.files.length : 0"
        ) != 0:
            raise PersonioSchemaError("optional additional document was not blank")

    @staticmethod
    def _binding(application: PersonioApplication) -> str:
        return _content_hash(
            {
                "adapter_id": ADAPTER_ID,
                "adapter_version": ADAPTER_VERSION,
                "application_url": APPLICATION_URL,
                "form_schema_sha256": FORM_SCHEMA_SHA256,
                "payload_sha256": application.payload_sha256,
                "duplicate_check_sha256": application.duplicate_check.check_sha256,
            }
        )

    def prepare_review(
        self,
        page: Page,
        *,
        application: PersonioApplication,
        network_trace: PersonioNetworkTrace,
    ) -> PersonioPreflightReview:
        self._assert_schema(page)
        network_urls = network_trace.snapshot()
        reasons = list(self._blocking_reasons(page, network_urls=network_urls))
        if application.duplicate_check.duplicate_found:
            reasons.append("duplicate_application_present")
        if reasons:
            document: dict[str, object] = {
                "schema": "jaa11.personio-preflight-review.v1",
                "adapter_id": ADAPTER_ID,
                "application_url_sha256": hashlib.sha256(
                    APPLICATION_URL.encode()
                ).hexdigest(),
                "form_schema_sha256": FORM_SCHEMA_SHA256,
                "payload_sha256": application.payload_sha256,
                "duplicate_check_sha256": application.duplicate_check.check_sha256,
                "network_trace_sha256": _content_hash(list(network_urls)),
                "eligible_for_submit": False,
                "reason_codes": sorted(set(reasons)),
                "fields_populated": False,
                "release_consumed": False,
                "submit_clicked": False,
            }
            return PersonioPreflightReview(_content_hash(document), document)

        # Population happens only after the complete blocker scan has passed.
        self._fill(page, application)
        screenshot_sha256 = hashlib.sha256(
            page.screenshot(full_page=True)
        ).hexdigest()
        document = {
            "schema": "jaa11.personio-preflight-review.v1",
            "adapter_id": ADAPTER_ID,
            "application_url_sha256": hashlib.sha256(
                APPLICATION_URL.encode()
            ).hexdigest(),
            "form_schema_sha256": FORM_SCHEMA_SHA256,
            "payload_sha256": application.payload_sha256,
            "duplicate_check_sha256": application.duplicate_check.check_sha256,
            "network_trace_sha256": _content_hash(list(network_urls)),
            "review_screenshot_sha256": screenshot_sha256,
            "eligible_for_submit": True,
            "reason_codes": [],
            "fields_populated": True,
            "optional_linkedin": "deliberately_omitted",
            "optional_additional_document": "deliberately_omitted",
            "release_consumed": False,
            "submit_clicked": False,
        }
        return PersonioPreflightReview(_content_hash(document), document)

    def submit(
        self,
        page: Page,
        *,
        application: PersonioApplication,
        network_trace: PersonioNetworkTrace,
        authority: JAA08ReleaseAuthority,
    ) -> OfficialSuccessReceipt:
        try:
            review = self.prepare_review(
                page,
                application=application,
                network_trace=network_trace,
            )
        except Exception:
            if self.circuit.snapshot()["state"] == "ready":
                self.circuit.block("preflight_failure")
            raise
        if not review.eligible_for_submit:
            self.circuit.block(review.reason_codes[0] if review.reason_codes else "parked")
            raise PersonioSchemaError("Personio canary is parked by preflight")

        binding = self._binding(application)
        try:
            self.circuit.prepare(binding)
            # Recheck the full boundary immediately before release consumption.
            self._assert_schema(page)
            reasons = self._blocking_reasons(
                page,
                network_urls=network_trace.snapshot(),
            )
            if reasons:
                self.circuit.block(reasons[0])
                raise PersonioSchemaError("Personio boundary changed after review")
            self.circuit.consumption_started(binding)
            try:
                consumed = authority.consume()
            except Exception as exc:
                raise PersonioSubmissionIndeterminateError(
                    "release consumption started; retry is forbidden"
                ) from exc

            receipt_manifest = getattr(consumed, "release_manifest_sha256", None)
            receipt_token = getattr(consumed, "token_sha256", None)
            if (
                receipt_manifest != authority.release_manifest_sha256
                or receipt_token != authority.token_sha256
            ):
                raise PersonioSubmissionIndeterminateError(
                    "release-consumption receipt differs from authority"
                )
            self.circuit.release_consumed(
                binding,
                authority.release_manifest_sha256,
                authority.token_sha256,
            )
            submit = page.get_by_role("button", name=SUBMIT_LABEL, exact=True)
            if submit.count() != 1:
                raise PersonioSubmissionIndeterminateError(
                    "submit control changed after release consumption"
                )
            self.circuit.click_started(binding)
            try:
                submit.click()
            except Exception as exc:
                raise PersonioSubmissionIndeterminateError(
                    "submit click outcome is unknown; retry is forbidden"
                ) from exc

            success = page.get_by_text(SUCCESS_MARKER, exact=True)
            submit_remaining = page.get_by_role(
                "button", name=SUBMIT_LABEL, exact=True
            ).count()
            if success.count() != 1 or not success.is_visible() or submit_remaining != 0:
                raise PersonioSubmissionIndeterminateError(
                    "official Personio success proof is absent; retry is forbidden"
                )
            now = datetime.now().astimezone()
            receipt_document: dict[str, object] = {
                "schema": "jaa11.personio-official-receipt.v1",
                "adapter_id": ADAPTER_ID,
                "adapter_version": ADAPTER_VERSION,
                "application_url_sha256": hashlib.sha256(
                    APPLICATION_URL.encode()
                ).hexdigest(),
                "vacancy_id_sha256": hashlib.sha256(VACANCY_ID.encode()).hexdigest(),
                "form_schema_sha256": FORM_SCHEMA_SHA256,
                "binding_sha256": binding,
                "payload_sha256": application.payload_sha256,
                "duplicate_check_sha256": application.duplicate_check.check_sha256,
                "release_manifest_sha256": authority.release_manifest_sha256,
                "release_token_sha256": authority.token_sha256,
                "success_marker_sha256": hashlib.sha256(
                    SUCCESS_MARKER.encode()
                ).hexdigest(),
                "success_dom_sha256": hashlib.sha256(
                    page.content().encode()
                ).hexdigest(),
                "success_screenshot_sha256": hashlib.sha256(
                    page.screenshot(full_page=True)
                ).hexdigest(),
                "observed_at": now.isoformat(),
            }
            receipt = OfficialSuccessReceipt(
                _content_hash(receipt_document), receipt_document
            )
            self.circuit.succeed(receipt)
            return receipt
        except PersonioSubmissionIndeterminateError:
            raise
        except Exception:
            state = str(self.circuit.snapshot()["state"])
            if state in {
                "release_consumption_started",
                "release_consumed",
                "click_started",
            }:
                raise PersonioSubmissionIndeterminateError(
                    "consequential state reached; retry is forbidden"
                )
            if state not in {"blocked", "succeeded"}:
                self.circuit.block("pre_submit_failure")
            raise
