"""Pure-data intake contracts for the narrow JAA-11 live-canary authority.

This module does not discover vacancies, access a network, operate a browser,
release an application, or submit anything.  It verifies caller-supplied
selection evidence against the frozen operator scope while keeping the
separate operational release gate withheld.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
AUTHORITY_PATH_BASE = "software_factory_root"
AUTHORITY_RELATIVE_PATH = (
    "giga-user/reports/"
    "JAA11_LIVE_CANARY_OPERATOR_AUTHORITY_2026-07-31.md"
)
AUTHORITY_FILE_SHA256 = (
    "b1cc3740a7d760ab905c27156bf8498bb7f03f8cfe5e9267b82e2ad6f2a9f77c"
)
MAX_CANARIES = 1
FORBIDDEN_RANKS = tuple(range(1, 21))
MINIMUM_SELECTED_RANK = 21
FAIL_CLOSED_TRIGGERS = (
    "account_creation",
    "captcha",
    "login",
    "mfa",
    "missing_approved_fact",
    "payment",
)


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
    if not clean or clean != value:
        raise ValueError(
            f"{label} is required without surrounding whitespace"
        )
    return clean


def _aware_iso(value: str, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a canonical aware ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(
            f"{label} must be a canonical aware ISO timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(
            f"{label} must be a canonical aware ISO timestamp"
        )
    if parsed.isoformat() != value:
        raise ValueError(
            f"{label} must be a canonical aware ISO timestamp"
        )
    return parsed


def _official_https_url(value: str) -> str:
    clean = _required(value, "vacancy URL")
    parsed = urlsplit(clean)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(
            "vacancy URL must be a fragment-free official HTTPS URL"
        )
    return clean


@dataclass(frozen=True)
class LiveCanaryOperatorAuthority:
    path_base: str
    relative_path: str
    authority_file_sha256: str
    max_canaries: int
    forbidden_ranks: tuple[int, ...]
    minimum_selected_rank: int
    optional_marketing_consent: str
    fail_closed_triggers: tuple[str, ...]
    public_multi_vacancy_acquisition_authorized: bool
    public_acquisition_referral_required: bool
    expires_on_first_submission: bool
    expires_on_jaa11_certification: bool
    operational_release: str = "withheld"
    schema_version: str = "jaa11.live-canary-operator-authority.v1"

    def __post_init__(self) -> None:
        _digest(self.authority_file_sha256, "authority file hash")
        expected = (
            AUTHORITY_PATH_BASE,
            AUTHORITY_RELATIVE_PATH,
            AUTHORITY_FILE_SHA256,
            MAX_CANARIES,
            FORBIDDEN_RANKS,
            MINIMUM_SELECTED_RANK,
            "declined",
            FAIL_CLOSED_TRIGGERS,
            False,
            True,
            True,
            True,
            "withheld",
            "jaa11.live-canary-operator-authority.v1",
        )
        actual = (
            self.path_base,
            self.relative_path,
            self.authority_file_sha256,
            self.max_canaries,
            self.forbidden_ranks,
            self.minimum_selected_rank,
            self.optional_marketing_consent,
            self.fail_closed_triggers,
            self.public_multi_vacancy_acquisition_authorized,
            self.public_acquisition_referral_required,
            self.expires_on_first_submission,
            self.expires_on_jaa11_certification,
            self.operational_release,
            self.schema_version,
        )
        if actual != expected:
            raise ValueError(
                "operator authority record differs from the frozen scope"
            )

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "authority_document": {
                "path_base": self.path_base,
                "relative_path": self.relative_path,
                "sha256": self.authority_file_sha256,
            },
            "max_canaries": self.max_canaries,
            "forbidden_ranks": list(self.forbidden_ranks),
            "minimum_selected_rank": self.minimum_selected_rank,
            "optional_marketing_consent": self.optional_marketing_consent,
            "fail_closed_triggers": list(self.fail_closed_triggers),
            "public_multi_vacancy_acquisition_authorized": (
                self.public_multi_vacancy_acquisition_authorized
            ),
            "public_acquisition_referral_required": (
                self.public_acquisition_referral_required
            ),
            "expires_on_first_submission": (
                self.expires_on_first_submission
            ),
            "expires_on_jaa11_certification": (
                self.expires_on_jaa11_certification
            ),
            "operational_release": self.operational_release,
        }

    @property
    def record_sha256(self) -> str:
        return _content_hash(self.document())


FROZEN_LIVE_CANARY_AUTHORITY = LiveCanaryOperatorAuthority(
    path_base=AUTHORITY_PATH_BASE,
    relative_path=AUTHORITY_RELATIVE_PATH,
    authority_file_sha256=AUTHORITY_FILE_SHA256,
    max_canaries=MAX_CANARIES,
    forbidden_ranks=FORBIDDEN_RANKS,
    minimum_selected_rank=MINIMUM_SELECTED_RANK,
    optional_marketing_consent="declined",
    fail_closed_triggers=FAIL_CLOSED_TRIGGERS,
    public_multi_vacancy_acquisition_authorized=False,
    public_acquisition_referral_required=True,
    expires_on_first_submission=True,
    expires_on_jaa11_certification=True,
)


@dataclass(frozen=True)
class CanarySelectionContract:
    authority_record_sha256: str
    ranked_snapshot_sha256: str
    ranking_algorithm: str
    ranking_version: str
    snapshot_entry_count: int
    selected_rank: int
    vacancy_identity: str
    vacancy_url: str
    vacancy_retrieved_at: str
    vacancy_content_sha256: str
    selected_entry_sha256: str
    duplicate_application_found: bool
    eligibility_gate_passed: bool
    truth_gate_passed: bool
    vacancy_open: bool
    official_route: bool
    selected_only_for_submission_ease: bool
    account_creation_required: bool
    login_required: bool
    mfa_required: bool
    captcha_required: bool
    payment_required: bool
    missing_approved_fact: bool
    optional_marketing_consent: str
    public_acquisition_used: bool
    contract_sha256: str
    operational_release: str = "withheld"
    external_action_capability: bool = False
    schema_version: str = "jaa11.live-canary-selection.v1"

    def __post_init__(self) -> None:
        for value, label in (
            (self.authority_record_sha256, "authority record hash"),
            (self.ranked_snapshot_sha256, "ranked snapshot hash"),
            (self.vacancy_content_sha256, "vacancy content hash"),
            (self.selected_entry_sha256, "selected entry hash"),
            (self.contract_sha256, "selection contract hash"),
        ):
            _digest(value, label)
        if (
            self.authority_record_sha256
            != FROZEN_LIVE_CANARY_AUTHORITY.record_sha256
        ):
            raise ValueError("selection uses an unaccepted authority record")
        _required(self.ranking_algorithm, "ranking algorithm")
        _required(self.ranking_version, "ranking version")
        _required(self.vacancy_identity, "vacancy identity")
        _official_https_url(self.vacancy_url)
        _aware_iso(self.vacancy_retrieved_at, "vacancy retrieval time")
        if (
            type(self.snapshot_entry_count) is not int
            or self.snapshot_entry_count < MINIMUM_SELECTED_RANK
        ):
            raise ValueError("ranked snapshot must contain at least 21 entries")
        if (
            type(self.selected_rank) is not int
            or self.selected_rank < MINIMUM_SELECTED_RANK
            or self.selected_rank > self.snapshot_entry_count
        ):
            raise ValueError(
                "selected rank must be present and outside ranks 1-20"
            )
        required_booleans = (
            self.duplicate_application_found,
            self.eligibility_gate_passed,
            self.truth_gate_passed,
            self.vacancy_open,
            self.official_route,
            self.selected_only_for_submission_ease,
            self.account_creation_required,
            self.login_required,
            self.mfa_required,
            self.captcha_required,
            self.payment_required,
            self.missing_approved_fact,
            self.public_acquisition_used,
            self.external_action_capability,
        )
        if any(type(value) is not bool for value in required_booleans):
            raise ValueError("selection gate results must be unambiguous booleans")
        if self.duplicate_application_found:
            raise ValueError("duplicate application evidence fails closed")
        if not self.eligibility_gate_passed or not self.truth_gate_passed:
            raise ValueError("eligibility and truth gates must pass")
        if not self.vacancy_open or not self.official_route:
            raise ValueError("vacancy must be open on an official route")
        if self.selected_only_for_submission_ease:
            raise ValueError("selection cannot be based only on ease")
        if any((
            self.account_creation_required,
            self.login_required,
            self.mfa_required,
            self.captcha_required,
            self.payment_required,
            self.missing_approved_fact,
        )):
            raise ValueError("authority fail-closed trigger is present")
        if self.optional_marketing_consent != "declined":
            raise ValueError("optional marketing consent must remain declined")
        if self.public_acquisition_used:
            raise ValueError(
                "public vacancy acquisition requires a new operator referral"
            )
        if (
            self.operational_release != "withheld"
            or self.external_action_capability is not False
        ):
            raise ValueError(
                "selection contract cannot grant operational release"
            )
        expected_hash = _content_hash(self.document(include_hash=False))
        if self.contract_sha256 != expected_hash:
            raise ValueError("selection contract hash is invalid")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        document = {
            "schema_version": self.schema_version,
            "authority_record_sha256": self.authority_record_sha256,
            "ranked_snapshot_sha256": self.ranked_snapshot_sha256,
            "ranking_algorithm": self.ranking_algorithm,
            "ranking_version": self.ranking_version,
            "snapshot_entry_count": self.snapshot_entry_count,
            "selected_rank": self.selected_rank,
            "vacancy_identity": self.vacancy_identity,
            "vacancy_url": self.vacancy_url,
            "vacancy_retrieved_at": self.vacancy_retrieved_at,
            "vacancy_content_sha256": self.vacancy_content_sha256,
            "selected_entry_sha256": self.selected_entry_sha256,
            "duplicate_application_found": (
                self.duplicate_application_found
            ),
            "eligibility_gate_passed": self.eligibility_gate_passed,
            "truth_gate_passed": self.truth_gate_passed,
            "vacancy_open": self.vacancy_open,
            "official_route": self.official_route,
            "selected_only_for_submission_ease": (
                self.selected_only_for_submission_ease
            ),
            "account_creation_required": self.account_creation_required,
            "login_required": self.login_required,
            "mfa_required": self.mfa_required,
            "captcha_required": self.captcha_required,
            "payment_required": self.payment_required,
            "missing_approved_fact": self.missing_approved_fact,
            "optional_marketing_consent": self.optional_marketing_consent,
            "public_acquisition_used": self.public_acquisition_used,
            "operational_release": self.operational_release,
            "external_action_capability": self.external_action_capability,
        }
        if include_hash:
            document["contract_sha256"] = self.contract_sha256
        return document


def compile_canary_selection(
    authority: LiveCanaryOperatorAuthority,
    *,
    ranked_snapshot_sha256: str,
    ranking_algorithm: str,
    ranking_version: str,
    snapshot_entry_count: int,
    selected_rank: int,
    vacancy_identity: str,
    vacancy_url: str,
    vacancy_retrieved_at: str,
    vacancy_content_sha256: str,
    selected_entry_sha256: str,
    duplicate_application_found: bool,
    eligibility_gate_passed: bool,
    truth_gate_passed: bool,
    vacancy_open: bool,
    official_route: bool,
    selected_only_for_submission_ease: bool,
    account_creation_required: bool,
    login_required: bool,
    mfa_required: bool,
    captcha_required: bool,
    payment_required: bool,
    missing_approved_fact: bool,
    optional_marketing_consent: str,
    public_acquisition_used: bool,
) -> CanarySelectionContract:
    if authority != FROZEN_LIVE_CANARY_AUTHORITY:
        raise ValueError("selection requires the frozen operator authority")
    fields: dict[str, object] = {
        "authority_record_sha256": authority.record_sha256,
        "ranked_snapshot_sha256": ranked_snapshot_sha256,
        "ranking_algorithm": ranking_algorithm,
        "ranking_version": ranking_version,
        "snapshot_entry_count": snapshot_entry_count,
        "selected_rank": selected_rank,
        "vacancy_identity": vacancy_identity,
        "vacancy_url": vacancy_url,
        "vacancy_retrieved_at": vacancy_retrieved_at,
        "vacancy_content_sha256": vacancy_content_sha256,
        "selected_entry_sha256": selected_entry_sha256,
        "duplicate_application_found": duplicate_application_found,
        "eligibility_gate_passed": eligibility_gate_passed,
        "truth_gate_passed": truth_gate_passed,
        "vacancy_open": vacancy_open,
        "official_route": official_route,
        "selected_only_for_submission_ease": (
            selected_only_for_submission_ease
        ),
        "account_creation_required": account_creation_required,
        "login_required": login_required,
        "mfa_required": mfa_required,
        "captcha_required": captcha_required,
        "payment_required": payment_required,
        "missing_approved_fact": missing_approved_fact,
        "optional_marketing_consent": optional_marketing_consent,
        "public_acquisition_used": public_acquisition_used,
        "operational_release": "withheld",
        "external_action_capability": False,
        "schema_version": "jaa11.live-canary-selection.v1",
    }
    fields["contract_sha256"] = _content_hash(fields)
    return CanarySelectionContract(**fields)  # type: ignore[arg-type]


@dataclass(frozen=True)
class LiveCanaryAuthorityState:
    status: str
    reasons: tuple[str, ...]
    remaining_canaries: int
    operational_release: str = "withheld"
    may_submit: bool = False


def evaluate_live_canary_authority(
    authority: LiveCanaryOperatorAuthority,
    *,
    submission_count: int | None,
    jaa11_certified: bool | None,
) -> LiveCanaryAuthorityState:
    """Evaluate scope availability without opening the release gate."""

    if authority != FROZEN_LIVE_CANARY_AUTHORITY:
        return LiveCanaryAuthorityState(
            status="withheld",
            reasons=("authority_record_unaccepted",),
            remaining_canaries=0,
        )
    if (
        submission_count is None
        or isinstance(submission_count, bool)
        or submission_count < 0
        or type(jaa11_certified) is not bool
    ):
        return LiveCanaryAuthorityState(
            status="withheld",
            reasons=("authority_state_ambiguous",),
            remaining_canaries=0,
        )
    reasons: list[str] = []
    if submission_count >= authority.max_canaries:
        reasons.append("single_use_submission_consumed")
    if jaa11_certified:
        reasons.append("jaa11_already_certified")
    if reasons:
        return LiveCanaryAuthorityState(
            status="exhausted",
            reasons=tuple(reasons),
            remaining_canaries=0,
        )
    return LiveCanaryAuthorityState(
        status="permitted",
        reasons=("operator_scope_available_release_still_withheld",),
        remaining_canaries=1,
    )
