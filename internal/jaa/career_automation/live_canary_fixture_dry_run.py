"""Pure-fixture ranked-snapshot dry runs for the JAA-11 canary boundary.

This module performs no I/O and claims no live snapshot, selected external
target, release, submission, or certification authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from career_automation.live_canary_authority import (
    FORBIDDEN_RANKS,
    FROZEN_LIVE_CANARY_AUTHORITY,
    MINIMUM_SELECTED_RANK,
    CanarySelectionContract,
    _aware_iso,
    _content_hash,
    _digest,
    _official_https_url,
    _required,
    compile_canary_selection,
    evaluate_live_canary_authority,
)


SNAPSHOT_SCHEMA = "jaa11.live-canary-ranked-snapshot-fixture.v1"
DRY_RUN_SCHEMA = "jaa11.live-canary-ranked-snapshot-dry-run.v1"
SNAPSHOT_KEYS = frozenset({
    "schema_version",
    "ranking_algorithm",
    "ranking_version",
    "snapshot_taken_at",
    "entries",
})
ENTRY_KEYS = frozenset({
    "rank",
    "vacancy_identity",
    "vacancy_url",
    "vacancy_content_sha256",
    "vacancy_retrieved_at",
})
SELECTION_EVIDENCE_KEYS = frozenset({
    "selected_rank",
    "duplicate_application_found",
    "eligibility_gate_passed",
    "truth_gate_passed",
    "vacancy_open",
    "official_route",
    "selected_only_for_submission_ease",
    "account_creation_required",
    "login_required",
    "mfa_required",
    "captcha_required",
    "payment_required",
    "missing_approved_fact",
    "optional_marketing_consent",
    "public_acquisition_used",
})


def _strict_dict(
    value: object,
    expected_keys: frozenset[str],
    label: str,
) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(f"{label} must be a strict object")
    actual_keys = frozenset(value)
    if actual_keys != expected_keys:
        raise ValueError(f"{label} fields are missing or unknown")
    return value


@dataclass(frozen=True)
class RankedVacancyFixture:
    rank: int
    vacancy_identity: str
    vacancy_url: str
    vacancy_content_sha256: str
    vacancy_retrieved_at: str

    def document(self) -> dict[str, object]:
        return {
            "rank": self.rank,
            "vacancy_identity": self.vacancy_identity,
            "vacancy_url": self.vacancy_url,
            "vacancy_content_sha256": self.vacancy_content_sha256,
            "vacancy_retrieved_at": self.vacancy_retrieved_at,
        }


@dataclass(frozen=True)
class RankedSnapshotFixture:
    ranking_algorithm: str
    ranking_version: str
    snapshot_taken_at: str
    entries: tuple[RankedVacancyFixture, ...]
    schema_version: str = SNAPSHOT_SCHEMA

    def document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "ranking_algorithm": self.ranking_algorithm,
            "ranking_version": self.ranking_version,
            "snapshot_taken_at": self.snapshot_taken_at,
            "entries": [entry.document() for entry in self.entries],
        }

    @property
    def snapshot_sha256(self) -> str:
        return _content_hash(self.document())


@dataclass(frozen=True)
class LiveCanaryFixtureDryRun:
    snapshot: RankedSnapshotFixture
    selected_entry: RankedVacancyFixture
    selection_contract: CanarySelectionContract
    ranked_snapshot_sha256: str
    selected_entry_sha256: str
    dry_run_sha256: str
    snapshot_source: str = "caller_supplied_fixture"
    snapshot_is_live: bool = False
    snapshot_is_current: bool = False
    selected_vacancy_status: str = (
        "fixture_only_not_selected_for_external_use"
    )
    operational_release: str = "withheld"
    may_submit: bool = False
    external_action_capability: bool = False
    certifies_slice: bool = False
    receipt_written: bool = False
    real_applications: int = 0
    schema_version: str = DRY_RUN_SCHEMA

    def __post_init__(self) -> None:
        _digest(self.ranked_snapshot_sha256, "ranked snapshot hash")
        _digest(self.selected_entry_sha256, "selected entry hash")
        _digest(self.dry_run_sha256, "dry-run hash")
        expected_boundary = (
            "caller_supplied_fixture",
            False,
            False,
            "fixture_only_not_selected_for_external_use",
            "withheld",
            False,
            False,
            False,
            False,
            0,
            DRY_RUN_SCHEMA,
        )
        actual_boundary = (
            self.snapshot_source,
            self.snapshot_is_live,
            self.snapshot_is_current,
            self.selected_vacancy_status,
            self.operational_release,
            self.may_submit,
            self.external_action_capability,
            self.certifies_slice,
            self.receipt_written,
            self.real_applications,
            self.schema_version,
        )
        if actual_boundary != expected_boundary:
            raise ValueError("fixture dry run cannot open an external boundary")
        if self.ranked_snapshot_sha256 != self.snapshot.snapshot_sha256:
            raise ValueError("fixture snapshot hash is invalid")
        if self.selected_entry_sha256 != _content_hash(
            self.selected_entry.document()
        ):
            raise ValueError("fixture selected-entry hash is invalid")
        if (
            self.selection_contract.ranked_snapshot_sha256
            != self.ranked_snapshot_sha256
            or self.selection_contract.selected_entry_sha256
            != self.selected_entry_sha256
        ):
            raise ValueError("selection contract is not bound to fixture hashes")
        if self.dry_run_sha256 != _content_hash(
            self.document(include_hash=False)
        ):
            raise ValueError("fixture dry-run hash is invalid")

    def document(self, *, include_hash: bool = True) -> dict[str, object]:
        document = {
            "schema_version": self.schema_version,
            "snapshot": self.snapshot.document(),
            "ranked_snapshot_sha256": self.ranked_snapshot_sha256,
            "selected_entry": self.selected_entry.document(),
            "selected_entry_sha256": self.selected_entry_sha256,
            "selection_contract": self.selection_contract.document(),
            "snapshot_source": self.snapshot_source,
            "snapshot_is_live": self.snapshot_is_live,
            "snapshot_is_current": self.snapshot_is_current,
            "selected_vacancy_status": self.selected_vacancy_status,
            "operational_release": self.operational_release,
            "may_submit": self.may_submit,
            "external_action_capability": self.external_action_capability,
            "certifies_slice": self.certifies_slice,
            "receipt_written": self.receipt_written,
            "real_applications": self.real_applications,
        }
        if include_hash:
            document["dry_run_sha256"] = self.dry_run_sha256
        return document


def _compile_snapshot(value: object) -> RankedSnapshotFixture:
    snapshot = _strict_dict(value, SNAPSHOT_KEYS, "snapshot fixture")
    if snapshot["schema_version"] != SNAPSHOT_SCHEMA:
        raise ValueError("snapshot fixture schema is invalid")
    ranking_algorithm = _required(
        snapshot["ranking_algorithm"],  # type: ignore[arg-type]
        "ranking algorithm",
    )
    ranking_version = _required(
        snapshot["ranking_version"],  # type: ignore[arg-type]
        "ranking version",
    )
    snapshot_taken_at = snapshot["snapshot_taken_at"]
    snapshot_time = _aware_iso(
        snapshot_taken_at,  # type: ignore[arg-type]
        "snapshot time",
    )
    raw_entries = snapshot["entries"]
    if type(raw_entries) is not list:
        raise ValueError("snapshot entries must be an ordered list")
    if len(raw_entries) < MINIMUM_SELECTED_RANK:
        raise ValueError("snapshot fixture must contain at least 21 entries")

    entries: list[RankedVacancyFixture] = []
    identities: set[str] = set()
    urls: set[str] = set()
    for position, raw_entry in enumerate(raw_entries, start=1):
        entry = _strict_dict(raw_entry, ENTRY_KEYS, "snapshot entry")
        rank = entry["rank"]
        if type(rank) is not int or rank != position:
            raise ValueError(
                "snapshot ranks must be exact contiguous integers from 1"
            )
        vacancy_identity = _required(
            entry["vacancy_identity"],  # type: ignore[arg-type]
            "vacancy identity",
        )
        vacancy_url = _official_https_url(
            entry["vacancy_url"],  # type: ignore[arg-type]
        )
        vacancy_content_sha256 = _digest(
            entry["vacancy_content_sha256"],  # type: ignore[arg-type]
            "vacancy content hash",
        )
        vacancy_retrieved_at = entry["vacancy_retrieved_at"]
        retrieved_time = _aware_iso(
            vacancy_retrieved_at,  # type: ignore[arg-type]
            "vacancy retrieval time",
        )
        if retrieved_time > snapshot_time:
            raise ValueError("vacancy retrieval cannot postdate the snapshot")
        if vacancy_identity in identities:
            raise ValueError("snapshot vacancy identities must be unique")
        if vacancy_url in urls:
            raise ValueError("snapshot vacancy URLs must be unique")
        identities.add(vacancy_identity)
        urls.add(vacancy_url)
        entries.append(
            RankedVacancyFixture(
                rank=rank,
                vacancy_identity=vacancy_identity,
                vacancy_url=vacancy_url,
                vacancy_content_sha256=vacancy_content_sha256,
                vacancy_retrieved_at=vacancy_retrieved_at,  # type: ignore[arg-type]
            )
        )
    return RankedSnapshotFixture(
        ranking_algorithm=ranking_algorithm,
        ranking_version=ranking_version,
        snapshot_taken_at=snapshot_taken_at,  # type: ignore[arg-type]
        entries=tuple(entries),
    )


def compile_live_canary_fixture_dry_run(
    snapshot_fixture: object,
    selected_entry_evidence: object,
    *,
    submission_count: int | None,
    jaa11_certified: bool | None,
) -> LiveCanaryFixtureDryRun:
    """Compile one deterministic fixture-only selection dry run."""

    authority_state = evaluate_live_canary_authority(
        FROZEN_LIVE_CANARY_AUTHORITY,
        submission_count=submission_count,
        jaa11_certified=jaa11_certified,
    )
    if authority_state.status != "permitted":
        raise ValueError("live-canary authority is unavailable or ambiguous")

    snapshot = _compile_snapshot(snapshot_fixture)
    evidence = _strict_dict(
        selected_entry_evidence,
        SELECTION_EVIDENCE_KEYS,
        "selected-entry evidence",
    )
    selected_rank = evidence["selected_rank"]
    if (
        type(selected_rank) is not int
        or selected_rank in FORBIDDEN_RANKS
        or selected_rank < MINIMUM_SELECTED_RANK
        or selected_rank > len(snapshot.entries)
    ):
        raise ValueError("selected rank must be present and outside ranks 1-20")
    selected_entry = snapshot.entries[selected_rank - 1]
    ranked_snapshot_sha256 = snapshot.snapshot_sha256
    selected_entry_sha256 = _content_hash(selected_entry.document())
    selection = compile_canary_selection(
        FROZEN_LIVE_CANARY_AUTHORITY,
        ranked_snapshot_sha256=ranked_snapshot_sha256,
        ranking_algorithm=snapshot.ranking_algorithm,
        ranking_version=snapshot.ranking_version,
        snapshot_entry_count=len(snapshot.entries),
        selected_rank=selected_rank,
        vacancy_identity=selected_entry.vacancy_identity,
        vacancy_url=selected_entry.vacancy_url,
        vacancy_retrieved_at=selected_entry.vacancy_retrieved_at,
        vacancy_content_sha256=selected_entry.vacancy_content_sha256,
        selected_entry_sha256=selected_entry_sha256,
        duplicate_application_found=evidence[
            "duplicate_application_found"
        ],  # type: ignore[arg-type]
        eligibility_gate_passed=evidence[
            "eligibility_gate_passed"
        ],  # type: ignore[arg-type]
        truth_gate_passed=evidence[
            "truth_gate_passed"
        ],  # type: ignore[arg-type]
        vacancy_open=evidence["vacancy_open"],  # type: ignore[arg-type]
        official_route=evidence["official_route"],  # type: ignore[arg-type]
        selected_only_for_submission_ease=evidence[
            "selected_only_for_submission_ease"
        ],  # type: ignore[arg-type]
        account_creation_required=evidence[
            "account_creation_required"
        ],  # type: ignore[arg-type]
        login_required=evidence["login_required"],  # type: ignore[arg-type]
        mfa_required=evidence["mfa_required"],  # type: ignore[arg-type]
        captcha_required=evidence["captcha_required"],  # type: ignore[arg-type]
        payment_required=evidence["payment_required"],  # type: ignore[arg-type]
        missing_approved_fact=evidence[
            "missing_approved_fact"
        ],  # type: ignore[arg-type]
        optional_marketing_consent=evidence[
            "optional_marketing_consent"
        ],  # type: ignore[arg-type]
        public_acquisition_used=evidence[
            "public_acquisition_used"
        ],  # type: ignore[arg-type]
    )
    fields: dict[str, object] = {
        "snapshot": snapshot,
        "selected_entry": selected_entry,
        "selection_contract": selection,
        "ranked_snapshot_sha256": ranked_snapshot_sha256,
        "selected_entry_sha256": selected_entry_sha256,
        "snapshot_source": "caller_supplied_fixture",
        "snapshot_is_live": False,
        "snapshot_is_current": False,
        "selected_vacancy_status": (
            "fixture_only_not_selected_for_external_use"
        ),
        "operational_release": "withheld",
        "may_submit": False,
        "external_action_capability": False,
        "certifies_slice": False,
        "receipt_written": False,
        "real_applications": 0,
        "schema_version": DRY_RUN_SCHEMA,
    }
    fields["dry_run_sha256"] = _content_hash({
        "schema_version": DRY_RUN_SCHEMA,
        "snapshot": snapshot.document(),
        "ranked_snapshot_sha256": ranked_snapshot_sha256,
        "selected_entry": selected_entry.document(),
        "selected_entry_sha256": selected_entry_sha256,
        "selection_contract": selection.document(),
        "snapshot_source": "caller_supplied_fixture",
        "snapshot_is_live": False,
        "snapshot_is_current": False,
        "selected_vacancy_status": (
            "fixture_only_not_selected_for_external_use"
        ),
        "operational_release": "withheld",
        "may_submit": False,
        "external_action_capability": False,
        "certifies_slice": False,
        "receipt_written": False,
        "real_applications": 0,
    })
    return LiveCanaryFixtureDryRun(**fields)  # type: ignore[arg-type]
