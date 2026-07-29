"""Deterministic loopback-only Playwright executor for JAA-09.

Materialised values exist only in caller memory and are never written to
workflow definitions, checkpoints or events. Final fixture submission consumes
one genuine JAA-08 token and records only content-addressed evidence.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Collection, Mapping
from urllib.parse import urljoin, urlsplit

from playwright.sync_api import Locator, Page, Route

from .application_compiler import (
    ApplicationSource,
    CandidateContact,
)
from .ats_fixture import FixtureReceipt
from .browser_workflows import (
    ActionKind,
    ApprovalRequiredError,
    ApprovedValue,
    BrowserAction,
    BrowserWorkflowStore,
    PendingAction,
    ReleaseGateError,
    SelectorCandidate,
    SelectorOutcome,
    SelectorRecoveryReport,
    SelectorStrategy,
    StepResult,
    SubmissionProof,
    ValueReference,
    WorkflowError,
    fixture_submit_event_sha256,
)
from .release_gate import ReleaseGateStore
from .rendering import ApplicationArtifacts


class LocalBrowserBoundaryError(RuntimeError):
    """An action attempted to leave the cooperative loopback fixture."""


class SelectorExecutionError(RuntimeError):
    """All declared selector candidates were exhausted without a match."""


class ConsequentialActionError(RuntimeError):
    """A browser action attempted an unapproved consequential boundary."""


class SubmissionIndeterminateError(RuntimeError):
    """A started submit has no recoverable receipt and cannot be repeated."""


@dataclass(frozen=True)
class MaterializedValue:
    reference: ValueReference
    authorization_reference: str
    value: str | Path = field(repr=False)
    expected_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reference, ValueReference):
            raise TypeError("materialized value requires a ValueReference")
        if (
            not isinstance(self.authorization_reference, str)
            or not self.authorization_reference.strip()
        ):
            raise ValueError(
                "materialized value requires an authorization reference"
            )
        if not isinstance(self.value, (str, Path)):
            raise TypeError("materialized value must be text or a file path")
        if (
            self.expected_sha256 is not None
            and not re.fullmatch(r"[0-9a-f]{64}", self.expected_sha256)
        ):
            raise ValueError(
                "materialized value hash must be lowercase SHA-256"
            )


@dataclass(frozen=True)
class ExecutedAction:
    run_id: str
    step_id: str
    action_kind: ActionKind
    selector_report: SelectorRecoveryReport | None
    checkpoint_created: bool


@dataclass(frozen=True)
class ReleaseExecutionAuthority:
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
    receipt_url: str
    application_id: str
    job_key: str

    def __post_init__(self) -> None:
        if not isinstance(self.gate, ReleaseGateStore):
            raise TypeError("release authority requires the JAA-08 gate")
        if (
            not self.release_token.startswith("jaa08.")
            or len(self.release_token.split(".")) != 3
        ):
            raise ValueError("release authority token format is invalid")
        if not _loopback_url(self.receipt_url):
            raise ValueError("release receipt URL must be loopback HTTP")
        if (
            urlsplit(self.receipt_url).path
            != f"/applications/{self.application_id}/receipt"
        ):
            raise ValueError(
                "release receipt URL differs from its application"
            )
        if self.source.job_key != self.job_key:
            raise ValueError("release authority job identity is inconsistent")
        if (
            not self.application_id
            or not self.jurisdiction
            or not self.contract_type
        ):
            raise ValueError("release execution authority is incomplete")
        if (
            self.consumed_at.tzinfo is None
            or self.consumed_at.utcoffset() is None
        ):
            raise ValueError("release consumption time must include a timezone")


def _loopback_url(value: str) -> bool:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return False
    if parsed.hostname.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        return False


def _origin(value: str) -> tuple[str, str, int] | None:
    if not _loopback_url(value):
        return None
    parsed = urlsplit(value)
    return (parsed.scheme, str(parsed.hostname).casefold(), parsed.port or 80)


class LocalBrowserExecutor:
    """Execute one leased non-submit workflow action on a Playwright page."""

    def __init__(
        self,
        store: BrowserWorkflowStore,
        *,
        repository_root: str | Path,
    ) -> None:
        self.store = store
        self.repository_root = Path(repository_root).resolve(strict=True)
        if not self.repository_root.is_dir():
            raise ValueError("repository root must be a directory")
        self._routed_pages: set[Page] = set()
        self._allowed_origins: dict[Page, tuple[str, str, int]] = {}

    def _secure_page(self, page: Page) -> None:
        if page not in self._routed_pages:
            def local_route(route: Route) -> None:
                allowed = self._allowed_origins.get(page)
                if allowed is not None and _origin(route.request.url) == allowed:
                    route.continue_()
                else:
                    route.abort("blockedbyclient")

            page.route("**/*", local_route)
            self._routed_pages.add(page)

    @staticmethod
    def _locator(
        page: Page,
        candidate: SelectorCandidate,
    ) -> Locator:
        strategy = candidate.strategy
        query = candidate.query
        if strategy is SelectorStrategy.LABEL:
            return page.get_by_label(query, exact=True)
        if strategy is SelectorStrategy.TEST_ID:
            return page.get_by_test_id(query)
        if strategy is SelectorStrategy.CSS:
            return page.locator(query)
        if strategy is SelectorStrategy.XPATH:
            return page.locator(f"xpath={query}")
        if strategy is SelectorStrategy.TEXT:
            return page.get_by_text(query, exact=True)
        if strategy is SelectorStrategy.ROLE:
            role, separator, name = query.partition(":")
            if not separator or not role.strip() or not name.strip():
                raise ValueError(
                    "role selector must use '<role>:<accessible name>'"
                )
            return page.get_by_role(
                role.strip(),  # type: ignore[arg-type]
                name=name.strip(),
                exact=True,
            )
        raise ValueError("selector strategy is unsupported")

    @classmethod
    def _resolve(
        cls,
        page: Page,
        action: BrowserAction,
    ) -> tuple[Locator, SelectorRecoveryReport]:
        if action.selectors is None:
            raise ValueError("selector action is missing its selector plan")
        outcomes: list[SelectorOutcome] = []
        for candidate in action.selectors.candidates:
            locator = cls._locator(page, candidate)
            count = locator.count()
            if count == 0:
                outcomes.append(SelectorOutcome.NOT_FOUND)
                continue
            if count != 1:
                outcomes.append(SelectorOutcome.AMBIGUOUS)
                continue
            if not locator.is_visible():
                outcomes.append(SelectorOutcome.NOT_VISIBLE)
                continue
            outcomes.append(SelectorOutcome.MATCHED)
            return locator, action.selectors.assess(tuple(outcomes))
        raise SelectorExecutionError(
            action.selectors.assess(tuple(outcomes)).to_dict()
        )

    @staticmethod
    def _approved_materialized(
        action: BrowserAction,
        approved_values: Collection[ApprovedValue],
        materialized_values: Mapping[str, MaterializedValue],
    ) -> MaterializedValue:
        reference = action.value_reference
        if reference is None:
            raise ValueError("value action is missing its reference")
        materialized = materialized_values.get(reference.key)
        if materialized is None or materialized.reference != reference:
            raise ApprovalRequiredError(
                f"step {action.step_id} has no exact materialized authority"
            )
        if not any(
            approval.reference == reference
            and approval.authorization_reference
            == materialized.authorization_reference
            for approval in approved_values
        ):
            raise ApprovalRequiredError(
                f"step {action.step_id} materialization lacks exact approval"
            )
        return materialized

    def _upload_path(self, materialized: MaterializedValue) -> tuple[Path, str]:
        path = Path(materialized.value)
        if path.is_symlink():
            raise ValueError("upload path cannot be a symlink")
        resolved = path.resolve(strict=True)
        if (
            not resolved.is_file()
            or resolved == self.repository_root
            or self.repository_root in resolved.parents
        ):
            raise ValueError(
                "browser uploads must be regular external artifact files"
            )
        content = resolved.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if (
            materialized.expected_sha256 != digest
            or not resolved.name.casefold().endswith(".pdf")
            or not content.startswith(b"%PDF-")
            or len(content) > 1024 * 1024
        ):
            raise ValueError(
                "browser upload differs from its approved bounded PDF"
            )
        return resolved, digest

    @staticmethod
    def _assert_release_materialization(
        action: BrowserAction,
        materialized: MaterializedValue,
        authority: ReleaseExecutionAuthority | None,
    ) -> None:
        if authority is None or action.value_reference is None:
            return
        expected_text = {
            "EV_FULL_NAME": authority.contact.full_name,
            "EV_EMAIL": authority.contact.email,
            "EV_PHONE": authority.contact.phone,
            "EV_CITY": authority.contact.city,
            "EV_WORK_AUTHORISATION": "authorised",
            "EV_COVER_NOTE": (
                authority.artifacts.editable.answers_text.strip()
            ),
        }
        reference_id = action.value_reference.reference_id
        if reference_id == "EV_CV":
            expected_hash = authority.artifacts.cv_pdf.pdf_sha256
        elif reference_id == "EV_COVER_LETTER":
            expected_hash = (
                authority.artifacts.cover_letter_pdf.pdf_sha256
            )
        else:
            expected_hash = None
        if expected_hash is not None:
            if materialized.expected_sha256 != expected_hash:
                raise ApprovalRequiredError(
                    "upload materialization differs from JAA-08 authority"
                )
            return
        expected = expected_text.get(reference_id)
        if expected is None or materialized.value != expected:
            raise ApprovalRequiredError(
                "field materialization differs from JAA-08 authority"
            )

    def _selector_failure(
        self,
        pending: PendingAction,
        worker_id: str,
        error: SelectorExecutionError,
    ) -> None:
        report_data = error.args[0]
        if not isinstance(report_data, dict):
            raise TypeError("selector failure report is malformed")
        action = pending.action
        if action.selectors is None:
            raise ValueError("selector failure lacks a selector plan")
        outcomes = tuple(
            SelectorOutcome(str(row["outcome"]))
            for row in report_data["attempts"]
        )
        report = action.selectors.assess(outcomes)
        self.store.record_selector_failure(
            pending.run_id,
            worker_id,
            step_id=action.step_id,
            report=report,
            idempotency_key=(
                f"executor-{pending.action_index}-"
                f"{action.selectors.content_hash}"
            ),
        )

    @staticmethod
    def _click_is_consequential(page: Page, locator: Locator) -> bool:
        if locator.get_attribute("data-testid") == "final-submit":
            return True
        targets = (
            locator.get_attribute("href"),
            locator.get_attribute("formaction"),
            locator.evaluate(
                "(element) => element.form ? element.form.action : ''"
            ),
        )
        for target in targets:
            if not isinstance(target, str) or not target:
                continue
            path = urlsplit(urljoin(page.url, target)).path.rstrip("/")
            if path.endswith("/submit"):
                return True
        return False

    @staticmethod
    def _field_map_sha256(page: Page) -> str:
        rows = page.locator("form [name]").evaluate_all(
            """(elements) => elements.map((element) => ({
                id: element.id || "",
                name: element.getAttribute("name") || "",
                tag: element.tagName.toLowerCase(),
                type: element.getAttribute("type") || "",
                required: Boolean(element.required),
                multiple: Boolean(element.multiple),
                labels: Array.from(element.labels || []).map(
                    (label) => (label.textContent || "").trim()
                )
            }))"""
        )
        document = json.dumps(
            rows,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(document.encode()).hexdigest()

    @staticmethod
    def _expected_fixture_payload_sha256(
        authority: ReleaseExecutionAuthority,
    ) -> str:
        document = {
            "contract": "jaa09.fixture-application.v1",
            "application_id": authority.application_id,
            "job_key": authority.job_key,
            "fields": {
                "full_name": authority.contact.full_name,
                "email": authority.contact.email,
                "phone": authority.contact.phone,
                "city": authority.contact.city,
                "work_authorisation": "authorised",
                "cover_note": (
                    authority.artifacts.editable.answers_text.strip()
                    .replace("\r\n", "\n")
                    .replace("\r", "\n")
                    .replace("\n", "\r\n")
                ),
            },
            "sponsorship_details": "",
            "uploads": {
                "cv": {
                    "filename": "cv.pdf",
                    "sha256": authority.artifacts.cv_pdf.pdf_sha256,
                    "size_bytes": len(
                        authority.artifacts.cv_pdf.pdf_bytes
                    ),
                },
                "cover_letter": {
                    "filename": "cover-letter.pdf",
                    "sha256": (
                        authority.artifacts.cover_letter_pdf.pdf_sha256
                    ),
                    "size_bytes": len(
                        authority.artifacts.cover_letter_pdf.pdf_bytes
                    ),
                },
            },
        }
        return hashlib.sha256(
            json.dumps(
                document,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()

    @staticmethod
    def _stored_selector_report(
        action: BrowserAction,
        dispatch: Mapping[str, object],
    ) -> SelectorRecoveryReport:
        if action.selectors is None:
            raise ValueError("submit action is missing its selector plan")
        try:
            document = json.loads(str(dispatch["selector_report_json"]))
            outcomes = tuple(
                SelectorOutcome(str(row["outcome"]))
                for row in document["attempts"]
            )
        except (
            KeyError,
            TypeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            raise ValueError(
                "durable submit selector report is invalid"
            ) from exc
        report = action.selectors.assess(outcomes)
        if report.to_dict() != document:
            raise ValueError(
                "durable submit selector report differs from its plan"
            )
        return report

    def _restore_prior_state(
        self,
        page: Page,
        pending: PendingAction,
        *,
        approved_values: Collection[ApprovedValue],
        materialized_values: Mapping[str, MaterializedValue],
        release_authority: ReleaseExecutionAuthority | None,
    ) -> None:
        dispatch = self.store.submit_dispatch(pending.run_id)
        if (
            dispatch is not None
            and str(dispatch["state"]) not in {
                "prepared",
                "release_consumed",
            }
        ):
            raise SubmissionIndeterminateError(
                "started submit browser state cannot be reconstructed safely"
            )
        prefix = self.store.replay_prefix(
            pending.run_id,
            before_action_index=pending.action_index,
        )
        if prefix[0][0].kind is not ActionKind.NAVIGATE:
            raise SubmissionIndeterminateError(
                "browser replay requires an initial navigation checkpoint"
            )
        for action, prior_result in prefix:
            if action.kind is ActionKind.NAVIGATE:
                if action.target_url is None or not _loopback_url(
                    action.target_url
                ):
                    raise LocalBrowserBoundaryError(
                        "replay navigation target is not loopback HTTP"
                    )
                target_origin = _origin(action.target_url)
                if target_origin is None:
                    raise LocalBrowserBoundaryError(
                        "replay navigation origin is invalid"
                    )
                self._allowed_origins[page] = target_origin
                response = page.goto(
                    action.target_url,
                    wait_until="domcontentloaded",
                )
                if (
                    response is None
                    or not response.ok
                    or _origin(page.url) != target_origin
                ):
                    raise LocalBrowserBoundaryError(
                        "replay navigation left or failed the local fixture"
                    )
                outputs: dict[str, object] = {
                    "navigation_status": response.status,
                    "url_sha256": hashlib.sha256(
                        page.url.encode()
                    ).hexdigest(),
                    "field_map_sha256": self._field_map_sha256(page),
                }
            else:
                if action.kind is ActionKind.SUBMIT:
                    raise ConsequentialActionError(
                        "a submit checkpoint can never be replayed"
                    )
                allowed_origin = self._allowed_origins.get(page)
                if (
                    allowed_origin is None
                    or _origin(page.url) != allowed_origin
                ):
                    raise LocalBrowserBoundaryError(
                        "browser replay left the local fixture"
                    )
                locator, report = self._resolve(page, action)
                if report != prior_result.selector_report:
                    raise SelectorExecutionError(
                        "replayed selector differs from its checkpoint"
                    )
                if action.kind is ActionKind.CLICK:
                    if self._click_is_consequential(page, locator):
                        raise ConsequentialActionError(
                            "browser replay reached a consequential control"
                        )
                    locator.click()
                    outputs = {"action_status": "clicked"}
                elif action.kind in {
                    ActionKind.FILL,
                    ActionKind.SELECT_OPTION,
                    ActionKind.UPLOAD,
                }:
                    materialized = self._approved_materialized(
                        action,
                        approved_values,
                        materialized_values,
                    )
                    self._assert_release_materialization(
                        action,
                        materialized,
                        release_authority,
                    )
                    if action.kind is ActionKind.FILL:
                        if not isinstance(materialized.value, str):
                            raise TypeError(
                                "fill materialization must be text"
                            )
                        locator.fill(materialized.value)
                        outputs = {"field_status": "filled"}
                    elif action.kind is ActionKind.SELECT_OPTION:
                        if not isinstance(materialized.value, str):
                            raise TypeError(
                                "select materialization must be text"
                            )
                        locator.select_option(materialized.value)
                        outputs = {"field_status": "selected"}
                    else:
                        upload, digest = self._upload_path(materialized)
                        locator.set_input_files(str(upload))
                        if (
                            hashlib.sha256(upload.read_bytes()).hexdigest()
                            != digest
                        ):
                            raise ValueError(
                                "browser upload changed during replay"
                            )
                        outputs = {
                            "field_status": "uploaded",
                            "upload_sha256": digest,
                        }
                    if release_authority is not None:
                        outputs["release_materialization_status"] = "verified"
                        outputs["release_manifest_sha256"] = (
                            release_authority.release_token.split(".")[1]
                        )
                elif action.kind is ActionKind.ASSERT:
                    outputs = {"assertion_status": "matched"}
                elif action.kind is ActionKind.EXTRACT:
                    outputs = {
                        "extracted_text_sha256": hashlib.sha256(
                            locator.inner_text().encode()
                        ).hexdigest()
                    }
                else:
                    raise ConsequentialActionError(
                        f"{action.kind.value} cannot be replayed"
                    )
                if _origin(page.url) != allowed_origin:
                    raise LocalBrowserBoundaryError(
                        "browser replay left the local fixture"
                    )
            if outputs != dict(prior_result.outputs):
                raise WorkflowError(
                    f"replayed step {action.step_id} differs from checkpoint"
                )

    def _execute_submit(
        self,
        page: Page,
        pending: PendingAction,
        worker_id: str,
        authority: ReleaseExecutionAuthority,
    ) -> ExecutedAction:
        action = pending.action
        if self.store.path.resolve() != authority.gate.path.resolve():
            raise ReleaseGateError(
                "browser and JAA-08 authority must share one database"
            )
        if (
            authority.repository_root.resolve(strict=True)
            != self.repository_root
        ):
            raise ReleaseGateError(
                "browser and JAA-08 repository authority differ"
            )
        release_manifest_sha256 = authority.release_token.split(".")[1]
        for step_id in (
            "full_name",
            "email",
            "phone",
            "city",
            "work_authorisation",
            "cover_note",
            "cv",
            "cover_letter",
        ):
            outputs = pending.prior_outputs.get(step_id, {})
            if (
                outputs.get("release_materialization_status")
                != "verified"
                or outputs.get("release_manifest_sha256")
                != release_manifest_sha256
            ):
                raise ApprovalRequiredError(
                    "submit lacks exact JAA-08 field materialization"
                )
        dispatch = self.store.submit_dispatch(pending.run_id)
        locator: Locator | None = None
        if dispatch is None:
            allowed_origin = self._allowed_origins.get(page)
            if (
                allowed_origin is None
                or _origin(page.url) != allowed_origin
                or _origin(authority.receipt_url) != allowed_origin
            ):
                raise LocalBrowserBoundaryError(
                    "submit page is outside its approved local fixture"
                )
            locator, report = self._resolve(page, action)
            if not self._click_is_consequential(page, locator):
                raise ConsequentialActionError(
                    "SUBMIT action does not target the final-submit boundary"
                )
            field_map_sha256 = next(
                (
                    str(outputs["field_map_sha256"])
                    for outputs in pending.prior_outputs.values()
                    if "field_map_sha256" in outputs
                ),
                "",
            )
            if not field_map_sha256:
                raise WorkflowError(
                    "submit requires a prior field-map checkpoint"
                )
            self.store.prepare_submit_dispatch(
                pending.run_id,
                worker_id,
                step_id=action.step_id,
                release_token=authority.release_token,
                field_map_sha256=field_map_sha256,
                selector_report=report,
            )
            dispatch = self.store.submit_dispatch(pending.run_id)
        if dispatch is None:
            raise WorkflowError("submit dispatch was not persisted")
        report = self._stored_selector_report(action, dispatch)
        state = str(dispatch["state"])
        release_arguments = {
            "release_token": authority.release_token,
            "source": authority.source,
            "artifacts": authority.artifacts,
            "contact": authority.contact,
            "questions": authority.questions,
            "artifact_root": authority.artifact_root,
            "repository_root": authority.repository_root,
            "jurisdiction": authority.jurisdiction,
            "contract_type": authority.contract_type,
        }
        if state in {"prepared", "release_consumed"} and locator is None:
            allowed_origin = self._allowed_origins.get(page)
            if (
                allowed_origin is None
                or _origin(page.url) != allowed_origin
            ):
                raise SubmissionIndeterminateError(
                    "pre-click browser state cannot be reconstructed safely"
                )
            locator, current_report = self._resolve(page, action)
            if current_report != report:
                raise SelectorExecutionError(
                    "submit selector changed after dispatch preparation"
                )
            if not self._click_is_consequential(page, locator):
                raise ConsequentialActionError(
                    "prepared SUBMIT no longer targets final submit"
                )
        returned_consumed_at: str | None = None
        if state == "prepared":
            try:
                consumed = authority.gate.consume_release_token(
                    **release_arguments,
                    consumed_at=authority.consumed_at,
                )
                returned_consumed_at = consumed.consumed_at
            except ValueError as error:
                if str(error) != "release token was already consumed":
                    raise
            self.store.reconcile_release_consumed(
                pending.run_id,
                worker_id,
                release_token=authority.release_token,
            )
            dispatch = self.store.submit_dispatch(pending.run_id)
            if dispatch is None:
                raise WorkflowError(
                    "consumed release dispatch was not persisted"
                )
            state = str(dispatch["state"])
            if (
                returned_consumed_at is not None
                and dispatch["release_consumed_at"] != returned_consumed_at
            ):
                raise ReleaseGateError(
                    "durable release consumption differs from JAA-08 return"
                )
        fresh_click = False
        if state == "release_consumed":
            durable_consumed_at = datetime.fromisoformat(
                str(dispatch["release_consumed_at"])
            )
            if (
                durable_consumed_at.tzinfo is None
                or durable_consumed_at.utcoffset() is None
            ):
                raise ReleaseGateError(
                    "durable release consumption time lacks a timezone"
                )
            authority.gate.verify_consumed_release_token(
                **release_arguments,
                consumed_at=durable_consumed_at,
            )
            fresh_click = self.store.mark_submit_started(
                pending.run_id,
                worker_id,
                release_token=authority.release_token,
            )
            state = "click_started"
        if state != "click_started":
            raise WorkflowError("submit dispatch state cannot produce a receipt")
        if fresh_click:
            if locator is None:
                raise SubmissionIndeterminateError(
                    "submit click target is no longer available"
                )
            locator.click()
            if _origin(page.url) != _origin(authority.receipt_url):
                raise LocalBrowserBoundaryError(
                    "submit action left the local fixture"
                )
        else:
            receipt_origin = _origin(authority.receipt_url)
            if receipt_origin is None:
                raise LocalBrowserBoundaryError(
                    "fixture receipt origin is invalid"
                )
            self._allowed_origins[page] = receipt_origin
            response = page.goto(
                authority.receipt_url,
                wait_until="domcontentloaded",
            )
            if response is None or response.status != 200:
                raise SubmissionIndeterminateError(
                    "started submit has no recoverable official receipt"
                )
        receipt_id = page.get_by_test_id("receipt-id").inner_text().strip()
        payload_sha256 = page.get_by_test_id(
            "payload-hash"
        ).inner_text().strip()
        receipt = FixtureReceipt(
            receipt_id=receipt_id,
            application_id=authority.application_id,
            job_key=authority.job_key,
            payload_sha256=payload_sha256,
        )
        receipt.verify()
        if (
            receipt.payload_sha256
            != self._expected_fixture_payload_sha256(authority)
        ):
            raise ValueError(
                "fixture receipt payload differs from exact JAA-08 authority"
            )
        screenshot_sha256 = hashlib.sha256(
            page.screenshot(full_page=True)
        ).hexdigest()
        field_map_sha256 = str(dispatch["field_map_hash"])
        release_manifest_sha256 = str(dispatch["release_manifest_hash"])
        token_sha256 = str(dispatch["release_token_hash"])
        submit_event_sha256 = fixture_submit_event_sha256(
            run_id=pending.run_id,
            workflow_sha256=pending.workflow_hash,
            step_id=action.step_id,
            release_manifest_sha256=release_manifest_sha256,
            receipt_id=receipt_id,
            receipt_payload_sha256=payload_sha256,
            screenshot_sha256=screenshot_sha256,
            field_map_sha256=field_map_sha256,
        )
        proof = SubmissionProof(
            release_manifest_sha256=release_manifest_sha256,
            token_sha256=token_sha256,
            receipt_id=receipt_id,
            receipt_payload_sha256=payload_sha256,
            screenshot_sha256=screenshot_sha256,
            field_map_sha256=field_map_sha256,
            submit_event_sha256=submit_event_sha256,
        )
        outputs = {
            "receipt_id": receipt_id,
            "receipt_payload_sha256": payload_sha256,
            "screenshot_sha256": screenshot_sha256,
            "field_map_sha256": field_map_sha256,
            "submit_event_sha256": submit_event_sha256,
        }
        created = self.store.complete_step(
            pending.run_id,
            worker_id,
            step_id=action.step_id,
            result=StepResult(outputs, report),
            release_gate_token=authority.release_token,
            submission_proof=proof,
        )
        return ExecutedAction(
            pending.run_id,
            action.step_id,
            action.kind,
            report,
            created,
        )

    def execute_next(
        self,
        page: Page,
        *,
        run_id: str,
        worker_id: str,
        approved_values: Collection[ApprovedValue] = (),
        materialized_values: Mapping[str, MaterializedValue] | None = None,
        release_authority: ReleaseExecutionAuthority | None = None,
    ) -> ExecutedAction | None:
        """Execute and checkpoint only the first missing non-submit action."""
        self._secure_page(page)
        values = materialized_values or {}
        pending = self.store.next_action(
            run_id,
            worker_id,
            approved_values=approved_values,
            release_gate_token=(
                release_authority.release_token
                if release_authority is not None
                else None
            ),
        )
        if pending is None:
            return None
        action = pending.action
        dispatch = self.store.submit_dispatch(run_id)
        if (
            action.kind is not ActionKind.NAVIGATE
            and (
                self._allowed_origins.get(page) is None
                or _origin(page.url) != self._allowed_origins.get(page)
            )
            and (
                dispatch is None
                or str(dispatch["state"])
                in {"prepared", "release_consumed"}
            )
        ):
            self._restore_prior_state(
                page,
                pending,
                approved_values=approved_values,
                materialized_values=values,
                release_authority=release_authority,
            )
        if action.kind is ActionKind.SUBMIT:
            if release_authority is None:
                raise ConsequentialActionError(
                    "submit requires exact JAA-08 execution authority"
                )
            return self._execute_submit(
                page,
                pending,
                worker_id,
                release_authority,
            )
        if action.kind is ActionKind.NAVIGATE:
            if action.target_url is None or not _loopback_url(
                action.target_url
            ):
                raise LocalBrowserBoundaryError(
                    "browser navigation target is not loopback HTTP"
                )
            target_origin = _origin(action.target_url)
            if target_origin is None:
                raise LocalBrowserBoundaryError(
                    "browser navigation origin is invalid"
                )
            self._allowed_origins[page] = target_origin
            response = page.goto(
                action.target_url,
                wait_until="domcontentloaded",
            )
            if (
                response is None
                or not response.ok
                or _origin(page.url) != target_origin
            ):
                raise LocalBrowserBoundaryError(
                    "browser navigation left or failed the local fixture"
                )
            created = self.store.complete_step(
                run_id,
                worker_id,
                step_id=action.step_id,
                result=StepResult(
                    {
                        "navigation_status": response.status,
                        "url_sha256": hashlib.sha256(
                            page.url.encode()
                        ).hexdigest(),
                        "field_map_sha256": self._field_map_sha256(page),
                    }
                ),
            )
            return ExecutedAction(
                run_id,
                action.step_id,
                action.kind,
                None,
                created,
            )
        allowed_origin = self._allowed_origins.get(page)
        if allowed_origin is None or _origin(page.url) != allowed_origin:
            raise LocalBrowserBoundaryError(
                "browser page is outside the local fixture"
            )
        try:
            locator, report = self._resolve(page, action)
        except SelectorExecutionError as error:
            self._selector_failure(pending, worker_id, error)
            raise
        outputs: dict[str, object]
        if action.kind is ActionKind.CLICK:
            if self._click_is_consequential(page, locator):
                raise ConsequentialActionError(
                    "final-submit controls require a SUBMIT action"
                )
            locator.click()
            outputs = {"action_status": "clicked"}
        elif action.kind is ActionKind.FILL:
            materialized = self._approved_materialized(
                action,
                approved_values,
                values,
            )
            self._assert_release_materialization(
                action,
                materialized,
                release_authority,
            )
            if not isinstance(materialized.value, str):
                raise TypeError("fill materialization must be text")
            locator.fill(materialized.value)
            outputs = {"field_status": "filled"}
        elif action.kind is ActionKind.SELECT_OPTION:
            materialized = self._approved_materialized(
                action,
                approved_values,
                values,
            )
            self._assert_release_materialization(
                action,
                materialized,
                release_authority,
            )
            if not isinstance(materialized.value, str):
                raise TypeError("select materialization must be text")
            locator.select_option(materialized.value)
            outputs = {"field_status": "selected"}
        elif action.kind is ActionKind.UPLOAD:
            materialized = self._approved_materialized(
                action,
                approved_values,
                values,
            )
            self._assert_release_materialization(
                action,
                materialized,
                release_authority,
            )
            upload, digest = self._upload_path(materialized)
            locator.set_input_files(str(upload))
            if hashlib.sha256(upload.read_bytes()).hexdigest() != digest:
                raise ValueError("browser upload changed during materialization")
            outputs = {
                "field_status": "uploaded",
                "upload_sha256": digest,
            }
        elif action.kind is ActionKind.ASSERT:
            outputs = {"assertion_status": "matched"}
        elif action.kind is ActionKind.EXTRACT:
            outputs = {"extracted_text_sha256": hashlib.sha256(
                locator.inner_text().encode()
            ).hexdigest()}
        else:
            raise ConsequentialActionError(
                f"{action.kind.value} is not enabled in this executor increment"
            )
        if (
            action.kind
            in {
                ActionKind.FILL,
                ActionKind.SELECT_OPTION,
                ActionKind.UPLOAD,
            }
            and release_authority is not None
        ):
            outputs["release_materialization_status"] = "verified"
            outputs["release_manifest_sha256"] = (
                release_authority.release_token.split(".")[1]
            )
        if _origin(page.url) != allowed_origin:
            raise LocalBrowserBoundaryError(
                "browser action left the local fixture"
            )
        for key in action.required_output_keys:
            if key not in outputs:
                raise ValueError(
                    f"executor cannot produce required output {key}"
                )
        created = self.store.complete_step(
            run_id,
            worker_id,
            step_id=action.step_id,
            result=StepResult(outputs, report),
            approved_values=approved_values,
        )
        return ExecutedAction(
            run_id,
            action.step_id,
            action.kind,
            report,
            created,
        )
