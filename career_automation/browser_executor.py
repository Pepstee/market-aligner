"""Deterministic loopback-only Playwright executor for JAA-09.

This first executor increment performs non-submit actions against the
cooperative local fixture. Materialised values exist only in caller memory and
are never written to workflow definitions, checkpoints or events.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Collection, Mapping
from urllib.parse import urljoin, urlsplit

from playwright.sync_api import Locator, Page, Route

from .browser_workflows import (
    ActionKind,
    ApprovalRequiredError,
    ApprovedValue,
    BrowserAction,
    BrowserWorkflowStore,
    PendingAction,
    SelectorCandidate,
    SelectorOutcome,
    SelectorRecoveryReport,
    SelectorStrategy,
    StepResult,
    ValueReference,
)


class LocalBrowserBoundaryError(RuntimeError):
    """An action attempted to leave the cooperative loopback fixture."""


class SelectorExecutionError(RuntimeError):
    """All declared selector candidates were exhausted without a match."""


class ConsequentialActionError(RuntimeError):
    """A submit action reached an executor increment that cannot dispatch it."""


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

    def execute_next(
        self,
        page: Page,
        *,
        run_id: str,
        worker_id: str,
        approved_values: Collection[ApprovedValue] = (),
        materialized_values: Mapping[str, MaterializedValue] | None = None,
    ) -> ExecutedAction | None:
        """Execute and checkpoint only the first missing non-submit action."""
        self._secure_page(page)
        values = materialized_values or {}
        pending = self.store.next_action(
            run_id,
            worker_id,
            approved_values=approved_values,
        )
        if pending is None:
            return None
        action = pending.action
        if action.kind is ActionKind.SUBMIT:
            raise ConsequentialActionError(
                "submit requires the isolated JAA-08 token package"
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
