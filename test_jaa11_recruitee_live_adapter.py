from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from career_automation.recruitee_live_adapter import (
    APPLICATION_URL,
    EXPECTED_FORM_INVENTORY,
    JAA08ReleaseAuthority,
    InventoryEntry,
    RecruiteeApplication,
    RecruiteeBoundaryError,
    RecruiteeCircuitError,
    RecruiteeLiveAdapter,
    RecruiteeOneUseCircuit,
    RecruiteeSchemaError,
    RecruiteeSubmissionIndeterminateError,
)


class FakeGate:
    def __init__(self, manifest: str, token_hash: str) -> None:
        self.manifest = manifest
        self.token_hash = token_hash
        self.calls: list[dict[str, object]] = []
        self.fail = False

    def consume_release_token(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        if self.fail:
            raise ValueError("synthetic gate refusal")
        return SimpleNamespace(
            release_manifest_sha256=self.manifest,
            token_sha256=self.token_hash,
            consumed_at=kwargs["consumed_at"].isoformat(),
        )


class FakeLocator:
    def __init__(
        self,
        page: FakePage,
        *,
        kind: str,
        selector: str = "",
        name: str = "",
        value: str | None = None,
        marker: str = "",
    ) -> None:
        self.page = page
        self.kind = kind
        self.selector = selector
        self.name = name
        self.value = value
        self.marker = marker

    def evaluate_all(self, _script: str) -> list[dict[str, object]]:
        assert self.kind == "inventory"
        return [entry.document() for entry in self.page.inventory]

    def count(self) -> int:
        if self.kind == "forbidden":
            return 1 if self.selector in self.page.forbidden_selectors else 0
        if self.kind == "body":
            return 1
        if self.kind == "submit":
            return 1 if self.page.submit_present else 0
        if self.kind == "success":
            return int(self.page.submitted and self.page.receipt_present)
        if self.kind == "control":
            return int((self.name, self.value) in self.page.controls)
        raise AssertionError(f"unknown locator kind {self.kind}")

    def inner_text(self) -> str:
        assert self.kind == "body"
        return self.page.body_text

    def fill(self, value: str) -> None:
        assert self.kind == "control"
        self.page.controls[(self.name, self.value)]["input_value"] = value

    def input_value(self) -> str:
        assert self.kind == "control"
        return str(self.page.controls[(self.name, self.value)]["input_value"])

    def check(self) -> None:
        assert self.kind == "control"
        self.page.controls[(self.name, self.value)]["checked"] = True

    def is_checked(self) -> bool:
        assert self.kind == "control"
        return bool(self.page.controls[(self.name, self.value)]["checked"])

    def set_input_files(self, path: str) -> None:
        assert self.kind == "control"
        assert Path(path).is_file()
        self.page.controls[(self.name, self.value)]["file_count"] = 1

    def evaluate(self, _script: str) -> int:
        assert self.kind == "control"
        return int(self.page.controls[(self.name, self.value)]["file_count"])

    def click(self) -> None:
        assert self.kind == "submit"
        self.page.clicks += 1
        self.page.submitted = True

    def is_visible(self) -> bool:
        return self.count() == 1


class FakePage:
    def __init__(self) -> None:
        self.url = APPLICATION_URL
        self.inventory = list(deepcopy(EXPECTED_FORM_INVENTORY))
        self.body_text = "Decoded application form"
        self.forbidden_selectors: set[str] = set()
        self.submit_present = True
        self.receipt_present = True
        self.submitted = False
        self.clicks = 0
        self.html = "<html><body>official-application-dom</body></html>"
        self.controls: dict[tuple[str, str | None], dict[str, object]] = {}
        for entry in self.inventory:
            if entry.field_type == "radio":
                key = (entry.name, entry.option_value)
            else:
                key = (entry.name, None)
            self.controls[key] = {
                "input_value": "",
                "checked": False,
                "file_count": 0,
            }

    def locator(self, selector: str) -> FakeLocator:
        if selector == "input:not([type=hidden]),textarea,select":
            return FakeLocator(self, kind="inventory")
        if selector == "body":
            return FakeLocator(self, kind="body")
        if selector.startswith("[name="):
            match = re.fullmatch(
                r'\[name="([^"]+)"\](?:\[value="([^"]+)"\])?',
                selector,
            )
            assert match is not None
            return FakeLocator(
                self,
                kind="control",
                name=match.group(1),
                value=match.group(2),
            )
        return FakeLocator(self, kind="forbidden", selector=selector)

    def get_by_role(self, role: str, *, name: str, exact: bool) -> FakeLocator:
        assert (role, name, exact) == ("button", "Send", True)
        return FakeLocator(self, kind="submit")

    def get_by_text(self, marker: str, *, exact: bool) -> FakeLocator:
        assert exact is True
        return FakeLocator(self, kind="success", marker=marker)

    def content(self) -> str:
        # A real success DOM may still contain form values.  The adapter hashes
        # these bytes and never persists them.
        return self.html

    def screenshot(self, *, full_page: bool) -> bytes:
        assert full_page is True
        return b"official-success-screenshot"

    def title(self) -> str:
        return "Application received | Decoded Limited"


def _application(tmp_path: Path) -> RecruiteeApplication:
    cv = tmp_path / "canary-cv.pdf"
    cv.write_bytes(b"%PDF-1.4\nsynthetic deterministic CV\n")
    return RecruiteeApplication(
        full_name="Canary Person",
        email="canary@example.test",
        phone="+44 7000 000000",
        linkedin="https://www.linkedin.com/in/canary-person/",
        location="Birmingham, United Kingdom",
        work_rights="Yes, unrestricted UK work rights.",
        travel="Yes.",
        public_speaking=True,
        facilitation_window=True,
        technology_interest="Python and applied AI systems.",
        languages="Romanian and Russian.",
        cv_path=cv,
        cv_sha256=hashlib.sha256(cv.read_bytes()).hexdigest(),
    )


def _authority() -> tuple[JAA08ReleaseAuthority, FakeGate]:
    manifest = hashlib.sha256(b"manifest").hexdigest()
    token = f"jaa08.{manifest}.synthetic-secret"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    gate = FakeGate(manifest, token_hash)
    authority = JAA08ReleaseAuthority(
        gate=gate,  # type: ignore[arg-type]
        release_token=token,
        source=object(),  # type: ignore[arg-type]
        artifacts=object(),  # type: ignore[arg-type]
        contact=object(),  # type: ignore[arg-type]
        questions=None,
        artifact_root=Path("/synthetic/artifacts"),
        repository_root=Path("/synthetic/repository"),
        jurisdiction="GB",
        contract_type="contractor",
        consumed_at=datetime(2026, 8, 4, 0, 30, tzinfo=timezone.utc),
    )
    return authority, gate


def test_exact_form_consumes_once_clicks_once_and_writes_hash_only_receipt(
    tmp_path: Path,
) -> None:
    database = tmp_path / "circuit.sqlite3"
    circuit = RecruiteeOneUseCircuit(database)
    adapter = RecruiteeLiveAdapter(circuit)
    page = FakePage()
    application = _application(tmp_path)
    authority, gate = _authority()

    receipt = adapter.submit(
        page,
        application=application,
        authority=authority,
    )

    assert page.clicks == 1
    assert len(gate.calls) == 1
    assert circuit.snapshot()["state"] == "succeeded"
    assert circuit.receipt() == receipt
    assert (
        hashlib.sha256(
            json.dumps(
                receipt.document,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
        == receipt.receipt_sha256
    )
    receipt_text = json.dumps(receipt.document)
    database_bytes = database.read_bytes()
    for secret in (
        application.full_name,
        application.email,
        application.phone,
        application.linkedin,
        application.location,
        application.technology_interest,
        authority.release_token,
    ):
        assert secret not in receipt_text
        assert secret.encode() not in database_bytes


def test_schema_drift_blocks_before_release_or_click(tmp_path: Path) -> None:
    circuit = RecruiteeOneUseCircuit(tmp_path / "circuit.sqlite3")
    page = FakePage()
    page.inventory.append(
        InventoryEntry(
            "text",
            "candidate.openQuestionAnswers.9999999.content",
            True,
            "Unreviewed required question *",
        )
    )
    authority, gate = _authority()

    with pytest.raises(RecruiteeSchemaError, match="inventory"):
        RecruiteeLiveAdapter(circuit).submit(
            page,
            application=_application(tmp_path),
            authority=authority,
        )

    assert gate.calls == []
    assert page.clicks == 0
    assert circuit.snapshot()["state"] == "blocked"


def test_hidden_captcha_configuration_parks_review_without_release_or_click(
    tmp_path: Path,
) -> None:
    circuit = RecruiteeOneUseCircuit(tmp_path / "circuit.sqlite3")
    adapter = RecruiteeLiveAdapter(circuit)
    page = FakePage()
    page.html = (
        '<html><script>window.config={"captcha":{'
        '"siteKey":"synthetic"},"hcaptcha":true};</script>'
        '<div id="input-captchaToken-undefined"></div></html>'
    )
    application = _application(tmp_path)
    authority, gate = _authority()

    review = adapter.prepare_review(page, application=application)
    assert review.eligible_for_submit is False
    assert review.reason_codes == ("captcha_configuration_present",)
    assert page.clicks == 0
    assert gate.calls == []
    assert circuit.snapshot()["state"] == "ready"
    assert all(
        control["input_value"] == ""
        and control["file_count"] == 0
        and control["checked"] is False
        for control in page.controls.values()
    )

    with pytest.raises(RecruiteeSchemaError, match="parked"):
        adapter.submit(page, application=application, authority=authority)
    assert page.clicks == 0
    assert gate.calls == []
    assert circuit.snapshot()["state"] == "blocked"


@pytest.mark.parametrize(
    "selector",
    (
        'input[type="password"]',
        'input[autocomplete="one-time-code"]',
        'iframe[src*="captcha" i]',
        "[data-sitekey]",
        'input[type="checkbox"][required]',
        'input[name*="payment" i]',
    ),
)
def test_login_mfa_captcha_payment_and_attestation_fail_closed(
    tmp_path: Path,
    selector: str,
) -> None:
    circuit = RecruiteeOneUseCircuit(tmp_path / "circuit.sqlite3")
    page = FakePage()
    page.forbidden_selectors.add(selector)
    authority, gate = _authority()

    with pytest.raises(RecruiteeSchemaError, match="prohibited"):
        RecruiteeLiveAdapter(circuit).submit(
            page,
            application=_application(tmp_path),
            authority=authority,
        )

    assert gate.calls == []
    assert page.clicks == 0


def test_missing_receipt_leaves_indeterminate_and_forbids_retry(
    tmp_path: Path,
) -> None:
    circuit = RecruiteeOneUseCircuit(tmp_path / "circuit.sqlite3")
    adapter = RecruiteeLiveAdapter(circuit)
    page = FakePage()
    page.receipt_present = False
    application = _application(tmp_path)
    authority, gate = _authority()

    with pytest.raises(
        RecruiteeSubmissionIndeterminateError,
        match="receipt",
    ):
        adapter.submit(page, application=application, authority=authority)

    assert page.clicks == 1
    assert len(gate.calls) == 1
    assert circuit.snapshot()["state"] == "click_started"
    assert circuit.receipt() is None

    with pytest.raises(RecruiteeCircuitError, match="one-use"):
        adapter.submit(page, application=application, authority=authority)
    assert page.clicks == 1
    assert len(gate.calls) == 1


def test_successful_circuit_forbids_second_submit(tmp_path: Path) -> None:
    circuit = RecruiteeOneUseCircuit(tmp_path / "circuit.sqlite3")
    adapter = RecruiteeLiveAdapter(circuit)
    page = FakePage()
    application = _application(tmp_path)
    authority, gate = _authority()

    adapter.submit(page, application=application, authority=authority)
    with pytest.raises(RecruiteeCircuitError, match="one-use"):
        adapter.submit(page, application=application, authority=authority)

    assert page.clicks == 1
    assert len(gate.calls) == 1


def test_wrong_https_host_or_path_is_rejected(tmp_path: Path) -> None:
    circuit = RecruiteeOneUseCircuit(tmp_path / "circuit.sqlite3")
    page = FakePage()
    page.url = "https://decoded.recruitee.com/o/another-role/c/new"
    authority, gate = _authority()

    with pytest.raises(RecruiteeBoundaryError, match="exact"):
        RecruiteeLiveAdapter(circuit).submit(
            page,
            application=_application(tmp_path),
            authority=authority,
        )

    assert gate.calls == []
    assert page.clicks == 0


def test_gate_failure_cannot_reach_click_or_retry(tmp_path: Path) -> None:
    circuit = RecruiteeOneUseCircuit(tmp_path / "circuit.sqlite3")
    adapter = RecruiteeLiveAdapter(circuit)
    page = FakePage()
    application = _application(tmp_path)
    authority, gate = _authority()
    gate.fail = True

    with pytest.raises(
        RecruiteeSubmissionIndeterminateError,
        match="consumption",
    ):
        adapter.submit(page, application=application, authority=authority)

    assert len(gate.calls) == 1
    assert page.clicks == 0
    assert circuit.snapshot()["state"] == "blocked"
    with pytest.raises(RecruiteeCircuitError):
        adapter.submit(page, application=application, authority=authority)


def test_receipt_row_is_canonical_and_content_addressed(tmp_path: Path) -> None:
    database = tmp_path / "circuit.sqlite3"
    circuit = RecruiteeOneUseCircuit(database)
    page = FakePage()
    authority, _gate = _authority()
    receipt = RecruiteeLiveAdapter(circuit).submit(
        page,
        application=_application(tmp_path),
        authority=authority,
    )

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT receipt_sha256,document_json FROM recruitee_receipt"
        ).fetchone()
    assert row is not None
    assert row[0] == receipt.receipt_sha256
    assert json.loads(row[1]) == dict(receipt.document)
