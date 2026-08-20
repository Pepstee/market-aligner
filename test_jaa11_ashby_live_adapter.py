from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy
from datetime import date, datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from career_automation.ashby_live_adapter import (
    APPLICATION_URL,
    ROLE_TITLE,
    SUBMIT_LABEL,
    SUCCESS_MARKER,
    AshbyApplication,
    AshbyBoundaryError,
    AshbyCircuitError,
    AshbyLiveAdapter,
    AshbyOneUseCircuit,
    AshbySchemaError,
    AshbySubmissionIndeterminateError,
    CompensationBinding,
    EXPECTED_FORM_INVENTORY,
    InventoryEntry,
    JAA08ReleaseAuthority,
)


class FakeGate:
    def __init__(self, manifest: str, token_hash: str) -> None:
        self.manifest = manifest
        self.token_hash = token_hash
        self.calls: list[dict[str, object]] = []
        self.fail = False
        self.mismatch = False

    def consume_release_token(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        if self.fail:
            raise ValueError("synthetic gate refusal")
        return SimpleNamespace(
            release_manifest_sha256=(
                hashlib.sha256(b"different").hexdigest()
                if self.mismatch
                else self.manifest
            ),
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
        marker: str = "",
        role_name: str = "",
    ) -> None:
        self.page = page
        self.kind = kind
        self.selector = selector
        self.marker = marker
        self.role_name = role_name

    def evaluate_all(self, _script: str) -> list[dict[str, object]]:
        assert self.kind == "inventory"
        return [entry.document() for entry in self.page.inventory]

    def count(self) -> int:
        if self.kind == "forbidden":
            return int(self.selector in self.page.forbidden_selectors)
        if self.kind == "body":
            return 1
        if self.kind == "control":
            return int(self.selector in self.page.controls)
        if self.kind == "work_right_field":
            return 1
        if self.kind == "work_right_button":
            return int(self.role_name in {"Yes", "No"})
        if self.kind == "submit":
            if not self.page.submit_present:
                return 0
            if self.page.submitted and not self.page.submit_remains_after_success:
                return 0
            return 1
        if self.kind == "success":
            return int(
                self.marker == SUCCESS_MARKER
                and self.page.submitted
                and self.page.receipt_present
            )
        raise AssertionError(f"unknown locator kind {self.kind}")

    def inner_text(self) -> str:
        assert self.kind == "body"
        return self.page.body_text

    def fill(self, value: str) -> None:
        assert self.kind == "control"
        self.page.controls[self.selector]["input_value"] = value

    def input_value(self) -> str:
        assert self.kind == "control"
        return str(self.page.controls[self.selector]["input_value"])

    def set_input_files(self, path: str) -> None:
        assert self.kind == "control"
        assert Path(path).is_file()
        self.page.controls[self.selector]["file_count"] = 1

    def evaluate(self, _script: str) -> int:
        assert self.kind == "control"
        return int(self.page.controls[self.selector]["file_count"])

    def is_checked(self) -> bool:
        assert self.kind == "control"
        return bool(self.page.controls[self.selector]["checked"])

    def get_by_role(self, role: str, *, name: str, exact: bool) -> FakeLocator:
        assert self.kind == "work_right_field"
        assert role == "button" and exact is True
        return FakeLocator(
            self.page,
            kind="work_right_button",
            role_name=name,
        )

    def click(self) -> None:
        if self.kind == "work_right_button":
            self.page.work_right_clicks.append(self.role_name)
            self.page.controls[
                '[name="8ff73809-7ebc-4964-9ed0-aa50b9b0073d"]'
            ]["checked"] = self.role_name == "Yes"
            return
        assert self.kind == "submit"
        self.page.clicks += 1
        self.page.submitted = True

    def is_visible(self) -> bool:
        return self.count() == 1


class FakePage:
    def __init__(self) -> None:
        self.url = APPLICATION_URL
        self.page_title = ROLE_TITLE
        self.inventory = list(deepcopy(EXPECTED_FORM_INVENTORY))
        self.body_text = "Vega Product Operations Intern application"
        self.forbidden_selectors: set[str] = set()
        self.html = "<html><body>official Vega application DOM</body></html>"
        self.submit_present = True
        self.submit_remains_after_success = False
        self.receipt_present = True
        self.submitted = False
        self.clicks = 0
        self.work_right_clicks: list[str] = []
        self.controls: dict[str, dict[str, object]] = {
            '[id="_systemfield_name"]': self._empty(),
            '[id="_systemfield_email"]': self._empty(),
            '[id="bb738f7d-543d-45f8-9119-29bc615bf9cf"]': self._empty(),
            '[id="_systemfield_resume"]': self._empty(),
            '[id="249396a8-8fdc-4a7d-be1b-3c20aae99bf4"]': self._empty(),
            '[name="8ff73809-7ebc-4964-9ed0-aa50b9b0073d"]': (
                self._empty()
            ),
        }

    @staticmethod
    def _empty() -> dict[str, object]:
        return {"input_value": "", "file_count": 0, "checked": False}

    def locator(self, selector: str) -> FakeLocator:
        if selector == ".ashby-application-form-field-entry":
            return FakeLocator(self, kind="inventory")
        if selector == "body":
            return FakeLocator(self, kind="body")
        if selector == (
            '[data-field-path="8ff73809-7ebc-4964-9ed0-aa50b9b0073d"]'
        ):
            return FakeLocator(self, kind="work_right_field")
        if selector in self.controls:
            return FakeLocator(self, kind="control", selector=selector)
        return FakeLocator(self, kind="forbidden", selector=selector)

    def get_by_role(self, role: str, *, name: str, exact: bool) -> FakeLocator:
        assert (role, name, exact) == ("button", SUBMIT_LABEL, True)
        return FakeLocator(self, kind="submit")

    def get_by_text(self, marker: str, *, exact: bool) -> FakeLocator:
        assert exact is True
        return FakeLocator(self, kind="success", marker=marker)

    def content(self) -> str:
        return self.html

    def screenshot(self, *, full_page: bool) -> bytes:
        assert full_page is True
        return b"official-success-or-review-screenshot"

    def title(self) -> str:
        return self.page_title


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _compensation() -> CompensationBinding:
    return CompensationBinding.derive(
        market_low_gbp=24_000,
        market_high_gbp=30_000,
        statutory_floor_gbp=24_420,
        market_evidence_sha256=_digest(b"market evidence"),
        statutory_evidence_sha256=_digest(b"statutory floor evidence"),
        as_of=date(2026, 8, 4),
    )


def _application(tmp_path: Path) -> AshbyApplication:
    resume = tmp_path / "vega-resume.pdf"
    resume.write_bytes(b"%PDF-1.4\nsynthetic approved Vega resume\n")
    return AshbyApplication(
        full_name="Canary Person",
        email="canary@example.test",
        linkedin="https://www.linkedin.com/in/canary-person/",
        resume_path=resume,
        resume_sha256=_digest(resume.read_bytes()),
        work_rights_uk=True,
        compensation=_compensation(),
    )


def _authority() -> tuple[JAA08ReleaseAuthority, FakeGate]:
    manifest = _digest(b"release manifest")
    token = f"jaa08.{manifest}.synthetic-secret"
    token_hash = _digest(token.encode())
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
        contract_type="employee",
        consumed_at=datetime(2026, 8, 4, 0, 30, tzinfo=timezone.utc),
    )
    return authority, gate


def test_compensation_is_deterministic_and_cannot_be_overridden() -> None:
    binding = _compensation()
    assert binding.annual_total_comp_gbp == 27_000
    assert binding.annual_total_comp_gbp >= binding.statutory_floor_gbp
    with pytest.raises(ValueError, match="deterministic"):
        CompensationBinding(
            25_123,
            binding.market_low_gbp,
            binding.market_high_gbp,
            binding.statutory_floor_gbp,
            binding.market_evidence_sha256,
            binding.statutory_evidence_sha256,
            binding.as_of,
        )


def test_safe_preflight_fills_exact_mapping_but_cannot_consume_or_click(
    tmp_path: Path,
) -> None:
    circuit = AshbyOneUseCircuit(tmp_path / "circuit.sqlite3")
    page = FakePage()
    application = _application(tmp_path)
    _authority_value, gate = _authority()

    review = AshbyLiveAdapter(circuit).prepare_review(
        page,
        application=application,
    )

    assert review.eligible_for_submit is True
    assert review.reason_codes == ()
    assert page.controls['[id="_systemfield_name"]']["input_value"] == (
        application.full_name
    )
    assert page.controls['[id="_systemfield_email"]']["input_value"] == (
        application.email
    )
    assert page.controls[
        '[id="bb738f7d-543d-45f8-9119-29bc615bf9cf"]'
    ]["input_value"] == application.linkedin
    assert page.controls['[id="249396a8-8fdc-4a7d-be1b-3c20aae99bf4"]'][
        "input_value"
    ] == "27000"
    assert page.controls['[id="_systemfield_resume"]']["file_count"] == 1
    assert page.work_right_clicks == ["Yes"]
    assert gate.calls == []
    assert page.clicks == 0
    assert circuit.snapshot()["state"] == "ready"


def test_exact_form_consumes_once_clicks_once_and_writes_hash_only_receipt(
    tmp_path: Path,
) -> None:
    database = tmp_path / "circuit.sqlite3"
    circuit = AshbyOneUseCircuit(database)
    page = FakePage()
    application = _application(tmp_path)
    authority, gate = _authority()

    receipt = AshbyLiveAdapter(circuit).submit(
        page,
        application=application,
        authority=authority,
    )

    assert page.clicks == 1
    assert len(gate.calls) == 1
    assert circuit.snapshot()["state"] == "succeeded"
    assert circuit.receipt() == receipt
    assert _digest(
        json.dumps(
            receipt.document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ) == receipt.receipt_sha256
    persisted = database.read_bytes()
    receipt_text = json.dumps(receipt.document)
    for secret in (
        application.full_name,
        application.email,
        application.linkedin,
        authority.release_token,
    ):
        assert secret not in receipt_text
        assert secret.encode() not in persisted


def test_schema_drift_blocks_before_token_or_click(tmp_path: Path) -> None:
    circuit = AshbyOneUseCircuit(tmp_path / "circuit.sqlite3")
    page = FakePage()
    page.inventory.append(
        InventoryEntry(
            "new-required-field",
            "text",
            "new-required-field",
            "new-required-field",
            True,
            "Tell us an unreviewed fact",
        )
    )
    authority, gate = _authority()

    with pytest.raises(AshbySchemaError, match="inventory"):
        AshbyLiveAdapter(circuit).submit(
            page,
            application=_application(tmp_path),
            authority=authority,
        )
    assert gate.calls == []
    assert page.clicks == 0
    assert circuit.snapshot()["state"] == "blocked"


def test_current_hidden_recaptcha_parks_without_entering_applicant_data(
    tmp_path: Path,
) -> None:
    circuit = AshbyOneUseCircuit(tmp_path / "circuit.sqlite3")
    page = FakePage()
    page.html = (
        '<script>window.__appData={"recaptchaPublicSiteKey":"synthetic"}</script>'
        '<textarea name="g-recaptcha-response" style="display:none"></textarea>'
    )
    page.forbidden_selectors.add('textarea[name*="captcha" i]')
    application = _application(tmp_path)
    authority, gate = _authority()
    adapter = AshbyLiveAdapter(circuit)

    review = adapter.prepare_review(page, application=application)
    assert review.eligible_for_submit is False
    assert review.reason_codes == (
        "captcha_configuration_present",
        "prohibited_control_present",
    )
    assert all(
        value["input_value"] == "" and value["file_count"] == 0
        for value in page.controls.values()
    )
    assert page.work_right_clicks == []
    assert gate.calls == []
    assert page.clicks == 0
    assert circuit.snapshot()["state"] == "ready"

    with pytest.raises(AshbySchemaError, match="parked"):
        adapter.submit(page, application=application, authority=authority)
    assert gate.calls == []
    assert page.clicks == 0
    assert circuit.snapshot()["state"] == "blocked"


@pytest.mark.parametrize(
    "selector",
    (
        'input[type="password"]',
        'input[autocomplete="one-time-code"]',
        'iframe[src*="captcha" i]',
        '[data-sitekey]',
        'input[name*="payment" i]',
        'input[autocomplete^="cc-"]',
    ),
)
def test_login_mfa_captcha_and_payment_controls_fail_closed(
    tmp_path: Path,
    selector: str,
) -> None:
    circuit = AshbyOneUseCircuit(tmp_path / "circuit.sqlite3")
    page = FakePage()
    page.forbidden_selectors.add(selector)
    authority, gate = _authority()
    with pytest.raises(AshbySchemaError, match="parked"):
        AshbyLiveAdapter(circuit).submit(
            page,
            application=_application(tmp_path),
            authority=authority,
        )
    assert gate.calls == []
    assert page.clicks == 0


def test_unknown_required_legal_or_marketing_question_fails_closed(
    tmp_path: Path,
) -> None:
    circuit = AshbyOneUseCircuit(tmp_path / "circuit.sqlite3")
    page = FakePage()
    changed = list(page.inventory)
    changed[-1] = InventoryEntry(
        changed[-1].field_path,
        changed[-1].field_type,
        changed[-1].name,
        changed[-1].control_id,
        True,
        "I consent to future marketing",
        changed[-1].placeholder,
        changed[-1].button_labels,
    )
    page.inventory = changed
    authority, gate = _authority()
    with pytest.raises(AshbySchemaError, match="inventory"):
        AshbyLiveAdapter(circuit).submit(
            page,
            application=_application(tmp_path),
            authority=authority,
        )
    assert gate.calls == []
    assert page.clicks == 0


@pytest.mark.parametrize(
    ("url", "title"),
    (
        (
            "https://jobs.ashbyhq.com/vega/another/application",
            ROLE_TITLE,
        ),
        (APPLICATION_URL + "?source=drift", ROLE_TITLE),
        (APPLICATION_URL, "Different role @ Vega"),
    ),
)
def test_url_or_vacancy_title_drift_fails_closed(
    tmp_path: Path,
    url: str,
    title: str,
) -> None:
    circuit = AshbyOneUseCircuit(tmp_path / "circuit.sqlite3")
    page = FakePage()
    page.url = url
    page.page_title = title
    authority, gate = _authority()
    with pytest.raises(AshbyBoundaryError):
        AshbyLiveAdapter(circuit).submit(
            page,
            application=_application(tmp_path),
            authority=authority,
        )
    assert gate.calls == []
    assert page.clicks == 0


def test_gate_failure_blocks_without_click_and_cannot_retry(tmp_path: Path) -> None:
    circuit = AshbyOneUseCircuit(tmp_path / "circuit.sqlite3")
    adapter = AshbyLiveAdapter(circuit)
    page = FakePage()
    application = _application(tmp_path)
    authority, gate = _authority()
    gate.fail = True

    with pytest.raises(AshbySubmissionIndeterminateError, match="consumption"):
        adapter.submit(page, application=application, authority=authority)
    assert len(gate.calls) == 1
    assert page.clicks == 0
    assert circuit.snapshot()["state"] == "blocked"
    with pytest.raises(AshbyCircuitError, match="one-use"):
        adapter.submit(page, application=application, authority=authority)


def test_gate_receipt_mismatch_blocks_without_click(tmp_path: Path) -> None:
    circuit = AshbyOneUseCircuit(tmp_path / "circuit.sqlite3")
    page = FakePage()
    authority, gate = _authority()
    gate.mismatch = True
    with pytest.raises(AshbySubmissionIndeterminateError, match="differs"):
        AshbyLiveAdapter(circuit).submit(
            page,
            application=_application(tmp_path),
            authority=authority,
        )
    assert len(gate.calls) == 1
    assert page.clicks == 0
    assert circuit.snapshot()["state"] == "blocked"


@pytest.mark.parametrize(
    ("receipt_present", "submit_remains"),
    ((False, False), (True, True)),
)
def test_missing_official_success_proof_is_indeterminate_and_no_retry(
    tmp_path: Path,
    receipt_present: bool,
    submit_remains: bool,
) -> None:
    circuit = AshbyOneUseCircuit(tmp_path / "circuit.sqlite3")
    adapter = AshbyLiveAdapter(circuit)
    page = FakePage()
    page.receipt_present = receipt_present
    page.submit_remains_after_success = submit_remains
    application = _application(tmp_path)
    authority, gate = _authority()

    with pytest.raises(AshbySubmissionIndeterminateError, match="proof|submit"):
        adapter.submit(page, application=application, authority=authority)
    assert page.clicks == 1
    assert len(gate.calls) == 1
    assert circuit.snapshot()["state"] == "click_started"
    assert circuit.receipt() is None

    with pytest.raises(AshbyCircuitError, match="one-use"):
        adapter.submit(page, application=application, authority=authority)
    assert page.clicks == 1
    assert len(gate.calls) == 1


def test_successful_circuit_forbids_second_click(tmp_path: Path) -> None:
    circuit = AshbyOneUseCircuit(tmp_path / "circuit.sqlite3")
    adapter = AshbyLiveAdapter(circuit)
    page = FakePage()
    application = _application(tmp_path)
    authority, gate = _authority()

    adapter.submit(page, application=application, authority=authority)
    with pytest.raises(AshbyCircuitError, match="one-use"):
        adapter.submit(page, application=application, authority=authority)
    assert page.clicks == 1
    assert len(gate.calls) == 1


def test_receipt_row_is_canonical_content_addressed_and_secret_free(
    tmp_path: Path,
) -> None:
    database = tmp_path / "circuit.sqlite3"
    circuit = AshbyOneUseCircuit(database)
    page = FakePage()
    authority, _gate = _authority()
    application = _application(tmp_path)
    receipt = AshbyLiveAdapter(circuit).submit(
        page,
        application=application,
        authority=authority,
    )
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT receipt_sha256,document_json FROM ashby_receipt"
        ).fetchone()
    assert row is not None
    assert row[0] == receipt.receipt_sha256
    assert json.loads(row[1]) == dict(receipt.document)
    database_text = database.read_bytes()
    assert application.email.encode() not in database_text
    assert application.full_name.encode() not in database_text
    assert authority.release_token.encode() not in database_text


def test_resume_hash_mismatch_is_rejected_before_browser_or_database(
    tmp_path: Path,
) -> None:
    resume = tmp_path / "resume.pdf"
    resume.write_bytes(b"original")
    with pytest.raises(ValueError, match="approved bytes"):
        AshbyApplication(
            full_name="Canary Person",
            email="canary@example.test",
            linkedin="https://www.linkedin.com/in/canary-person/",
            resume_path=resume,
            resume_sha256=_digest(b"different"),
            work_rights_uk=True,
            compensation=_compensation(),
        )


def test_selected_canary_cannot_claim_absent_uk_work_rights(
    tmp_path: Path,
) -> None:
    resume = tmp_path / "resume.pdf"
    resume.write_bytes(b"resume")
    with pytest.raises(ValueError, match="UK work rights"):
        AshbyApplication(
            full_name="Canary Person",
            email="canary@example.test",
            linkedin="https://www.linkedin.com/in/canary-person/",
            resume_path=resume,
            resume_sha256=_digest(resume.read_bytes()),
            work_rights_uk=False,
            compensation=_compensation(),
        )
