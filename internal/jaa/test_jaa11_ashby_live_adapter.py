from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy
from dataclasses import replace
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
    AshbyApplicationBoundary,
    AshbyBoundaryError,
    AshbyCircuitError,
    AshbyLiveAdapter,
    AshbyNonReleasePreparator,
    AshbyOneUseCircuit,
    AshbyPreparationRefused,
    AshbySchemaError,
    AshbySubmissionIndeterminateError,
    CompensationBinding,
    EXPECTED_FORM_INVENTORY,
    InventoryEntry,
    JAA08ReleaseAuthority,
)
from career_automation.ats_application_authority import (
    verify_ats_application_authority,
)
from career_automation.live_canary_authority import (
    FROZEN_LIVE_CANARY_AUTHORITY,
    compile_canary_selection,
)
from test_application_quality import _quality_input, _quality_source


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


# --------------------------------------------------------------------------
# Vacancy-generic, non-release preparation against a closed fake of the real
# Improbable-shaped Ashby DOM: entry-scoped applicant inventory, out-of-entry
# anonymous upload plumbing, hidden recaptcha response/config signals,
# autocomplete combobox Location and Yes/No work-permit button groups.
# --------------------------------------------------------------------------


ROUTE_A = "https://jobs.ashbyhq.com/company-a/role-a/application"
ROUTE_B = "https://jobs.ashbyhq.com/company-b/role-b/application"
IMPROBABLE_SHAPED_URL = (
    "https://jobs.ashbyhq.com/improbable/general-application"
)
_CAPTURE_SELECTOR = (
    ".ashby-application-form-field-entry input, "
    ".ashby-application-form-field-entry textarea, "
    ".ashby-application-form-field-entry select"
)
_RECAPTCHA_SIGNAL_SELECTORS = frozenset(
    {'textarea[name*="captcha" i]'}
)
_RECAPTCHA_CONFIG_HTML = (
    '<script>window.__appData={"recaptchaPublicSiteKey":"synthetic"}'
    '</script><textarea name="g-recaptcha-response"></textarea>'
)
# Exact static invisible reCAPTCHA anchor as shipped on real Ashby pages:
# recaptcha.net api2/anchor with size=invisible, title reCAPTCHA, and the
# frame itself reports visible via offsetParent/getClientRects.
_RECAPTCHA_ANCHOR_FRAME = {
    "src": (
        "https://www.recaptcha.net/recaptcha/api2/anchor?ar=1&k=synthetic"
        "&co=synthetic&hl=en&v=synthetic&size=invisible&cb=synthetic"
    ),
    "title": "reCAPTCHA",
    "visible": True,
}
_ACTIVE_CHALLENGE_FRAME = {
    "src": (
        "https://www.recaptcha.net/recaptcha/api2/bframe?ar=1"
        "&k=synthetic&v=synthetic&size=invisible"
    ),
    "title": "recaptcha challenge expires in two minutes",
    "visible": True,
}
_VISIBLE_WIDGET_FRAME = {
    "src": (
        "https://www.google.com/recaptcha/api2/anchor?ar=1&k=synthetic"
        "&co=synthetic&hl=en&v=synthetic&size=normal&cb=synthetic"
    ),
    "title": "reCAPTCHA",
    "visible": True,
}


class FakeAshbyControl:
    def __init__(
        self,
        *,
        kind: str,
        id: str = "",
        name: str = "",
        path: str = "",
        label: str = "",
        required: bool = False,
        visible: bool = True,
        disabled: bool = False,
        read_only: bool = False,
        multiple: bool = False,
        options: tuple[tuple[str, str], ...] = (),
        buttons: tuple[dict[str, object], ...] = (),
        value: object = "",
        checked: bool = False,
        role: str = "",
        aria_autocomplete: str = "",
        entry: bool = True,
    ) -> None:
        self.kind = kind
        self.id = id
        self.name = name
        self.path = path
        self.label = label
        self.required = required
        self.visible = visible
        self.disabled = disabled
        self.read_only = read_only
        self.multiple = multiple
        self.options = options
        self.buttons = buttons
        self.value = value
        self.checked = checked
        self.role = role
        self.aria_autocomplete = aria_autocomplete
        self.entry = entry
        self.files: list[dict[str, object]] = []
        self.drop_fill = False
        self.reject_files = False

    @property
    def identity(self) -> str:
        return self.path or self.id or self.name

    def row(self) -> dict[str, object]:
        if self.kind == "checkbox":
            current: object = self.checked
        elif self.kind == "radio":
            current = self.value if self.checked else None
        elif self.kind == "file":
            current = None
        else:
            current = self.value
        return {
            "input_type": self.kind,
            "id": self.id,
            "name": self.name,
            "field_path": self.path,
            "required": self.required,
            "visible": False if self.kind == "hidden" else self.visible,
            "disabled": self.disabled,
            "read_only": self.read_only,
            "multiple": self.multiple,
            "value_attribute": "" if self.value is None else str(self.value),
            "options": [
                {"value": option_value, "label": option_label}
                for option_value, option_label in self.options
            ],
            "buttons": list(self.buttons),
            "current_value": current,
            "role": self.role,
            "aria_autocomplete": self.aria_autocomplete,
            "label": self.label,
            "file_count": len(self.files),
        }


class FakeAshbyButtonLocator:
    def __init__(
        self, page: FakeAshbyPage, control: FakeAshbyControl, label: str
    ) -> None:
        self.page = page
        self.control = control
        self.label = label

    def count(self) -> int:
        return int(
            any(
                button["label"] == self.label for button in self.control.buttons
            )
        )

    def click(self) -> None:
        self.page.log.append(("choice", self.control.identity, self.label))
        self.control.checked = True


class FakeAshbyControlLocator:
    def __init__(self, page: FakeAshbyPage, control: FakeAshbyControl) -> None:
        self.page = page
        self.control = control

    def count(self) -> int:
        return 1

    def fill(self, value: str) -> None:
        self.page.log.append(("fill", self.control.identity))
        if not self.control.drop_fill:
            self.control.value = value

    def input_value(self) -> str:
        return str(self.control.value)

    def select_option(self, value: str) -> None:
        self.page.log.append(("select", self.control.identity))
        self.control.value = value

    def set_input_files(self, files: list[dict[str, object]]) -> None:
        self.page.log.append(("upload", self.control.identity, files))
        if not self.control.reject_files:
            self.control.files = files

    def evaluate(self, _script: str) -> int:
        return len(self.control.files)

    def get_by_role(
        self, role: str, *, name: str, exact: bool
    ) -> FakeAshbyButtonLocator:
        assert role == "button" and exact is True
        return FakeAshbyButtonLocator(self.page, self.control, name)


class FakeAshbySelectorLocator:
    def __init__(self, page: FakeAshbyPage, selector: str) -> None:
        self.page = page
        self.selector = selector
        self.control = self._matching_control()
        self.forbidden_hit = selector in page.forbidden_selectors

    def _matching_control(self) -> FakeAshbyControl | None:
        for control in self.page.controls:
            if (
                self.selector == f'[data-field-path="{control.path}"]'
                and control.path
            ):
                return control
            if self.selector == f'[id="{control.id}"]' and control.id:
                return control
            if self.selector == f'[name="{control.name}"]' and control.name:
                return control
        return None

    def count(self) -> int:
        if self.control is not None:
            return 1
        return int(self.forbidden_hit)


class FakeAshbyCaptureLocator:
    def __init__(self, page: FakeAshbyPage) -> None:
        self.page = page

    def evaluate_all(self, _script: str) -> list[dict[str, object]]:
        self.page.capture_count += 1
        if self.page.capture_count == 2 and self.page.on_recapture is not None:
            self.page.on_recapture(self.page)
        self.page.log.append(("capture",))
        return [
            control.row() for control in self.page.controls if control.entry
        ]


class FakeAshbyFrameLocator:
    def __init__(self, page: FakeAshbyPage) -> None:
        self.page = page

    def evaluate_all(self, _script: str) -> list[dict[str, object]]:
        return [dict(frame) for frame in self.page.frames]


class FakeAshbyCountLocator:
    def __init__(self, count: int, text: str = "") -> None:
        self._count = count
        self._text = text

    def count(self) -> int:
        return self._count

    def inner_text(self) -> str:
        return self._text


class FakeAshbyPage:
    """Closed fake of the live Page surface the preparator may use.

    There is deliberately no ``get_by_role`` on the page itself: the
    preparator must never address a final submit control or any CAPTCHA
    element.  Every inspection surface carries an access counter so tests
    can prove exactly which page reads a refusal path performed.
    """

    def __init__(
        self,
        *,
        url: str,
        title: str,
        controls: list[FakeAshbyControl],
        html: str = "<html><body>exact application form</body></html>",
        body_text: str = "",
        forbidden_selectors: frozenset[str] = frozenset(),
        frames: list[dict[str, object]] | None = None,
    ) -> None:
        self._url = url
        self.url_reads = 0
        self.page_title = title
        self.title_calls = 0
        self.content_calls = 0
        self.screenshot_calls = 0
        self.locator_access: list[str] = []
        self.controls = controls
        self.html = html
        self.body_text = body_text
        self.forbidden_selectors = set(forbidden_selectors)
        self.frames = list(frames or [])
        self.log: list[tuple[object, ...]] = []
        self.capture_count = 0
        self.on_recapture = None

    @property
    def url(self) -> str:
        self.url_reads += 1
        return self._url

    def locator(self, selector: str):
        self.locator_access.append(selector)
        if selector == "iframe":
            return FakeAshbyFrameLocator(self)
        if selector == _CAPTURE_SELECTOR:
            return FakeAshbyCaptureLocator(self)
        if selector == "body":
            return FakeAshbyCountLocator(1, self.body_text)
        probe = FakeAshbySelectorLocator(self, selector)
        if probe.control is not None:
            return FakeAshbyControlLocator(self, probe.control)
        return probe

    def title(self) -> str:
        self.title_calls += 1
        return self.page_title

    def content(self) -> str:
        self.content_calls += 1
        return self.html

    def screenshot(self, *, full_page: bool) -> bytes:
        assert full_page is True
        self.screenshot_calls += 1
        return b"generic-ashby-capture-screenshot"


def _selection_for(source, url: str, **overrides):
    fields = dict(
        ranked_snapshot_sha256=_digest(b"ranked-snapshot"),
        ranking_algorithm="evidence-weighted",
        ranking_version="v1",
        snapshot_entry_count=25,
        selected_rank=21,
        vacancy_identity=source.vacancy_source_identity,
        vacancy_url=url,
        vacancy_retrieved_at="2026-08-26T08:00:00+00:00",
        vacancy_content_sha256=source.vacancy_sha256,
        selected_entry_sha256=_digest(b"selected-entry"),
        duplicate_application_found=False,
        eligibility_gate_passed=True,
        truth_gate_passed=True,
        vacancy_open=True,
        official_route=True,
        selected_only_for_submission_ease=False,
        account_creation_required=False,
        login_required=False,
        mfa_required=False,
        captcha_required=False,
        payment_required=False,
        missing_approved_fact=False,
        optional_marketing_consent="declined",
        public_acquisition_used=False,
    )
    fields.update(overrides)
    return compile_canary_selection(FROZEN_LIVE_CANARY_AUTHORITY, **fields)


def _generic_controls() -> list[FakeAshbyControl]:
    return [
        FakeAshbyControl(
            kind="text", id="_systemfield_name", label="Full name", required=True
        ),
        FakeAshbyControl(
            kind="email", id="_systemfield_email", label="Email", required=True
        ),
        FakeAshbyControl(kind="tel", id="phone_field", label="Phone"),
        FakeAshbyControl(
            kind="file", id="_systemfield_resume", label="Resume", required=True
        ),
        FakeAshbyControl(
            kind="text",
            id="location_field",
            label="Location",
            role="combobox",
            aria_autocomplete="list",
        ),
        FakeAshbyControl(
            kind="checkbox",
            path="work_permit_question",
            name="work_permit_question",
            label="Do you have the legal right to work in the UK?",
            visible=False,
            buttons=(
                {"label": "Yes", "visible": True},
                {"label": "No", "visible": True},
            ),
            checked=False,
        ),
        FakeAshbyControl(
            kind="hidden", name="csrf_state", value="csrf-token-123"
        ),
        FakeAshbyControl(kind="hidden", id="robot_check", name="robot_check"),
        # A real Ashby page carries a visible 1px anonymous file input
        # outside every field entry: external upload plumbing that is not
        # applicant authority.
        FakeAshbyControl(
            kind="file", id="external_anonymous_upload", entry=False
        ),
    ]


def _improbable_shaped_controls() -> list[FakeAshbyControl]:
    return [
        FakeAshbyControl(
            kind="text", id="_systemfield_name", label="Full name", required=True
        ),
        FakeAshbyControl(
            kind="email", id="_systemfield_email", label="Email", required=True
        ),
        FakeAshbyControl(
            kind="file", id="cv_upload_field", label="CV", required=True
        ),
        FakeAshbyControl(
            kind="text",
            id="location_field",
            label="Location",
            required=True,
            role="combobox",
            aria_autocomplete="list",
        ),
        FakeAshbyControl(
            kind="checkbox",
            path="work_permit_question",
            name="work_permit_question",
            label="Do you have the legal right to work in the UK?",
            required=True,
            visible=False,
            buttons=(
                {"label": "Yes", "visible": True},
                {"label": "No", "visible": True},
            ),
            checked=False,
        ),
        FakeAshbyControl(kind="text", id="pronouns_field", label="Pronouns"),
        FakeAshbyControl(
            kind="url", id="linkedin_profile", label="LinkedIn Profile"
        ),
        FakeAshbyControl(kind="url", id="personal_website", label="Website"),
        FakeAshbyControl(
            kind="textarea",
            id="additional_information",
            label="Additional information",
        ),
        FakeAshbyControl(
            kind="hidden", name="csrf_state", value="csrf-token-123"
        ),
        FakeAshbyControl(kind="hidden", id="robot_check", name="robot_check"),
        FakeAshbyControl(
            kind="file", id="external_anonymous_upload", entry=False
        ),
    ]


def _live_page(
    quality_input,
    *,
    url: str = ROUTE_A,
    controls: list[FakeAshbyControl] | None = None,
    title: str | None = None,
) -> FakeAshbyPage:
    return FakeAshbyPage(
        url=url,
        title=(
            title
            or f"{quality_input.source.role_title} @ "
            f"{quality_input.source.company_name}"
        ),
        controls=(
            _generic_controls() if controls is None else controls
        ),
        html=_RECAPTCHA_CONFIG_HTML,
        forbidden_selectors=frozenset(_RECAPTCHA_SIGNAL_SELECTORS),
        frames=[dict(_RECAPTCHA_ANCHOR_FRAME)],
    )


def _prepare(
    page: FakeAshbyPage,
    quality_input,
    *,
    boundary=None,
    selection=None,
    application_url=None,
):
    preparator = AshbyNonReleasePreparator()
    result = preparator.prepare(
        page,
        boundary=boundary
        or AshbyApplicationBoundary.from_selection_contract(
            selection
            or _selection_for(
                quality_input.source, application_url or page.url
            ),
            quality_input.source,
        ),
        selection=selection
        or _selection_for(quality_input.source, application_url or page.url),
        candidate_authority_sha256=quality_input.candidate_authority_sha256,
        source=quality_input.source,
        artifacts=quality_input.artifacts,
        publication_receipt=quality_input.publication_receipt,
    )
    return preparator, result


EXPECTED_GENERIC_IDS = (
    "_systemfield_name",
    "_systemfield_email",
    "phone_field",
    "_systemfield_resume",
    "location_field",
    "work_permit_question",
    "csrf_state",
    "robot_check",
)


def test_generic_preparation_binds_exact_nonrelease_authority(tmp_path: Path) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    source = quality_input.source
    artifacts = quality_input.artifacts
    page = _live_page(quality_input)
    circuit = AshbyOneUseCircuit(tmp_path / "circuit.sqlite3")
    before = circuit.snapshot()

    preparator, preparation = _prepare(page, quality_input)

    authority = preparation.authority
    assert authority.external_action_capability is False
    assert authority.document()["external_action_capability"] is False
    assert authority.answer_sha256 == _digest(authority.answer_bytes)
    assert authority.inventory_sha256 == _digest(authority.inventory_bytes)
    assert authority.document()["observed_inventory_sha256"] == (
        preparation.observed_inventory.content_sha256
    )
    field_ids = tuple(
        row.field_id for row in preparation.observed_inventory.fields
    )
    assert field_ids == EXPECTED_GENERIC_IDS
    assert "external_anonymous_upload" not in field_ids
    assert [row.field_id for row in preparation.answers] == list(field_ids)
    roles = {
        row.field_id: row.automation_role
        for row in preparation.observed_inventory.fields
    }
    assert roles["robot_check"] == "honeypot"
    assert roles["csrf_state"] == "provider_managed"
    assert roles["location_field"] == "applicant"
    assert roles["work_permit_question"] == "applicant"
    assert preparation.anti_bot_signals == (
        "captcha_configuration_present",
        "captcha_hidden_response_present",
    )
    contact = source.contact
    assert preparation.filled_field_ids == (
        "_systemfield_name",
        "_systemfield_email",
        "phone_field",
    )
    assert preparation.uploaded_field_ids == ("_systemfield_resume",)
    assert preparation.uploaded_sha256s == (artifacts.cv_pdf.pdf_sha256,)
    uploads = [event for event in page.log if event[0] == "upload"]
    assert len(uploads) == 1
    assert uploads[0][1] == "_systemfield_resume"
    payload = uploads[0][2][0]
    assert payload["name"] == "cv.pdf"
    assert payload["mimeType"] == "application/pdf"
    assert payload["buffer"] == artifacts.cv_pdf.pdf_bytes
    reviewed = {
        row.field_id: row.current_value
        for row in preparation.reviewed_inventory.fields
    }
    assert reviewed["_systemfield_name"] == contact.full_name
    assert reviewed["_systemfield_email"] == contact.email
    assert reviewed["phone_field"] == contact.phone
    assert reviewed["_systemfield_resume"] == artifacts.cv_pdf.pdf_sha256
    assert reviewed["location_field"] == ""
    # Exact DOM truth: the untouched optional work-permit checkbox keeps
    # its exact False state in observed and reviewed inventories.
    assert reviewed["work_permit_question"] is False
    observed_by_id = {
        row.field_id: row.current_value
        for row in preparation.observed_inventory.fields
    }
    assert observed_by_id["work_permit_question"] is False
    answers_by_id = {
        row.field_id: row for row in preparation.answers
    }
    assert answers_by_id["work_permit_question"].action == "omit"
    assert answers_by_id["work_permit_question"].observed_value is False
    assert reviewed["csrf_state"] == "csrf-token-123"
    assert reviewed["robot_check"] in (None, "")
    anonymous = next(
        row for row in page.controls if row.id == "external_anonymous_upload"
    )
    assert anonymous.files == []
    assert page.log[0] == ("capture",)
    captures = [
        index for index, event in enumerate(page.log) if event[0] == "capture"
    ]
    assert len(captures) == 2
    assert all(
        index > captures[0]
        for index, event in enumerate(page.log)
        if event[0] in {"fill", "upload"}
    )
    assert all(
        event[0] in {"capture", "fill", "upload"} for event in page.log
    )
    assert not any(event[0] == "choice" for event in page.log)
    assert preparator.submit_clicks == 0
    assert preparation.submit_clicks == 0
    assert circuit.snapshot() == before
    assert before["state"] == "ready"
    assert verify_ats_application_authority(
        authority,
        candidate_authority_sha256=quality_input.candidate_authority_sha256,
        source=source,
        artifacts=artifacts,
        publication_receipt=quality_input.publication_receipt,
    ) is authority


def test_two_route_substitution_refuses_before_page_access(tmp_path: Path) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    source = quality_input.source
    selection = _selection_for(source, ROUTE_A)
    boundary = AshbyApplicationBoundary.from_selection_contract(
        selection, source
    )

    page_b = _live_page(quality_input, url=ROUTE_B)
    preparator = AshbyNonReleasePreparator()
    with pytest.raises(
        AshbyPreparationRefused, match="route_outside_approved_ashby_boundary"
    ):
        preparator.prepare(
            page_b,
            boundary=boundary,
            selection=selection,
            candidate_authority_sha256=quality_input.candidate_authority_sha256,
            source=source,
            artifacts=quality_input.artifacts,
            publication_receipt=quality_input.publication_receipt,
        )
    assert page_b.log == []
    assert preparator.value_writes == 0
    assert preparator.upload_writes == 0

    forged = AshbyApplicationBoundary(application_url=ROUTE_B, page_title=boundary.page_title)
    page_a = _live_page(quality_input, url=ROUTE_A)
    with pytest.raises(
        AshbyPreparationRefused, match="selection_boundary_mismatch"
    ):
        preparator.prepare(
            page_a,
            boundary=forged,
            selection=selection,
            candidate_authority_sha256=quality_input.candidate_authority_sha256,
            source=source,
            artifacts=quality_input.artifacts,
            publication_receipt=quality_input.publication_receipt,
        )
    assert page_a.log == []


def test_selection_identity_hash_and_contract_substitutions_refuse(
    tmp_path: Path,
) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    source = quality_input.source
    canonical = _selection_for(source, ROUTE_A)
    boundary = AshbyApplicationBoundary.from_selection_contract(
        canonical, source
    )

    def attempt(selection, *, type_error: bool = False):
        page = _live_page(quality_input)
        preparator = AshbyNonReleasePreparator()
        call = preparator.prepare(
            page,
            boundary=boundary,
            selection=selection,
            candidate_authority_sha256=quality_input.candidate_authority_sha256,
            source=source,
            artifacts=quality_input.artifacts,
            publication_receipt=quality_input.publication_receipt,
        )
        assert page.log == []
        assert preparator.value_writes == 0
        assert preparator.upload_writes == 0
        return call

    with pytest.raises(AshbyPreparationRefused) as refused:
        attempt(_selection_for(source, ROUTE_A, vacancy_identity="vacancy:someone-else"))
    assert refused.value.reason_codes == ("selection_source_mismatch",)

    with pytest.raises(AshbyPreparationRefused) as refused:
        attempt(
            _selection_for(
                source,
                ROUTE_A,
                vacancy_content_sha256=_digest(b"other-vacancy"),
            )
        )
    assert refused.value.reason_codes == ("selection_source_mismatch",)

    tampered = _selection_for(source, ROUTE_A)
    object.__setattr__(tampered, "selected_rank", 1)
    with pytest.raises(AshbyPreparationRefused) as refused:
        attempt(tampered)
    assert refused.value.reason_codes == ("selection_contract_unverified",)

    page = _live_page(quality_input)
    with pytest.raises(TypeError, match="CanarySelectionContract"):
        AshbyNonReleasePreparator().prepare(
            page,
            boundary=boundary,
            selection=SimpleNamespace(vacancy_url=ROUTE_A),
            candidate_authority_sha256=quality_input.candidate_authority_sha256,
            source=source,
            artifacts=quality_input.artifacts,
            publication_receipt=quality_input.publication_receipt,
        )
    assert page.log == []


def test_boundary_derives_from_selection_and_source_only() -> None:
    source = _quality_source()
    selection = _selection_for(source, ROUTE_A)
    derived = AshbyApplicationBoundary.from_selection_contract(
        selection, source
    )
    manual = AshbyApplicationBoundary(
        application_url=selection.vacancy_url,
        page_title="Software Engineer @ Example Ltd",
    )
    assert derived == manual
    assert derived.application_url == selection.vacancy_url
    with pytest.raises(TypeError, match="CanarySelectionContract"):
        AshbyApplicationBoundary.from_selection_contract(
            SimpleNamespace(vacancy_url=ROUTE_A), source
        )
    with pytest.raises(TypeError, match="application source"):
        AshbyApplicationBoundary.from_selection_contract(selection, object())
    substituted = _selection_for(source, ROUTE_A, vacancy_identity="vacancy:other")
    with pytest.raises(ValueError, match="vacancy identity"):
        AshbyApplicationBoundary.from_selection_contract(substituted, source)
    rehashed = _selection_for(
        source, ROUTE_A, vacancy_content_sha256=_digest(b"other-vacancy")
    )
    with pytest.raises(ValueError, match="vacancy hash"):
        AshbyApplicationBoundary.from_selection_contract(rehashed, source)


def test_improbable_shaped_required_location_and_work_permit_refuse_before_data(
    tmp_path: Path,
) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    page = _live_page(
        quality_input,
        url=IMPROBABLE_SHAPED_URL,
        controls=_improbable_shaped_controls(),
    )
    circuit = AshbyOneUseCircuit(tmp_path / "circuit.sqlite3")
    before = circuit.snapshot()

    with pytest.raises(AshbyPreparationRefused) as refused:
        _prepare(page, quality_input)

    assert refused.value.reason_codes == ("unsupported_required_field",)
    message = str(refused.value)
    assert "location_field" in message
    assert "work_permit_question" in message
    assert page.log == [("capture",)]
    for optional in (
        "pronouns_field",
        "linkedin_profile",
        "personal_website",
        "additional_information",
    ):
        control = next(row for row in page.controls if row.id == optional)
        assert control.value == ""
    honeypot = next(row for row in page.controls if row.id == "robot_check")
    assert honeypot.value == ""
    csrf = next(row for row in page.controls if row.name == "csrf_state")
    assert csrf.value == "csrf-token-123"
    work_permit = next(
        row for row in page.controls if row.path == "work_permit_question"
    )
    assert work_permit.checked is False
    anonymous = next(
        row for row in page.controls if row.id == "external_anonymous_upload"
    )
    assert anonymous.files == []
    assert circuit.snapshot() == before


def test_required_autocomplete_location_refuses_before_data(tmp_path: Path) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    controls = _generic_controls()
    next(
        row for row in controls if row.id == "location_field"
    ).required = True
    page = _live_page(quality_input, controls=controls)

    with pytest.raises(AshbyPreparationRefused) as refused:
        _prepare(page, quality_input)

    assert refused.value.reason_codes == ("unsupported_required_field",)
    assert "location_field" in str(refused.value)
    assert page.log == [("capture",)]
    location = next(row for row in page.controls if row.id == "location_field")
    assert location.value == ""


def test_every_unbound_required_field_refuses_before_any_applicant_data(
    tmp_path: Path,
) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    controls = [
        FakeAshbyControl(
            kind="file", id="portfolio_upload", label="Portfolio", required=True
        ),
        *_generic_controls()[1:],
    ]
    page = _live_page(quality_input, controls=controls)

    with pytest.raises(AshbyPreparationRefused) as refused:
        _prepare(page, quality_input)

    assert refused.value.reason_codes == ("unsupported_required_field",)
    assert "portfolio_upload" in str(refused.value)
    assert page.log == [("capture",)]


def test_schema_drift_after_fill_refuses_the_review(tmp_path: Path) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    page = _live_page(quality_input)
    page.on_recapture = lambda current: current.controls.pop(0)

    with pytest.raises(AshbyPreparationRefused, match="schema_drift_after_fill"):
        _prepare(page, quality_input)

    fills = [event for event in page.log if event[0] == "fill"]
    assert len(fills) >= 1


@pytest.mark.parametrize(
    "extra_control",
    (
        FakeAshbyControl(kind="file", id="_systemfield_name"),
        FakeAshbyControl(kind="textarea", name="_systemfield_email"),
    ),
)
def test_duplicate_or_ambiguous_stable_identity_refuses_before_data(
    tmp_path: Path,
    extra_control: FakeAshbyControl,
) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    page = _live_page(
        quality_input, controls=[*_generic_controls(), extra_control]
    )

    with pytest.raises(AshbyPreparationRefused) as refused:
        _prepare(page, quality_input)

    assert refused.value.reason_codes == ("ambiguous_field_identity",)
    assert page.log == [("capture",)]


def test_missing_stable_identity_refuses_before_data(tmp_path: Path) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    controls = [
        *_generic_controls(),
        FakeAshbyControl(kind="text", label="Unidentified free text"),
    ]
    page = _live_page(quality_input, controls=controls)

    with pytest.raises(AshbyPreparationRefused) as refused:
        _prepare(page, quality_input)

    assert refused.value.reason_codes == ("unstable_field_identity",)
    assert page.log == [("capture",)]


def test_prefilled_honeypot_refuses_before_data(tmp_path: Path) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    controls = _generic_controls()
    honeypot = next(row for row in controls if row.id == "robot_check")
    honeypot.value = "bot-text"
    page = _live_page(quality_input, controls=controls)

    with pytest.raises(
        AshbyPreparationRefused, match="honeypot must remain empty"
    ):
        _prepare(page, quality_input)

    assert page.log == [("capture",)]
    assert honeypot.value == "bot-text"


def test_provider_managed_state_change_between_captures_refuses(
    tmp_path: Path,
) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    page = _live_page(quality_input)

    def rotate(current: FakeAshbyPage) -> None:
        csrf = next(
            row for row in current.controls if row.name == "csrf_state"
        )
        csrf.value = "rotated-token"

    page.on_recapture = rotate

    with pytest.raises(AshbyPreparationRefused, match="reviewed_value_drift"):
        _prepare(page, quality_input)

    csrf = next(row for row in page.controls if row.name == "csrf_state")
    assert csrf.value == "rotated-token"


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    (
        (
            lambda page: page.forbidden_selectors.add('input[type="password"]'),
            "prohibited_control_present",
        ),
        (
            lambda page: page.forbidden_selectors.add(
                'input[autocomplete="one-time-code"]'
            ),
            "prohibited_control_present",
        ),
        (
            lambda page: page.forbidden_selectors.add(
                'input[name*="payment" i]'
            ),
            "prohibited_control_present",
        ),
        (
            lambda page: page.frames.append(dict(_ACTIVE_CHALLENGE_FRAME)),
            "active_captcha_challenge_present",
        ),
        (
            lambda page: page.frames.append(dict(_VISIBLE_WIDGET_FRAME)),
            "prohibited_control_present",
        ),
        (
            lambda page: setattr(
                page,
                "body_text",
                "Create an account to apply to continue.",
            ),
            "prohibited_visible_boundary_present",
        ),
    ),
)
def test_login_mfa_payment_and_active_challenge_refuse_with_zero_writes(
    tmp_path: Path,
    mutate,
    expected_code: str,
) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    page = _live_page(quality_input)
    mutate(page)
    preparator = AshbyNonReleasePreparator()
    selection = _selection_for(quality_input.source, ROUTE_A)

    with pytest.raises(AshbyPreparationRefused) as refused:
        preparator.prepare(
            page,
            boundary=AshbyApplicationBoundary.from_selection_contract(
                selection, quality_input.source
            ),
            selection=selection,
            candidate_authority_sha256=quality_input.candidate_authority_sha256,
            source=quality_input.source,
            artifacts=quality_input.artifacts,
            publication_receipt=quality_input.publication_receipt,
        )

    assert expected_code in refused.value.reason_codes
    assert page.log == []
    assert preparator.value_writes == 0
    assert preparator.upload_writes == 0
    assert preparator.submit_clicks == 0


def test_static_invisible_anchor_iframe_is_signal_not_blocker(
    tmp_path: Path,
) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    page = _live_page(quality_input)
    assert page.frames == [dict(_RECAPTCHA_ANCHOR_FRAME)]

    _preparator, preparation = _prepare(page, quality_input)

    assert preparation.anti_bot_signals == (
        "captcha_configuration_present",
        "captcha_hidden_response_present",
    )
    # The anchor/response/config surfaces are only ever inspected, never
    # interacted with: the log carries capture/fill/upload events alone.
    assert all(
        event[0] in {"capture", "fill", "upload"} for event in page.log
    )
    assert not any(
        "captcha" in str(event).casefold() or "recaptcha" in str(event).casefold()
        for event in page.log
    )


def test_url_mismatch_performs_no_further_page_access(tmp_path: Path) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    source = quality_input.source
    selection = _selection_for(source, ROUTE_A)
    boundary = AshbyApplicationBoundary.from_selection_contract(
        selection, source
    )
    page_b = _live_page(quality_input, url=ROUTE_B)
    preparator = AshbyNonReleasePreparator()

    with pytest.raises(
        AshbyPreparationRefused, match="route_outside_approved_ashby_boundary"
    ):
        preparator.prepare(
            page_b,
            boundary=boundary,
            selection=selection,
            candidate_authority_sha256=quality_input.candidate_authority_sha256,
            source=source,
            artifacts=quality_input.artifacts,
            publication_receipt=quality_input.publication_receipt,
        )

    assert page_b.url_reads >= 1
    assert page_b.title_calls == 0
    assert page_b.content_calls == 0
    assert page_b.screenshot_calls == 0
    assert page_b.capture_count == 0
    assert page_b.locator_access == []
    assert page_b.log == []
    assert preparator.value_writes == 0
    assert preparator.upload_writes == 0


def test_sitekey_mount_is_configuration_signal_not_blocker(
    tmp_path: Path,
) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    page = _live_page(quality_input)
    page.forbidden_selectors.add("[data-sitekey]")

    _preparator, preparation = _prepare(page, quality_input)

    assert preparation.anti_bot_signals == (
        "captcha_configuration_present",
        "captcha_hidden_response_present",
    )
    assert page.capture_count == 2
    assert preparation.submit_clicks == 0
    assert all(
        event[0] in {"capture", "fill", "upload"} for event in page.log
    )


def test_hidden_challenge_frame_is_configuration_signal_only(
    tmp_path: Path,
) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    page = _live_page(quality_input)
    hidden_challenge = dict(_ACTIVE_CHALLENGE_FRAME)
    hidden_challenge["visible"] = False
    page.frames.append(hidden_challenge)

    _preparator, preparation = _prepare(page, quality_input)

    # A hidden/preloaded challenge frame is static configuration: recorded,
    # never blocking, never interacted with.
    assert preparation.anti_bot_signals == (
        "captcha_configuration_present",
        "captcha_hidden_response_present",
    )
    assert preparation.authority.external_action_capability is False
    assert preparation.filled_field_ids == (
        "_systemfield_name",
        "_systemfield_email",
        "phone_field",
    )
    assert preparation.uploaded_field_ids == ("_systemfield_resume",)
    assert not any(event[0] == "choice" for event in page.log)


@pytest.mark.parametrize("malformed_visible", ("yes", 1, None, [True]))
def test_malformed_frame_visible_refuses_before_data(
    tmp_path: Path,
    malformed_visible: object,
) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    page = _live_page(quality_input)
    page.frames.append(
        {
            "src": (
                "https://www.recaptcha.net/recaptcha/api2/bframe?ar=1"
                "&k=synthetic&size=invisible"
            ),
            "title": "recaptcha challenge expires in two minutes",
            "visible": malformed_visible,
        }
    )
    preparator = AshbyNonReleasePreparator()
    selection = _selection_for(quality_input.source, ROUTE_A)

    with pytest.raises(AshbyPreparationRefused) as refused:
        preparator.prepare(
            page,
            boundary=AshbyApplicationBoundary.from_selection_contract(
                selection, quality_input.source
            ),
            selection=selection,
            candidate_authority_sha256=quality_input.candidate_authority_sha256,
            source=quality_input.source,
            artifacts=quality_input.artifacts,
            publication_receipt=quality_input.publication_receipt,
        )

    assert refused.value.reason_codes == ("captcha_frame_inspection_failed",)
    assert page.log == []
    assert page.capture_count == 0
    assert preparator.value_writes == 0
    assert preparator.upload_writes == 0
    assert preparator.submit_clicks == 0


def test_wrong_route_host_and_title_each_fail_closed(tmp_path: Path) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    source = quality_input.source
    selection = _selection_for(source, ROUTE_A)
    boundary = AshbyApplicationBoundary.from_selection_contract(
        selection, source
    )

    page_b = _live_page(quality_input, url=ROUTE_B)
    with pytest.raises(
        AshbyPreparationRefused, match="route_outside_approved_ashby_boundary"
    ):
        _prepare(page_b, quality_input, boundary=boundary, selection=selection)
    assert page_b.log == []

    offsite = _live_page(quality_input)
    with pytest.raises(ValueError, match="public HTTPS Ashby"):
        AshbyApplicationBoundary(
            application_url=(
                "https://careers.example.com/example-role/application"
            ),
            page_title=boundary.page_title,
        )
    with pytest.raises(ValueError, match="public HTTPS Ashby"):
        AshbyApplicationBoundary(
            application_url="https://jobs.ashbyhq.com/only-org",
            page_title=boundary.page_title,
        )
    assert offsite.url == ROUTE_A

    mistitled = _live_page(quality_input, title="Different Role @ Example Ltd")
    with pytest.raises(
        AshbyPreparationRefused, match="page_title_boundary_mismatch"
    ):
        _prepare(mistitled, quality_input, selection=selection)
    assert mistitled.log == []


def test_substituted_candidate_source_artifacts_and_receipt_refuse_before_data(
    tmp_path: Path,
) -> None:
    quality_input = _quality_input(tmp_path / "primary", _quality_source())
    source = quality_input.source
    selection = _selection_for(source, ROUTE_A)
    boundary = AshbyApplicationBoundary.from_selection_contract(
        selection, source
    )
    foreign = _quality_input(
        tmp_path / "foreign",
        _quality_source(job_key="example:other-job", vacancy_sha256="e" * 64),
    )

    def refuses(**overrides):
        kwargs = dict(
            boundary=boundary,
            selection=selection,
            candidate_authority_sha256=quality_input.candidate_authority_sha256,
            source=source,
            artifacts=quality_input.artifacts,
            publication_receipt=quality_input.publication_receipt,
        )
        kwargs.update(overrides)
        page = _live_page(quality_input)
        preparator = AshbyNonReleasePreparator()
        with pytest.raises(AshbyPreparationRefused) as refused:
            preparator.prepare(page, **kwargs)
        assert page.log == []
        assert preparator.value_writes == 0
        assert preparator.upload_writes == 0
        return refused.value

    refusal = refuses(candidate_authority_sha256="not-a-hash")
    assert refusal.reason_codes == ("candidate_authority_identity_invalid",)
    forged_source = replace(source, content_sha256="f" * 64)
    refusal = refuses(source=forged_source)
    assert refusal.reason_codes == ("application_source_unverified",)
    # A valid but different vacancy source fails the exact selection binding.
    refusal = refuses(source=foreign.source)
    assert refusal.reason_codes == ("selection_source_mismatch",)
    tampered_artifacts = replace(
        quality_input.artifacts,
        editable=replace(
            quality_input.artifacts.editable,
            cv_text="substituted cv text\n",
        ),
    )
    refusal = refuses(artifacts=tampered_artifacts)
    assert refusal.reason_codes == ("artifacts_unverified",)
    refusal = refuses(publication_receipt=foreign.publication_receipt)
    assert refusal.reason_codes == ("publication_receipt_unverified",)


def test_fill_not_retained_refuses_without_completing(tmp_path: Path) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    controls = _generic_controls()
    next(
        row for row in controls if row.id == "_systemfield_name"
    ).drop_fill = True
    page = _live_page(quality_input, controls=controls)
    preparator = AshbyNonReleasePreparator()
    selection = _selection_for(quality_input.source, ROUTE_A)

    with pytest.raises(AshbyPreparationRefused, match="fill_not_retained"):
        preparator.prepare(
            page,
            boundary=AshbyApplicationBoundary.from_selection_contract(
                selection, quality_input.source
            ),
            selection=selection,
            candidate_authority_sha256=quality_input.candidate_authority_sha256,
            source=quality_input.source,
            artifacts=quality_input.artifacts,
            publication_receipt=quality_input.publication_receipt,
        )

    assert preparator.value_writes == 0
    assert preparator.upload_writes == 0
    assert not any(event[0] == "upload" for event in page.log)
    resume = next(
        row for row in page.controls if row.id == "_systemfield_resume"
    )
    assert resume.files == []
    anonymous = next(
        row for row in page.controls if row.id == "external_anonymous_upload"
    )
    assert anonymous.files == []


def test_upload_not_binding_one_file_refuses(tmp_path: Path) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    controls = _generic_controls()
    next(
        row for row in controls if row.id == "_systemfield_resume"
    ).reject_files = True
    page = _live_page(quality_input, controls=controls)
    preparator = AshbyNonReleasePreparator()
    selection = _selection_for(quality_input.source, ROUTE_A)

    with pytest.raises(AshbyPreparationRefused, match="upload_binding_failed"):
        preparator.prepare(
            page,
            boundary=AshbyApplicationBoundary.from_selection_contract(
                selection, quality_input.source
            ),
            selection=selection,
            candidate_authority_sha256=quality_input.candidate_authority_sha256,
            source=quality_input.source,
            artifacts=quality_input.artifacts,
            publication_receipt=quality_input.publication_receipt,
        )

    assert preparator.upload_writes == 0
    assert preparator.value_writes == 3
    anonymous = next(
        row for row in page.controls if row.id == "external_anonymous_upload"
    )
    assert anonymous.files == []


def test_post_fill_answer_drift_refuses_the_review(tmp_path: Path) -> None:
    quality_input = _quality_input(tmp_path, _quality_source())
    page = _live_page(quality_input)

    def tamper(current: FakeAshbyPage) -> None:
        email = next(
            row for row in current.controls if row.id == "_systemfield_email"
        )
        email.value = "substituted@example.test"

    page.on_recapture = tamper

    with pytest.raises(AshbyPreparationRefused, match="reviewed_value_drift"):
        _prepare(page, quality_input)
