from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from career_automation.personio_live_adapter import (
    APPLICATION_URL,
    DOCUMENT_ACCEPT,
    EMPLOYER_KEY,
    EXPECTED_FORM_INVENTORY,
    FORM_API_URL,
    FORM_SCHEMA_SHA256,
    FROZEN_KEY,
    PERSONIO_ALIAS,
    ROLE_TITLE,
    SUBMIT_LABEL,
    SUCCESS_MARKER,
    VACANCY_ID,
    ContactProfileBinding,
    DuplicateCheck,
    InventoryEntry,
    JAA08ReleaseAuthority,
    PersonioApplication,
    PersonioBoundaryError,
    PersonioCircuitError,
    PersonioLiveAdapter,
    PersonioNetworkTrace,
    PersonioOneUseCircuit,
    PersonioSchemaError,
    PersonioSubmissionIndeterminateError,
)


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _content_hash(value: object) -> str:
    return _hash(_canonical(value).encode())


class FakeGate:
    def __init__(self, manifest: str, token_hash: str) -> None:
        self.manifest = manifest
        self.token_hash = token_hash
        self.calls: list[dict[str, object]] = []
        self.fail = False
        self.wrong_receipt = False

    def consume_release_token(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        if self.fail:
            raise ValueError("synthetic gate refusal")
        return SimpleNamespace(
            release_manifest_sha256=(
                _hash(b"wrong manifest") if self.wrong_receipt else self.manifest
            ),
            token_sha256=(
                _hash(b"wrong token") if self.wrong_receipt else self.token_hash
            ),
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
    ) -> None:
        self.page = page
        self.kind = kind
        self.selector = selector
        self.marker = marker

    def evaluate_all(self, _script: str) -> list[object]:
        if self.kind == "inventory":
            return [entry.document() for entry in self.page.inventory]
        if self.kind == "scripts":
            return list(self.page.script_urls)
        raise AssertionError(f"evaluate_all unsupported for {self.kind}")

    def count(self) -> int:
        if self.kind == "forbidden":
            return int(self.selector in self.page.forbidden_selectors)
        if self.kind in {"body", "control", "inventory", "scripts"}:
            return 1
        if self.kind == "submit":
            if self.page.submitted and not self.page.submit_remains_after_success:
                return 0
            return int(self.page.submit_present)
        if self.kind == "success":
            return int(
                self.page.submitted
                and self.page.receipt_present
                and self.marker == SUCCESS_MARKER
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

    def click(self) -> None:
        assert self.kind == "submit"
        self.page.clicks += 1
        if self.page.click_failure:
            raise RuntimeError("synthetic browser process loss")
        self.page.submitted = True

    def is_visible(self) -> bool:
        return self.count() == 1


class FakePage:
    def __init__(self) -> None:
        self.url = APPLICATION_URL
        self.page_title = ROLE_TITLE
        self.inventory = list(deepcopy(EXPECTED_FORM_INVENTORY))
        self.body_text = "CloudCops Junior DevOps / Cloud Engineer application"
        self.html = "<html><body>official Personio application DOM</body></html>"
        self.script_urls = [
            "https://assets.cdn.personio.de/personio-jobs/main-app.js",
            "https://cloudcops.jobs.personio.com/_next/static/job-page.js",
        ]
        self.forbidden_selectors: set[str] = set()
        self.submit_present = True
        self.submit_remains_after_success = False
        self.receipt_present = True
        self.submitted = False
        self.click_failure = False
        self.clicks = 0
        self.controls = {
            f'[name="{entry.name}"]': {
                "input_value": "",
                "file_count": 0,
            }
            for entry in EXPECTED_FORM_INVENTORY
        }

    def locator(self, selector: str) -> FakeLocator:
        if selector == "form input:not([type=hidden])":
            return FakeLocator(self, kind="inventory")
        if selector == "script[src]":
            return FakeLocator(self, kind="scripts")
        if selector == "body":
            return FakeLocator(self, kind="body")
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
        return b"hash-only synthetic Personio screenshot"

    def title(self) -> str:
        return self.page_title


def _trace(*extra_urls: str) -> PersonioNetworkTrace:
    trace = PersonioNetworkTrace()
    trace.attached_before_navigation = True
    trace.urls.extend((APPLICATION_URL, FORM_API_URL, *extra_urls))
    return trace


def _contact() -> ContactProfileBinding:
    document = {
        "schema": "jaa.authoritative-contact-profile.v1",
        "first_name": "Canary",
        "last_name": "Person",
        "email": "canary@example.test",
        "phone": "+44 7000 000000",
    }
    return ContactProfileBinding(
        first_name=document["first_name"],
        last_name=document["last_name"],
        email=document["email"],
        phone=document["phone"],
        profile_sha256=_content_hash(document),
    )


def _duplicate(*, found: bool = False) -> DuplicateCheck:
    checked_at = datetime(2026, 8, 4, 1, 0, tzinfo=timezone.utc)
    document = {
        "schema": "jaa11.duplicate-check.v1",
        "employer_key": EMPLOYER_KEY,
        "vacancy_id": VACANCY_ID,
        "official_url": APPLICATION_URL,
        "checked_aliases": [FROZEN_KEY, PERSONIO_ALIAS],
        "duplicate_found": found,
        "ledger_snapshot_sha256": _hash(b"synthetic durable duplicate ledger"),
        "checked_at": checked_at.isoformat(),
    }
    return DuplicateCheck(
        employer_key=EMPLOYER_KEY,
        vacancy_id=VACANCY_ID,
        official_url=APPLICATION_URL,
        checked_aliases=(FROZEN_KEY, PERSONIO_ALIAS),
        duplicate_found=found,
        ledger_snapshot_sha256=document["ledger_snapshot_sha256"],
        checked_at=checked_at,
        check_sha256=_content_hash(document),
    )


def _application(tmp_path: Path) -> PersonioApplication:
    cv = tmp_path / "approved-cloudcops-cv.pdf"
    cv.write_bytes(b"%PDF-1.4\nsynthetic approved CloudCops CV\n")
    return PersonioApplication(
        contact=_contact(),
        cv_path=cv,
        cv_sha256=_hash(cv.read_bytes()),
        duplicate_check=_duplicate(),
    )


def _authority() -> tuple[JAA08ReleaseAuthority, FakeGate]:
    manifest = _hash(b"synthetic JAA08 release manifest")
    token = f"jaa08.{manifest}.synthetic-secret"
    token_hash = _hash(token.encode())
    gate = FakeGate(manifest, token_hash)
    authority = JAA08ReleaseAuthority(
        gate=gate,  # type: ignore[arg-type]
        release_token=token,
        source=object(),  # type: ignore[arg-type]
        artifacts=SimpleNamespace(
            cv_pdf=SimpleNamespace(
                pdf_sha256=_hash(
                    b"%PDF-1.4\nsynthetic approved CloudCops CV\n"
                )
            )
        ),  # type: ignore[arg-type]
        contact=SimpleNamespace(
            full_name="Canary Person",
            email="canary@example.test",
            phone="+44 7000 000000",
        ),  # type: ignore[arg-type]
        questions=None,
        artifact_root=Path("/synthetic/artifacts"),
        repository_root=Path("/synthetic/repository"),
        jurisdiction="GB",
        contract_type="employee",
        consumed_at=datetime(2026, 8, 4, 1, 15, tzinfo=timezone.utc),
    )
    return authority, gate


def test_submit_rejects_payload_not_bound_to_release_before_population(
    tmp_path: Path,
) -> None:
    application = _application(tmp_path)
    authority, gate = _authority()
    authority = JAA08ReleaseAuthority(
        gate=authority.gate,
        release_token=authority.release_token,
        source=authority.source,
        artifacts=SimpleNamespace(
            cv_pdf=SimpleNamespace(pdf_sha256=_hash(b"different released CV"))
        ),  # type: ignore[arg-type]
        contact=authority.contact,
        questions=authority.questions,
        artifact_root=authority.artifact_root,
        repository_root=authority.repository_root,
        jurisdiction=authority.jurisdiction,
        contract_type=authority.contract_type,
        consumed_at=authority.consumed_at,
    )
    page = FakePage()
    with pytest.raises(PersonioSchemaError, match="differs from the exact"):
        PersonioLiveAdapter(
            PersonioOneUseCircuit(tmp_path / "mismatch.sqlite3")
        ).submit(
            page,
            application=application,
            network_trace=_trace(),
            authority=authority,
        )
    assert gate.calls == []
    assert page.clicks == 0
    assert all(
        state["input_value"] == "" and state["file_count"] == 0
        for state in page.controls.values()
    )


def test_inventory_is_exact_current_personio_schema() -> None:
    assert [entry.name for entry in EXPECTED_FORM_INVENTORY] == [
        "first_name",
        "last_name",
        "email",
        "phone",
        "custom_attribute_3737466",
        "documents.cv",
        "documents.other",
    ]
    assert [entry.required for entry in EXPECTED_FORM_INVENTORY] == [
        True,
        True,
        True,
        True,
        False,
        True,
        False,
    ]
    assert EXPECTED_FORM_INVENTORY[-1].accept == DOCUMENT_ACCEPT
    assert FORM_SCHEMA_SHA256 == _content_hash(
        [entry.document() for entry in EXPECTED_FORM_INVENTORY]
    )


def test_contact_values_must_match_authoritative_profile_hash() -> None:
    valid = _contact()
    with pytest.raises(ValueError, match="authoritative"):
        ContactProfileBinding(
            valid.first_name,
            valid.last_name,
            "substitution@example.test",
            valid.phone,
            valid.profile_sha256,
        )


def test_duplicate_check_requires_exact_route_and_both_aliases() -> None:
    valid = _duplicate()
    with pytest.raises(ValueError, match="aliases"):
        DuplicateCheck(
            valid.employer_key,
            valid.vacancy_id,
            valid.official_url,
            (PERSONIO_ALIAS,),
            False,
            valid.ledger_snapshot_sha256,
            valid.checked_at,
            valid.check_sha256,
        )
    with pytest.raises(ValueError, match="duplicate application"):
        PersonioApplication(
            contact=_contact(),
            cv_path=Path("/does/not/matter"),
            cv_sha256=_hash(b"not used"),
            duplicate_check=_duplicate(found=True),
        )


def test_network_trace_must_attach_before_navigation() -> None:
    page = FakePage()
    trace = PersonioNetworkTrace()
    with pytest.raises(PersonioBoundaryError, match="before initial navigation"):
        trace.attach(page)  # type: ignore[arg-type]
    with pytest.raises(PersonioBoundaryError, match="not attached"):
        trace.snapshot()


def test_no_submit_review_fills_only_required_fields_after_full_scan(
    tmp_path: Path,
) -> None:
    page = FakePage()
    circuit = PersonioOneUseCircuit(tmp_path / "circuit.sqlite3")
    application = _application(tmp_path)
    authority, gate = _authority()

    review = PersonioLiveAdapter(circuit).prepare_review(
        page, application=application, network_trace=_trace()
    )

    assert review.eligible_for_submit is True
    assert review.reason_codes == ()
    assert page.controls['[name="first_name"]']["input_value"] == (
        application.contact.first_name
    )
    assert page.controls['[name="last_name"]']["input_value"] == (
        application.contact.last_name
    )
    assert page.controls['[name="email"]']["input_value"] == (
        application.contact.email
    )
    assert page.controls['[name="phone"]']["input_value"] == (
        application.contact.phone
    )
    assert page.controls['[name="documents.cv"]']["file_count"] == 1
    assert page.controls['[name="custom_attribute_3737466"]']["input_value"] == ""
    assert page.controls['[name="documents.other"]']["file_count"] == 0
    assert gate.calls == []
    assert page.clicks == 0
    assert circuit.snapshot()["state"] == "ready"
    review_text = _canonical(review.document)
    assert application.contact.email not in review_text
    assert application.contact.phone not in review_text


@pytest.mark.parametrize(
    "selector",
    (
        'input[type="password"]',
        'input[autocomplete="one-time-code"]',
        'iframe[src*="captcha" i]',
        'iframe[title*="captcha" i]',
        '[data-sitekey]',
        'textarea[name*="captcha" i]',
        'input[name*="payment" i]',
        'input[autocomplete^="cc-"]',
    ),
)
def test_forbidden_control_blocks_before_any_population_or_authority(
    tmp_path: Path,
    selector: str,
) -> None:
    page = FakePage()
    page.forbidden_selectors.add(selector)
    application = _application(tmp_path)
    authority, gate = _authority()
    circuit = PersonioOneUseCircuit(tmp_path / "circuit.sqlite3")
    adapter = PersonioLiveAdapter(circuit)

    review = adapter.prepare_review(
        page, application=application, network_trace=_trace()
    )
    assert review.eligible_for_submit is False
    assert "prohibited_control_present" in review.reason_codes
    assert all(
        state["input_value"] == "" and state["file_count"] == 0
        for state in page.controls.values()
    )
    assert gate.calls == [] and page.clicks == 0

    with pytest.raises(PersonioSchemaError, match="parked"):
        adapter.submit(
            page,
            application=application,
            network_trace=_trace(),
            authority=authority,
        )
    assert gate.calls == [] and page.clicks == 0
    assert circuit.snapshot()["state"] == "blocked"


@pytest.mark.parametrize(
    ("surface", "marker", "reason"),
    (
        ("body", "Create an account to apply", "prohibited_visible_boundary_present"),
        ("html", "g-recaptcha-response", "prohibited_serialized_boundary_present"),
        ("html", "hcaptcha", "prohibited_serialized_boundary_present"),
        ("html", "turnstile", "prohibited_serialized_boundary_present"),
        ("script", "https://captcha.example.test/client.js", "prohibited_url_boundary_present"),
        ("network", "https://id.example.test/login", "prohibited_url_boundary_present"),
        ("network", "https://pay.example.test/payment", "prohibited_url_boundary_present"),
        ("network", "https://id.example.test/identity-verification", "prohibited_url_boundary_present"),
    ),
)
def test_every_required_surface_is_scanned_before_population(
    tmp_path: Path,
    surface: str,
    marker: str,
    reason: str,
) -> None:
    page = FakePage()
    trace = _trace()
    if surface == "body":
        page.body_text += marker
    elif surface == "html":
        page.html += marker
    elif surface == "script":
        page.script_urls.append(marker)
    else:
        trace.urls.append(marker)

    review = PersonioLiveAdapter(
        PersonioOneUseCircuit(tmp_path / "circuit.sqlite3")
    ).prepare_review(page, application=_application(tmp_path), network_trace=trace)

    assert review.eligible_for_submit is False
    assert reason in review.reason_codes
    assert all(
        state["input_value"] == "" and state["file_count"] == 0
        for state in page.controls.values()
    )


def test_incomplete_network_observation_blocks_before_population(
    tmp_path: Path,
) -> None:
    trace = PersonioNetworkTrace(urls=[APPLICATION_URL], attached_before_navigation=True)
    page = FakePage()
    review = PersonioLiveAdapter(
        PersonioOneUseCircuit(tmp_path / "circuit.sqlite3")
    ).prepare_review(page, application=_application(tmp_path), network_trace=trace)
    assert review.reason_codes == ("incomplete_network_observation",)
    assert all(state["input_value"] == "" for state in page.controls.values())


def test_schema_or_identity_drift_blocks_without_filling(tmp_path: Path) -> None:
    application = _application(tmp_path)
    authority, gate = _authority()
    page = FakePage()
    page.inventory.append(
        InventoryEntry("new_fact", "new_fact", "text", True, "Unknown fact")
    )
    circuit = PersonioOneUseCircuit(tmp_path / "schema.sqlite3")
    with pytest.raises(PersonioSchemaError, match="inventory"):
        PersonioLiveAdapter(circuit).submit(
            page,
            application=application,
            network_trace=_trace(),
            authority=authority,
        )
    assert gate.calls == [] and page.clicks == 0
    assert all(state["input_value"] == "" for state in page.controls.values())
    assert circuit.snapshot()["state"] == "blocked"

    wrong = FakePage()
    wrong.url = APPLICATION_URL + "&unexpected=true"
    wrong_circuit = PersonioOneUseCircuit(tmp_path / "boundary.sqlite3")
    with pytest.raises(PersonioBoundaryError, match="exact approved"):
        PersonioLiveAdapter(wrong_circuit).prepare_review(
            wrong,
            application=application,
            network_trace=_trace(),
        )


def test_exact_form_consumes_once_clicks_once_and_persists_hashes_only(
    tmp_path: Path,
) -> None:
    database = tmp_path / "circuit.sqlite3"
    circuit = PersonioOneUseCircuit(database)
    page = FakePage()
    application = _application(tmp_path)
    authority, gate = _authority()

    receipt = PersonioLiveAdapter(circuit).submit(
        page,
        application=application,
        network_trace=_trace(),
        authority=authority,
    )

    assert page.clicks == 1
    assert len(gate.calls) == 1
    assert circuit.snapshot()["state"] == "succeeded"
    assert circuit.receipt() == receipt
    assert receipt.receipt_sha256 == _content_hash(receipt.document)
    persisted = database.read_bytes()
    receipt_text = _canonical(receipt.document)
    for secret in (
        application.contact.first_name,
        application.contact.last_name,
        application.contact.email,
        application.contact.phone,
        authority.release_token,
    ):
        assert secret not in receipt_text
        assert secret.encode() not in persisted


def test_gate_failure_is_indeterminate_and_never_retried(tmp_path: Path) -> None:
    circuit = PersonioOneUseCircuit(tmp_path / "circuit.sqlite3")
    adapter = PersonioLiveAdapter(circuit)
    application = _application(tmp_path)
    authority, gate = _authority()
    gate.fail = True

    with pytest.raises(PersonioSubmissionIndeterminateError, match="retry"):
        adapter.submit(
            FakePage(),
            application=application,
            network_trace=_trace(),
            authority=authority,
        )
    assert len(gate.calls) == 1
    assert circuit.snapshot()["state"] == "release_consumption_started"

    with pytest.raises(PersonioSubmissionIndeterminateError, match="retry"):
        adapter.submit(
            FakePage(),
            application=application,
            network_trace=_trace(),
            authority=authority,
        )
    assert len(gate.calls) == 1


def test_wrong_authority_receipt_is_indeterminate_without_click(
    tmp_path: Path,
) -> None:
    circuit = PersonioOneUseCircuit(tmp_path / "circuit.sqlite3")
    authority, gate = _authority()
    gate.wrong_receipt = True
    page = FakePage()
    with pytest.raises(PersonioSubmissionIndeterminateError, match="differs"):
        PersonioLiveAdapter(circuit).submit(
            page,
            application=_application(tmp_path),
            network_trace=_trace(),
            authority=authority,
        )
    assert len(gate.calls) == 1
    assert page.clicks == 0
    assert circuit.snapshot()["state"] == "release_consumption_started"


def test_click_crash_and_missing_receipt_remain_indeterminate(
    tmp_path: Path,
) -> None:
    application = _application(tmp_path)
    authority, gate = _authority()
    page = FakePage()
    page.click_failure = True
    circuit = PersonioOneUseCircuit(tmp_path / "click.sqlite3")
    with pytest.raises(PersonioSubmissionIndeterminateError, match="retry"):
        PersonioLiveAdapter(circuit).submit(
            page,
            application=application,
            network_trace=_trace(),
            authority=authority,
        )
    assert page.clicks == 1 and len(gate.calls) == 1
    assert circuit.snapshot()["state"] == "click_started"

    authority2, gate2 = _authority()
    no_receipt_page = FakePage()
    no_receipt_page.receipt_present = False
    circuit2 = PersonioOneUseCircuit(tmp_path / "receipt.sqlite3")
    with pytest.raises(PersonioSubmissionIndeterminateError, match="proof"):
        PersonioLiveAdapter(circuit2).submit(
            no_receipt_page,
            application=application,
            network_trace=_trace(),
            authority=authority2,
        )
    assert no_receipt_page.clicks == 1 and len(gate2.calls) == 1
    assert circuit2.snapshot()["state"] == "click_started"


def test_circuit_is_durable_across_process_reopen(tmp_path: Path) -> None:
    database = tmp_path / "circuit.sqlite3"
    first = PersonioOneUseCircuit(database)
    application = _application(tmp_path)
    first.prepare(PersonioLiveAdapter._binding(application))
    first.consumption_started(PersonioLiveAdapter._binding(application))
    reopened = PersonioOneUseCircuit(database)
    assert reopened.snapshot()["state"] == "release_consumption_started"
    with pytest.raises(PersonioCircuitError):
        reopened.prepare(PersonioLiveAdapter._binding(application))


def test_cv_bytes_are_bound_and_symlinks_are_rejected(tmp_path: Path) -> None:
    application = _application(tmp_path)
    application.cv_path.write_bytes(b"changed after approval")
    with pytest.raises(ValueError, match="approved bytes"):
        PersonioApplication(
            contact=application.contact,
            cv_path=application.cv_path,
            cv_sha256=application.cv_sha256,
            duplicate_check=application.duplicate_check,
        )

    target = tmp_path / "target.pdf"
    target.write_bytes(b"approved")
    link = tmp_path / "link.pdf"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="non-symlink"):
        PersonioApplication(
            contact=_contact(),
            cv_path=link,
            cv_sha256=_hash(target.read_bytes()),
            duplicate_check=_duplicate(),
        )


def test_receipt_table_rejects_second_receipt(tmp_path: Path) -> None:
    database = tmp_path / "circuit.sqlite3"
    circuit = PersonioOneUseCircuit(database)
    application = _application(tmp_path)
    authority, _gate = _authority()
    PersonioLiveAdapter(circuit).submit(
        FakePage(),
        application=application,
        network_trace=_trace(),
        authority=authority,
    )
    with sqlite3.connect(database) as connection:
        count = connection.execute("SELECT COUNT(*) FROM personio_receipt").fetchone()
    assert count == (1,)
