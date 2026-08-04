from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from career_automation.cloudcops_canary_release import (
    APPLICATION_URL,
    FROZEN_KEY,
    BoundFile,
    CloudCopsReleaseError,
    CloudCopsReleaseInputs,
    prepare_cloudcops_release,
)
from career_automation.personio_live_adapter import PersonioApplication


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _write(path: Path, value: object, *, raw: bool = False) -> BoundFile:
    data = value if raw else _canonical(value)
    assert isinstance(data, bytes)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return BoundFile(path, hashlib.sha256(data).hexdigest())


def _inputs(
    tmp_path: Path,
    *,
    complete_evidence: bool = True,
    route: str = APPLICATION_URL,
    work_right_permitted: bool = True,
    arm: bool = False,
) -> CloudCopsReleaseInputs:
    raw = _write(
        tmp_path / "raw-vacancy.json",
        {
            "title": "Junior DevOps / Cloud Engineer",
            "company": "CloudCops",
            "description": "Approved frozen vacancy bytes",
        },
    )
    entry = {
        "board": "himalayas",
        "company": "CloudCops",
        "entry_level": True,
        "extracted_sha256": hashlib.sha256(b"extracted").hexdigest(),
        "final": "33.131517326536965",
        "fit": "0.13433698948928319",
        "job_id": FROZEN_KEY.removeprefix("himalayas:"),
        "job_title": "Junior DevOps / Cloud Engineer",
        "key": FROZEN_KEY,
        "location": "Remote",
        "mapped_career": "Cloud_Platform_Engineer",
        "opportunity": "0.79093093540957116",
        "rank": 32,
        "raw_sha256": raw.sha256,
        "url": FROZEN_KEY.removeprefix("himalayas:"),
    }
    snapshot_body = {
        "candidate_evidence_sha256": hashlib.sha256(b"candidate").hexdigest(),
        "candidate_prior_profile": "empty",
        "database_sha256": hashlib.sha256(b"database").hexdigest(),
        "entries": [entry],
        "excluded_incomplete_source_count": 0,
        "incomplete_sources_excluded": [],
        "input_viable_count": 1,
        "ranked_entry_count": 1,
        "ranking_algorithm": "deterministic-test-order",
        "schema_version": "jaa11.live-ranked-vacancy-snapshot.v1",
        "source_status": {},
        "viability_manifest_sha256": hashlib.sha256(b"viability").hexdigest(),
    }
    snapshot = _write(
        tmp_path / "ranked-snapshot.json",
        {**snapshot_body, "snapshot_sha256": hashlib.sha256(_canonical(snapshot_body)).hexdigest()},
    )

    requirement_rows = [
        {
            "key": "cloud_automation",
            "text": "Passion for cloud technologies and automation",
            "essential": True,
        },
        {
            "key": "major_cloud",
            "text": "Initial hands-on experience with AWS, GCP, Azure or a similar major cloud",
            "essential": True,
        },
        {"key": "git", "text": "Solid Git know-how", "essential": True},
        {"key": "linux", "text": "Solid Linux know-how", "essential": True},
        {"key": "shell", "text": "Solid shell know-how", "essential": True},
        {
            "key": "learning_curiosity",
            "text": "Learning hunger and curiosity",
            "essential": True,
        },
        {
            "key": "team_communication",
            "text": "Team spirit and communication in German or English",
            "essential": True,
        },
    ]
    remote_policy = "Remote-first – work from anywhere"
    role_excerpt = "Junior DevOps / Cloud Engineer role: work from anywhere"
    body = "\n".join(
        [*(str(row["text"]) for row in requirement_rows), remote_policy, role_excerpt]
    )
    captured_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    capture = _write(
        tmp_path / "official-role-capture.json",
        {
            "schema_version": "jaa11.cloudcops-official-role-capture.v1",
            "captured_at": captured_at,
            "datePublished": captured_at,
            "employer": "CloudCops",
            "title": "Junior DevOps / Cloud Engineer",
            "vacancy_url": "https://cloudcops.jobs.personio.com/job/2183016?language=en",
            "application_url": route,
            "canonical_source_url": "https://cloudcops.jobs.personio.com/job/2183016",
            "ats": "personio",
            "job_id": "2183016",
            "remote_policy": remote_policy,
            "role_excerpt": role_excerpt,
            "requirements": requirement_rows,
            "body": body,
        },
    )
    statements = [
        {
            "id": "E-CLOUD",
            "kind": "portfolio_artifact",
            "statement": "I built and evaluated automation in AWS Lambda environments.",
            "proof_class": "portfolio_artifact",
        },
        {
            "id": "E-GIT",
            "kind": "portfolio_artifact",
            "statement": "I use Git for version control in my software projects.",
            "proof_class": "portfolio_artifact",
        },
        {
            "id": "E-COMMS",
            "kind": "employment_record",
            "statement": "I have paid experience providing online English lessons.",
            "proof_class": "employment_record",
        },
    ]
    if complete_evidence:
        statements.extend(
            [
                {
                    "id": "E-LINUX",
                    "kind": "portfolio_artifact",
                    "statement": "I use Linux in my software engineering work.",
                    "proof_class": "portfolio_artifact",
                },
                {
                    "id": "E-SHELL",
                    "kind": "portfolio_artifact",
                    "statement": "I use shell commands in my software engineering work.",
                    "proof_class": "portfolio_artifact",
                },
                {
                    "id": "E-LEARNING",
                    "kind": "portfolio_artifact",
                    "statement": "I demonstrate learning and curiosity by testing new tools.",
                    "proof_class": "portfolio_artifact",
                },
            ]
        )
    packet = _write(
        tmp_path / "approved-evidence.json",
        {
            "schema_version": "jaa05.operator-approved-statements.v1",
            "human_authority": "operator@example.test",
            "approved_at": "2026-08-03",
            "approval_source": "exact wording review",
            "statements": statements,
        },
    )
    contact = _write(
        tmp_path / "contact.json",
        {
            "schema_version": "1.0",
            "candidate": {
                "first_name": "Ari",
                "last_name": "Operator",
                "email": "ari.operator@example.test",
                "phone": "+44 7700 900321",
                "current_location": "Birmingham, United Kingdom",
            },
        },
    )
    today = datetime.now(timezone.utc).date()
    work_right = _write(
        tmp_path / "work-right.json",
        {
            "schema_version": "jaa.work-right-evidence.v1",
            "human_authority": "operator@example.test",
            "statement": "The candidate has unrestricted permission to work in the United Kingdom.",
            "jurisdiction": "GB",
            "contract_type": "employee",
            "permitted": work_right_permitted,
            "valid_from": (today - timedelta(days=365)).isoformat(),
            "valid_until": (today + timedelta(days=365)).isoformat(),
        },
    )
    authority = _write(
        tmp_path / "operator-authority.md",
        (
            b"The operator authorises one real JAA-11 application canary outside the top 20. "
            b"CAPTCHA, account and MFA boundaries remain forbidden."
        ),
        raw=True,
    )
    return CloudCopsReleaseInputs(
        snapshot,
        raw,
        capture,
        packet,
        contact,
        work_right,
        tmp_path / "published",
        tmp_path / "runtime.sqlite3",
        authority if arm else None,
        arm,
    )


def test_unmatched_role_preferences_do_not_masquerade_as_release_gates(tmp_path: Path) -> None:
    result = prepare_cloudcops_release(_inputs(tmp_path, complete_evidence=False))
    assert result.status == "prepared_not_issued"
    assert result.fit.status == "ready"
    assert result.blocker_codes == ()
    assert result.advisory_gap_codes == (
        "cloudcops-linux",
        "cloudcops-shell",
        "cloudcops-learning-curiosity",
    )
    assert result.publication is not None
    assert result.issued is None


def test_complete_exact_evidence_builds_real_jaa_artifacts_without_issuing(tmp_path: Path) -> None:
    result = prepare_cloudcops_release(_inputs(tmp_path))
    assert result.status == "prepared_not_issued"
    assert result.fit.status == "ready"
    assert result.publication is not None
    assert result.compilation is not None
    assert result.personio_application is not None
    assert result.issued is None
    receipt = next(row for row in result.publication.files if row.filename == "cv.pdf")
    assert result.personio_application.cv_sha256 == receipt.sha256
    assert result.artifacts is not None
    assert receipt.sha256 == result.artifacts.cv_pdf.pdf_sha256
    assert result.personio_application.cv_path.read_bytes() == result.artifacts.cv_pdf.pdf_bytes


def test_exact_input_hash_binding_rejects_changed_packet(tmp_path: Path) -> None:
    values = _inputs(tmp_path)
    values.approved_evidence_packet.path.write_text("{}", encoding="utf-8")
    with pytest.raises(CloudCopsReleaseError, match="differs from its approved bytes"):
        prepare_cloudcops_release(values)


def test_unapproved_work_right_and_different_route_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(CloudCopsReleaseError, match="does not permit GB employment"):
        prepare_cloudcops_release(_inputs(tmp_path / "rights", work_right_permitted=False))
    with pytest.raises(CloudCopsReleaseError, match="different application_url"):
        prepare_cloudcops_release(
            _inputs(tmp_path / "route", route="https://cloudcops.jobs.personio.com/job/999?apply")
        )


def test_personio_rejects_any_cv_bytes_other_than_jaa_publication(tmp_path: Path) -> None:
    result = prepare_cloudcops_release(_inputs(tmp_path))
    assert result.personio_application is not None
    other = tmp_path / "other.pdf"
    other.write_bytes(b"%PDF-1.4\ndifferent\n")
    with pytest.raises(ValueError, match="differs from its approved bytes"):
        PersonioApplication(
            result.personio_application.contact,
            other,
            result.personio_application.cv_sha256,
            result.personio_application.duplicate_check,
        )


def test_explicit_arm_issues_hash_only_and_is_one_use_compatible(tmp_path: Path) -> None:
    result = prepare_cloudcops_release(_inputs(tmp_path, arm=True))
    assert result.status == "issued_not_consumed"
    assert result.issued is not None
    assert result.gate is not None
    assert result.source is not None
    assert result.artifacts is not None
    assert result.contact is not None
    token = result.issued.release_token
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    assert result.public_document()["release_token_sha256"] == token_hash
    with sqlite3.connect(tmp_path / "runtime.sqlite3") as connection:
        assert connection.execute("SELECT token_hash FROM release_tokens").fetchone()[0] == token_hash
        database_text = "\n".join(
            str(value)
            for table in (
                "release_gate_attempts",
                "release_manifests",
                "release_validation_receipts",
                "release_tokens",
            )
            for row in connection.execute(f"SELECT * FROM {table}").fetchall()
            for value in row
        )
    assert token not in database_text
    consumed_at = datetime.now(timezone.utc)
    consumed = result.gate.consume_release_token(
        release_token=token,
        source=result.source,
        artifacts=result.artifacts,
        contact=result.contact,
        questions=result.questions,
        artifact_root=tmp_path / "published",
        repository_root=Path(__file__).resolve().parent,
        jurisdiction="GB",
        contract_type="employee",
        consumed_at=consumed_at,
    )
    with pytest.raises(ValueError, match="already consumed"):
        result.gate.consume_release_token(
            release_token=token,
            source=result.source,
            artifacts=result.artifacts,
            contact=result.contact,
            questions=result.questions,
            artifact_root=tmp_path / "published",
            repository_root=Path(__file__).resolve().parent,
            jurisdiction="GB",
            contract_type="employee",
            consumed_at=consumed_at,
        )
    assert result.gate.verify_consumed_release_token(
        release_token=token,
        source=result.source,
        artifacts=result.artifacts,
        contact=result.contact,
        questions=result.questions,
        artifact_root=tmp_path / "published",
        repository_root=Path(__file__).resolve().parent,
        jurisdiction="GB",
        contract_type="employee",
        consumed_at=datetime.fromisoformat(consumed.consumed_at),
    ) == consumed


def test_module_has_no_placeholder_candidate_identity_or_external_action_code() -> None:
    source = (
        Path(__file__).parent / "career_automation" / "cloudcops_canary_release.py"
    ).read_text(encoding="utf-8").casefold()
    assert "alex example" not in source
    assert "example.test" not in source
    assert "playwright" not in source
    assert "urlopen" not in source
    assert "requests." not in source
