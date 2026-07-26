"""Independent contracts for v1-seed to byte-backed v2 admission."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from career_automation.employer_research import Citation, RawResponseCache
from career_automation.seed_cohort import (
    CHECKED_SEED_RECORDS_HASH,
    hydrate_seed,
    load_seed,
)


ROOT = Path(__file__).resolve().parent
AS_OF = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def _seed(path: Path) -> list[dict[str, str]]:
    records = [
        {
            "job_key": f"himalayas:seed-{number:02d}",
            "board": "himalayas",
            "company": f"Seed Employer {number:02d}",
            "title": f"Software Engineer {number:02d}",
            "url": f"https://himalayas.example.test/jobs/seed-{number:02d}",
            "payload_hash": hashlib.sha256(f"seed-{number}".encode()).hexdigest(),
        }
        for number in range(1, 31)
    ]
    payload = {
        "schema_version": "jaa04.admitted-queue.v1",
        "source_label": "generated-test",
        "source_queue_count": 58,
        "selection": "generated distinct employers",
        "records": records,
        "records_hash": hashlib.sha256(_canonical(records)).hexdigest(),
    }
    path.write_bytes(_canonical(payload) + b"\n")
    return records


def _records_hash(records: list[dict[str, str]]) -> str:
    return hashlib.sha256(_canonical(records)).hexdigest()


class _Authorities:
    def __init__(
        self,
        cache: RawResponseCache,
        *,
        age_days: int = 1,
        role_outcome: str = "supported",
        top_level_list: bool = False,
        redirect: bool = False,
    ) -> None:
        self.cache = cache
        self.age_days = age_days
        self.role_outcome = role_outcome
        self.top_level_list = top_level_list
        self.redirect = redirect

    def retrieve_plan(self, task: Any):
        posted = (AS_OF - timedelta(days=self.age_days)).isoformat()
        number = task.job_key.rsplit("-", 1)[1]
        document = {
            "title": task.title,
            "hiringOrganization": {"name": task.company},
            "jobLocation": {"addressLocality": "London", "addressCountry": "UK"},
            "datePosted": posted,
            "description": (
                f"{task.company} is hiring {task.title} in London, UK to build "
                "secure Python cloud software and data platform services. "
                "Applications are open for candidates in the United Kingdom. " * 2
            ),
        }
        body = _canonical([document] if self.top_level_list else document)
        digest, reference = self.cache.store(body)
        source_id = f"official:{task.job_key}"
        url = f"https://jobs.official.example.test/{number}"
        requested_url = (
            f"https://apply.official.example.test/{number}"
            if self.redirect else url
        )
        redirect_history = (
            [{"url": requested_url, "status_code": 302}]
            if self.redirect else []
        )
        citation = Citation(
            source_id,
            url,
            AS_OF.isoformat(),
            AS_OF.isoformat(),
            digest,
            reference,
            200,
            requested_url,
            redirect_history,
            posted,
            None,
            "official_vacancy",
            "jobs.official.example.test",
            url,
            f'"datePosted":"{posted}"',
            "generated-authority",
        )
        plan = [{
            "id": "plan:role",
            "kind": "role",
            "outcome": self.role_outcome,
            "source_id": source_id,
            "source_type": "official_vacancy",
        }]
        return [citation], plan


def _capture_module():
    path = ROOT / "scripts" / "capture_jaa_04.py"
    spec = importlib.util.spec_from_file_location("seed_capture_contract", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_checked_fixture_is_valid_only_as_a_thin_seed() -> None:
    seeds = load_seed(ROOT / "career_automation/fixtures/jaa04_admitted_queue.json")
    assert len(seeds) == 30
    assert len({seed.company for seed in seeds}) == 30
    assert CHECKED_SEED_RECORDS_HASH == json.loads(
        (ROOT / "career_automation/fixtures/jaa04_admitted_queue.json").read_text(
            encoding="utf-8"
        )
    )["records_hash"]
    with pytest.raises(RuntimeError, match="authentic v2 decision evidence"):
        _capture_module()._admitted_input(
            ROOT / "career_automation/fixtures/jaa04_admitted_queue.json"
        )


def test_hydrated_seed_is_strict_v2_replayable_decision_evidence(tmp_path: Path) -> None:
    seed = tmp_path / "seed.json"
    records = _seed(seed)
    raw = tmp_path / "raw"
    output = tmp_path / "official-v2.json"
    envelope = hydrate_seed(
        seed,
        output,
        raw,
        as_of=AS_OF,
        authority_retriever=_Authorities(RawResponseCache(raw)),
        expected_seed_records_hash=_records_hash(records),
    )
    assert envelope["schema_version"] == "jaa04.official-admitted-queue.v2"
    assert envelope["seed"]["sha256"] == hashlib.sha256(seed.read_bytes()).hexdigest()
    assert [row["job_key"] for row in envelope["records"]] == [
        row["job_key"] for row in records
    ]
    assert all(row["url"].startswith("https://jobs.official.example.test/") for row in envelope["records"])
    assert all(row["seed_url"] != row["url"] for row in envelope["records"])
    admitted = _capture_module()._admitted_input(output)
    assert set(admitted) == {row["job_key"] for row in records}


def test_hydration_preserves_redirects_and_parses_top_level_json_arrays(
    tmp_path: Path,
) -> None:
    seed = tmp_path / "seed.json"
    records = _seed(seed)
    raw = tmp_path / "raw"
    envelope = hydrate_seed(
        seed,
        tmp_path / "official-v2.json",
        raw,
        as_of=AS_OF,
        authority_retriever=_Authorities(
            RawResponseCache(raw),
            top_level_list=True,
            redirect=True,
        ),
        expected_seed_records_hash=_records_hash(records),
    )
    first = envelope["records"][0]
    assert first["payload"]["location"] == "London, UK"
    assert first["raw_response_refs"][0]["redirect_chain"] == [
        "https://apply.official.example.test/01",
        "https://jobs.official.example.test/01",
    ]
    assert first["raw_response_refs"][0]["redirect_sequence"] == 1
    _capture_module()._admitted_input(tmp_path / "official-v2.json")


@pytest.mark.parametrize(
    ("attack", "message"),
    (
        ("schema", "seed must use"),
        ("hash", "records hash mismatch"),
        ("duplicate-employer", "must be distinct"),
        ("extra-field", "only the checked identity fields"),
        ("invalid-url", "invalid public URL"),
    ),
)
def test_tampered_or_overwide_seed_fails_closed(
    tmp_path: Path,
    attack: str,
    message: str,
) -> None:
    path = tmp_path / "seed.json"
    _seed(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if attack == "schema":
        payload["schema_version"] = "jaa04.official-admitted-queue.v2"
    elif attack == "hash":
        payload["records"][0]["title"] = "Changed"
    elif attack == "duplicate-employer":
        payload["records"][1]["company"] = payload["records"][0]["company"]
        payload["records_hash"] = hashlib.sha256(_canonical(payload["records"])).hexdigest()
    elif attack == "extra-field":
        payload["records"][0]["opportunity"] = 0.9
        payload["records_hash"] = hashlib.sha256(_canonical(payload["records"])).hexdigest()
    elif attack == "invalid-url":
        payload["records"][0]["url"] = "not-a-public-url"
        payload["records_hash"] = hashlib.sha256(_canonical(payload["records"])).hexdigest()
    path.write_bytes(_canonical(payload))
    with pytest.raises(ValueError, match=message):
        load_seed(path, expected_records_hash=payload["records_hash"])


def test_rehashing_a_changed_seed_cannot_bypass_the_reviewed_trust_anchor(
    tmp_path: Path,
) -> None:
    path = tmp_path / "seed.json"
    _seed(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["records"][0]["title"] = "Substituted Role"
    payload["records_hash"] = hashlib.sha256(_canonical(payload["records"])).hexdigest()
    path.write_bytes(_canonical(payload))
    with pytest.raises(ValueError, match="reviewed identity authority"):
        load_seed(path)


@pytest.mark.parametrize(
    ("age_days", "role_outcome", "message"),
    (
        (46, "supported", "publisher time is stale"),
        (1, "unknown", "no supported official vacancy"),
    ),
)
def test_hydration_refuses_stale_or_unproven_authority(
    tmp_path: Path,
    age_days: int,
    role_outcome: str,
    message: str,
) -> None:
    seed = tmp_path / "seed.json"
    records = _seed(seed)
    raw = tmp_path / "raw"
    with pytest.raises(ValueError, match=message):
        hydrate_seed(
            seed,
            tmp_path / "official-v2.json",
            raw,
            as_of=AS_OF,
            authority_retriever=_Authorities(
                RawResponseCache(raw),
                age_days=age_days,
                role_outcome=role_outcome,
            ),
            expected_seed_records_hash=_records_hash(records),
        )
