#!/usr/bin/env python3
"""Offline regression checks for the deterministic pre-LLM gate."""

from __future__ import annotations

from datetime import date

from scraper.viability import Vacancy, deduplicate, local_decision


def vacancy(
    key: str, title: str, *, board: str = "greenhouse", company: str = "Example AI",
    location: str = "London, UK", body: str = "Python and API work", url: str | None = None,
    expiry: str = "",
) -> Vacancy:
    return Vacancy(
        key=key, board=board, job_id=key.split(":", 1)[-1],
        url=url or f"https://example.test/{key}", posted_at="", raw_text="", raw_json={},
        title=title, company=company, location=location, body=body, expiry=expiry,
    )


def main() -> None:
    today = date(2026, 7, 19)
    good = vacancy("greenhouse:1", "Graduate AI Automation Engineer")
    assert local_decision(good, today=today).decision == "include"

    senior = vacancy("greenhouse:2", "Senior AI Engineer")
    assert local_decision(senior, today=today).reason == "unrealistic_seniority_title"

    hard_years = vacancy(
        "greenhouse:3", "AI Engineer", body="You must have at least 5 years of production experience."
    )
    assert local_decision(hard_years, today=today).reason == "hard_4plus_year_requirement"

    remote = vacancy(
        "weworkremotely:4", "Python Engineer", board="weworkremotely",
        location="Anywhere in the World",
    )
    assert local_decision(remote, today=today).decision == "include"

    foreign = vacancy("personio:5", "Python Engineer", board="personio", location="Munich, Germany")
    assert local_decision(foreign, today=today).reason == "not_uk_eligible"

    eu_remote = vacancy(
        "personio:eu", "Python Engineer", board="personio",
        location="Remote — Europe", body="This is a distributed role across Europe.",
    )
    assert local_decision(eu_remote, today=today).decision == "include"

    eu_only = vacancy(
        "personio:eu-only", "Python Engineer", board="personio",
        location="Remote — EU", body="Applicants must reside in the European Union.",
    )
    assert local_decision(eu_only, today=today).reason == "foreign_residency_required"

    swiss = vacancy(
        "jobsch:swiss", "Junior AI Automation Engineer", board="jobsch",
        location="Zürich, CH",
    )
    assert local_decision(swiss, today=today).reason == "not_uk_eligible"

    swiss_cross_border = vacancy(
        "jobsch:remote", "Junior AI Automation Engineer", board="jobsch",
        location="Remote — EMEA", body="This is a fully remote position across EMEA.",
    )
    assert local_decision(swiss_cross_border, today=today).decision == "include"

    country_tied_remote = vacancy(
        "personio:germany", "Python Engineer", board="personio",
        location="Remote - Munich, Germany", body="Remote work is available within Germany.",
    )
    assert local_decision(country_tied_remote, today=today).reason == "foreign_residency_required"

    ireland_remote = vacancy(
        "irishjobs:ireland", "Python Engineer", board="irishjobs",
        location="Remote - Ireland", body="You must be based in Ireland.",
    )
    assert local_decision(ireland_remote, today=today).reason == "foreign_residency_required"

    expired = vacancy("greenhouse:6", "AI Engineer", expiry="2026-07-18")
    assert local_decision(expired, today=today).reason == "expired"

    stale = vacancy("greenhouse:stale", "AI Engineer")
    stale.posted_at = "2025-06-01T00:00:00Z"
    assert local_decision(stale, today=today).reason == "stale_posting"

    security = vacancy("nhsjobs:security", "Fire Safety and Security Officer")
    assert local_decision(security, today=today).reason == "physical_security_role"

    local_security = vacancy("nhsjobs:local-security", "Band 7 Local Security Management Specialist")
    assert local_decision(local_security, today=today).reason == "physical_security_role"

    medical_technical = vacancy("nhsjobs:medical-tech", "Medical Technical Officer")
    assert local_decision(medical_technical, today=today).reason == "irrelevant_title"

    academic = vacancy("jobsacuk:professor", "Associate Professor in Cyber Security")
    assert local_decision(academic, today=today).reason == "academic_teaching_role"

    teaching = vacancy("jobsacuk:teaching", "Senior Teaching Associate - Cybersecurity")
    assert local_decision(teaching, today=today).reason == "academic_teaching_role"

    phd = vacancy("jobsch:phd", "PhD Position in Multimodal AI", board="jobsch", location="Zürich, CH")
    assert local_decision(phd, today=today).reason == "academic_teaching_role"

    overseas = vacancy(
        "jobsacuk:china", "AI Research Engineer", board="jobsacuk",
        location=("UK university partner information " * 20) + "Suzhou - China",
    )
    assert local_decision(overseas, today=today).reason == "not_uk_eligible"

    direct = vacancy("greenhouse:7", "Python Engineer", url="https://employer.test/jobs/7")
    mirror = vacancy(
        "himalayas:8", "Python Engineer", board="himalayas",
        url="https://aggregator.test/8", location="United Kingdom",
    )
    rows = [direct, mirror]
    decisions = {v.key: local_decision(v, today=today) for v in rows}
    deduplicate(rows, decisions)
    assert decisions[direct.key].decision == "include"
    assert decisions[mirror.key].reason == "cross_source_duplicate"
    assert decisions[mirror.key].representative_key == direct.key
    print("test_viability: PASS")


if __name__ == "__main__":
    main()
