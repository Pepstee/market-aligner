"""Canonical configuration contracts for the JAA-04 official cohort."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from career_automation.employer_research import (
    ATS_AUTHORITY_CANARIES,
    Citation,
    DEFAULT_ATS_ROUTE_ADAPTERS,
    LIVE_ATS_AUTHORITY_CANARIES,
    RawResponseCache,
)
from career_automation.official_cohort import (
    AGGREGATORS,
    OFFICIAL_ADAPTERS,
    _validate_config,
    build,
)
from career_automation.public_access import (
    PublicAccessPolicy,
    RobotsReceipt,
    TermsAttestation,
    USER_AGENT,
    replay_access_receipt,
)
import scripts.capture_jaa04_authority_canaries as canary_capture
from skeleton.configuration import load_config


ROOT = Path(__file__).resolve().parent
OVERNIGHT = ROOT / "skeleton" / "config.overnight.yaml"


def test_overnight_config_projects_one_canonical_official_interface() -> None:
    config = load_config(OVERNIGHT)
    assert "official_sources" not in config

    names, sections, terms = _validate_config(config)
    enabled = set(config["boards"]["enabled"])
    assert names == sorted(enabled & OFFICIAL_ADAPTERS)
    assert set(names) == OFFICIAL_ADAPTERS, (
        "config.overnight.yaml must enable every supported official adapter"
    )
    assert set(names).isdisjoint(AGGREGATORS)
    assert sections == {name: config.get(name, {}) for name in names}
    assert sections["greenhouse"]["companies"]["anthropic"] == "Anthropic"
    assert sections["lever"]["companies"]["palantir"] == "Palantir Technologies"
    assert terms == config["search_terms"]


def test_discovery_boards_are_filtered_without_becoming_authorities() -> None:
    config = {
        "boards": {
            "enabled": [
                "himalayas", "greenhouse", "jobicy", "workable", "remotefirst",
            ]
        },
        "greenhouse": {"companies": {"example": "Example"}},
        "workable": {"companies": {"example": "Example"}},
        "search_terms": ["software engineer"],
    }
    names, sections, terms = _validate_config(config)
    assert names == ["greenhouse", "workable"]
    assert set(sections) == set(names)
    assert terms == ["software engineer"]


def test_live_official_cohort_refuses_to_start_without_access_authority(
    tmp_path: Path,
) -> None:
    with pytest.raises(RuntimeError, match="requires public access authority"):
        build(
            tmp_path / "not-read-without-authority.yaml",
            tmp_path / "output.json",
            tmp_path / "raw",
        )


def test_live_greenhouse_authority_uses_current_public_job_board_api_host() -> None:
    frozen = next(
        row for row in ATS_AUTHORITY_CANARIES
        if row.job_key.startswith("greenhouse:")
    )
    live = next(
        row for row in LIVE_ATS_AUTHORITY_CANARIES
        if row.job_key == frozen.job_key
    )
    assert frozen.authority_url.startswith("https://api.greenhouse.io/")
    assert live.authority_url == (
        "https://boards-api.greenhouse.io/v1/boards/anthropic/jobs/5030244008"
    )
    assert live.authority_hosts == (
        "job-boards.greenhouse.io",
        "boards-api.greenhouse.io",
    )
    assert DEFAULT_ATS_ROUTE_ADAPTERS["greenhouse"].authority_hosts == (
        "boards-api.greenhouse.io",
    )


def test_live_workable_authority_uses_tenant_bound_markdown_route() -> None:
    task = SimpleNamespace(
        job_key="workable:suade:67D795D3DE",
        url="https://apply.workable.com/j/67D795D3DE",
    )
    adapter = DEFAULT_ATS_ROUTE_ADAPTERS["workable"]
    assert adapter.authority_url(task) == (
        "https://apply.workable.com/suade/jobs/view/67D795D3DE.md"
    )
    adapter._validate_route(task, adapter.authority_url(task), final=True)


def test_live_smartrecruiters_authority_remains_on_public_job_page() -> None:
    task = SimpleNamespace(
        job_key="smartrecruiters:Entain:744000133551599",
        url=(
            "https://jobs.smartrecruiters.com/Entain/"
            "744000133551599-platform-engineer-i"
        ),
    )
    adapter = DEFAULT_ATS_ROUTE_ADAPTERS["smartrecruiters"]
    assert adapter.authority_url(task) == task.url
    assert urlsplit(adapter.authority_url(task)).hostname == (
        "jobs.smartrecruiters.com"
    )
    adapter._validate_route(task, adapter.authority_url(task), final=True)


@pytest.mark.parametrize(
    ("job_key", "url"),
    (
        ("workable:suade:OTHER", "https://apply.workable.com/j/67D795D3DE"),
        ("workable:suade:67D795D3DE", "https://apply.workable.com/suade/jobs/view/67D795D3DE.md"),
    ),
)
def test_live_workable_authority_rejects_noncanonical_admitted_identity(
    job_key: str,
    url: str,
) -> None:
    task = SimpleNamespace(job_key=job_key, url=url)
    with pytest.raises(ValueError, match="admitted path"):
        DEFAULT_ATS_ROUTE_ADAPTERS["workable"].authority_url(task)


@pytest.mark.parametrize("attack", (None, "wrong-policy"))
def test_canary_publication_retains_replayable_content_and_robots_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str | None,
) -> None:
    stamp = "2026-07-27T02:00:00+00:00"
    attestations = {}
    for record in LIVE_ATS_AUTHORITY_CANARIES:
        host = urlsplit(record.authority_url).hostname or ""
        attestations[host] = TermsAttestation(
            host=host,
            terms_url=f"https://{host}/terms",
            determination="public_read_only_research_permitted",
            reviewed_at="2026-07-26T18:00:00+00:00",
            reviewed_by="Offline Test Operator",
            reviewer_type="human_operator",
            notes="Synthetic offline canary portability test.",
        )
    policy_hash = hashlib.sha256(b"offline-canary-policy").hexdigest()
    policy = PublicAccessPolicy(
        attestations,
        policy_sha256=policy_hash,
        now=datetime(2026, 7, 27, 2, tzinfo=timezone.utc),
    )

    class FakeTransport:
        def __init__(self, cache: RawResponseCache, **_: object) -> None:
            self.cache = cache

    class FakeRetriever:
        def __init__(
            self,
            cache: RawResponseCache,
            *,
            retriever: FakeTransport,
        ) -> None:
            self.cache = cache

        def retrieve_plan(
            self,
            task: object,
        ) -> tuple[list[Citation], list[dict[str, object]]]:
            job_key = str(getattr(task, "job_key"))
            record = next(
                row for row in LIVE_ATS_AUTHORITY_CANARIES
                if row.job_key == job_key
            )
            body = (
                f'<meta property="article:published_time" content="{stamp}">'
                f"<main>{record.company} — {record.title}</main>"
            ).encode()
            content_hash, content_ref = self.cache.store(body)
            robots = b"User-agent: *\nAllow: /\n"
            robots_hash, robots_ref = self.cache.store(robots)
            host = urlsplit(record.authority_url).hostname or ""
            receipt = RobotsReceipt(
                host=host,
                robots_url=f"https://{host}/robots.txt",
                final_url=f"https://{host}/robots.txt",
                status_code=200,
                content_sha256=robots_hash,
                raw_response_ref=robots_ref,
                redirect_history=[],
                retrieved_at=stamp,
                user_agent=USER_AGENT,
                requested_url=record.authority_url,
                allowed=True,
                crawl_delay_seconds=10.0,
                terms_policy_sha256=policy_hash,
                terms_attestation=asdict(attestations[host]),
            )
            citation = Citation(
                id=f"source:{job_key}",
                url=record.authority_url,
                captured_at=stamp,
                retrieved_at=stamp,
                content_sha256=content_hash,
                raw_response_ref=content_ref,
                status_code=200,
                requested_url=record.authority_url,
                published_at=stamp,
                source_kind="official_vacancy",
                canonical_publisher=host,
                canonical_article=record.authority_url,
                publisher_date_evidence=(
                    f'<meta property="article:published_time" content="{stamp}">'
                ),
                retrieval_engine="scrapling-static",
                access_receipt={
                    **asdict(receipt),
                    **(
                        {"terms_policy_sha256": "0" * 64}
                        if attack == "wrong-policy" else {}
                    ),
                },
            )
            if record.job_key.startswith("greenhouse:"):
                assert record.admitted_url != record.authority_url
                assert citation.requested_url == record.authority_url
                assert citation.access_receipt["requested_url"] == record.authority_url
            return [citation], []

    monkeypatch.setattr(canary_capture, "ScraplingPublicRetriever", FakeTransport)
    monkeypatch.setattr(canary_capture, "PortableAuthorityRetriever", FakeRetriever)
    destination = tmp_path / "canaries"
    if attack == "wrong-policy":
        with pytest.raises(ValueError, match="operator-presented policy"):
            canary_capture.capture(destination, policy)
        assert not destination.exists()
        return
    canary_capture.capture(destination, policy)

    cache = RawResponseCache(destination / ".raw")
    assert (destination / ".raw" / "sha256").is_dir()
    assert sorted(path.name for path in destination.glob("*.json")) == [
        "ashby.json",
        "greenhouse.json",
        "workable.json",
    ]
    for artifact_path in destination.glob("*.json"):
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        row = artifact["captures"][0]
        embedded = base64.b64decode(row["raw_response_base64"], validate=True)
        assert cache.resolve(
            row["sidecar_raw_response_ref"],
            row["content_sha256"],
        ) == embedded
        replay_access_receipt(
            row["access_receipt"],
            cache,
            content_urls=(row["requested_url"], row["url"]),
            content_retrieved_at=row["retrieved_at"],
            policies={policy_hash: policy},
        )


@pytest.mark.parametrize(
    ("config", "message"),
    (
        (
            {"official_sources": {"greenhouse": {}}},
            "official_sources is retired",
        ),
        (
            {"boards": {"enabled": ["himalayas", "jobicy"]}},
            "no supported official adapters",
        ),
        (
            {"boards": {"enabled": "greenhouse"}},
            "boards.enabled must be a non-empty list",
        ),
        (
            {"boards": {"enabled": ["greenhouse"]}, "greenhouse": []},
            "greenhouse configuration must be a mapping",
        ),
        (
            {
                "boards": {"enabled": ["greenhouse"]},
                "search_terms": ["software", ""],
            },
            "search_terms entries must be non-empty strings",
        ),
        (
            {
                "boards": {"enabled": ["greenhouse"]},
                "search_terms": [],
            },
            "search_terms must be a non-empty list",
        ),
    ),
)
def test_competing_or_malformed_config_fails_explicitly(
    config: dict[str, object], message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _validate_config(config)


@pytest.mark.parametrize("extends", (False, 7, [], ""))
def test_inherited_config_rejects_non_path_extends(
    tmp_path: Path, extends: object,
) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(f"extends: {extends!r}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="extends must be a non-empty string path"):
        load_config(path)


def test_inherited_config_rejects_cycles(tmp_path: Path) -> None:
    first, second = tmp_path / "first.yaml", tmp_path / "second.yaml"
    first.write_text("extends: second.yaml\n", encoding="utf-8")
    second.write_text("extends: first.yaml\n", encoding="utf-8")
    with pytest.raises(ValueError, match="configuration extends cycle"):
        load_config(first)


@pytest.mark.parametrize("payload", ("[]\n", "false\n", "'scalar'\n"))
def test_config_root_must_be_a_mapping(tmp_path: Path, payload: str) -> None:
    path = tmp_path / "invalid-root.yaml"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(ValueError, match="configuration must be a mapping"):
        load_config(path)
