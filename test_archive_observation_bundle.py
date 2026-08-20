import json
from pathlib import Path

from scripts.archive_observation_bundle import archive_observation


def test_observation_bundle_selects_observed_network_evidence(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    archive_root = tmp_path / "archive"
    screenshot = tmp_path / "blocked.png"
    screenshot.write_bytes(b"png")
    source_url = "https://example.test/jobs/113334"
    network = tmp_path / "network.json"
    network.write_text(
        json.dumps(
            {
                "availability": "observed",
                "events": [{"method": "GET", "status": 200, "url": source_url}],
                "schema_version": "jaa.browser-http-evidence.v1",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )

    result = archive_observation(
        repository_root=repository,
        archive_root=archive_root,
        job_key="provider:113334",
        role_title="Analyst",
        company_name="Example",
        source_url=source_url,
        classification="authentication_required",
        files=(screenshot,),
        network_evidence=network,
        boundary_description="Login required before form access.",
        future_queue="human_authentication",
    )

    manifest = json.loads(
        (
            archive_root
            / "attempts"
            / str(result["attempt_id"])
            / "terminal-manifest.json"
        ).read_bytes()
    )
    selected_hash = manifest["selected"]["browser.redirect_http_evidence"]
    selected = [
        row
        for row in manifest["objects"]
        if row["role"] == "browser.redirect_http_evidence"
        and row["sha256"] == selected_hash
    ]
    assert len(selected) == 1
    assert (
        archive_root / selected[0]["relative_path"]
    ).read_bytes() == network.read_bytes()
    assert result["outcome"] == "blocked"
