from career_automation.greenhouse_live_discovery import (
    classify_greenhouse_response,
    greenhouse_requisition_id,
)


URL = "https://job-boards.greenhouse.io/example/jobs/8624759002"


def test_requisition_identity_supports_direct_and_wrapped_urls() -> None:
    assert greenhouse_requisition_id(URL) == "8624759002"
    assert (
        greenhouse_requisition_id(
            "https://wayve.firststage.co/jobs?gh_jid=8624759002"
        )
        == "8624759002"
    )


def test_active_response_requires_title_requisition_and_form_marker() -> None:
    verdict = classify_greenhouse_response(
        requested_url=URL,
        final_url=URL,
        status=200,
        body=(
            b"<html><h1>Infrastructure Engineer</h1>"
            b"<div>Apply for this job</div><form class='application-form'>"
            b"<button>Submit Application</button></form></html>"
        ),
        expected_title="Infrastructure Engineer",
    )
    assert verdict.live is True
    assert verdict.reason == "live_application_form_observed"


def test_closed_marker_wins_even_when_stale_form_markup_remains() -> None:
    verdict = classify_greenhouse_response(
        requested_url=URL,
        final_url=URL,
        status=200,
        body=(
            b"<h1>Infrastructure Engineer</h1><p>This job is no longer open.</p>"
            b"<form class='application-form'></form>"
        ),
        expected_title="Infrastructure Engineer",
    )
    assert verdict.live is False
    assert verdict.reason == "provider_closed_marker"


def test_wrong_title_or_requisition_fails_closed() -> None:
    body = b"<h1>Different Role</h1><p>Apply for this job</p>"
    wrong_title = classify_greenhouse_response(
        requested_url=URL,
        final_url=URL,
        status=200,
        body=body,
        expected_title="Infrastructure Engineer",
    )
    assert wrong_title.reason == "vacancy_title_mismatch"
    wrong_id = classify_greenhouse_response(
        requested_url=URL,
        final_url="https://job-boards.greenhouse.io/example/jobs/9999999",
        status=200,
        body=b"<h1>Infrastructure Engineer</h1><p>Apply for this job</p>",
        expected_title="Infrastructure Engineer",
    )
    assert wrong_id.reason == "requisition_identity_mismatch"


def test_discovery_cli_archives_real_loopback_response(tmp_path) -> None:
    """Exercise installed fetcher, command and archive with synthetic local HTML."""
    import hashlib
    import json
    import os
    import subprocess
    import sys
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from pathlib import Path

    import pytest
    pytest.importorskip("scrapling.fetchers")
    body = b"<html><h1>Synthetic vacancy</h1><p>This job is no longer available</p></html>"
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    root = Path(__file__).resolve().parents[2]
    output = tmp_path / "queue.json"
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(json.dumps({"entries": [{
        "board": "greenhouse", "key": "greenhouse:synthetic", "raw_sha256": "a" * 64,
        "job_title": "Synthetic vacancy", "company": "Example", "fit": "0.2",
        "url": f"http://127.0.0.1:{server.server_port}/jobs/123",
    }]}))
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join([str(root / "src"), str(root / "internal/jaa")])
    try:
        result = subprocess.run([
            sys.executable, str(root / "internal/jaa/scripts/discover_live_greenhouse_queue.py"),
            "--repository-root", str(root), "--archive-root", str(tmp_path / "archive"),
            "--snapshot", str(snapshot), "--output", str(output),
        ], capture_output=True, text=True, env=environment, timeout=45)
        assert result.returncode == 0, result.stderr
        assert requests == ["/jobs/123"]
        summary = json.loads(result.stdout)
        queue = json.loads(output.read_bytes())
        assert summary["fetched_count"] == 1
        observation = queue["observations"][0]
        assert observation["status"] == 200
        assert observation["error"] is None
        assert observation["body_sha256"] == hashlib.sha256(body).hexdigest()
        assert queue["live_pending_eligibility"] == []
        assert queue["eligibility_authority"] is False
        assert queue["interaction"]["submit_clicks"] == 0
        from career_automation.application_archive import verify_complete_attempt
        verified = verify_complete_attempt(
            summary["attempt_id"], root=tmp_path / "archive", repository_root=root,
        )
        assert verified
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
