from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

from career_automation import production_handoff_runner as runner
from market_aligner.applications.production_handoff import ProductionHandoffDeployment


def test_public_runner_owns_current_time_and_exposes_no_release_path(monkeypatch, tmp_path: Path) -> None:
    deployment = ProductionHandoffDeployment(
        data_home=tmp_path / "data",
        repository_root=tmp_path / "repo",
        output_root=tmp_path / "outbox",
    )
    witness = object()
    observed: dict[str, object] = {}
    monkeypatch.setattr(runner, "installed_production_current_time_witness", lambda: witness)

    def obtain(value, **kwargs):
        observed.update(kwargs)
        assert value is witness
        return SimpleNamespace(evaluated_at="2026-08-21T00:01:00Z")

    expected = object()

    def build(**kwargs):
        observed["builder"] = kwargs
        return expected

    monkeypatch.setattr(runner, "obtain_current_time", obtain)
    monkeypatch.setattr(runner, "_build_production_handoff_from_authenticated_time", build)
    assert runner.run_production_handoff(
        deployment=deployment,
        profile_id="prf_" + "1" * 32,
        track="software-engineering",
        source_job_key="workable:cogna:847CFBC5F4",
    ) is expected
    assert "freshness_time" not in inspect.signature(runner.run_production_handoff).parameters
    assert observed["environment"] == "production"
    assert observed["purpose"] == "production_handoff_freshness"
    assert observed["builder"]["freshness_time"].isoformat() == "2026-08-21T00:01:00+00:00"
