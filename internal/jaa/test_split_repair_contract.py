"""Adversarial contracts for the generic-candidate repository split.

These tests deliberately inspect tracked shipping material instead of relying on
the working tree: a locally generated profile or ignored runtime directory must
not make a distributable checkout appear clean.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from baseline_adoption import cli
from profiler.candidate_profile import (
    build_profile,
    load_public_llm_context,
    write_profile,
)
from skeleton.run import _profile_block


ROOT = Path(__file__).resolve().parent

# Test code may use explicit hostile examples; it is not distributed runtime
# material.  Generated fixtures and lock files are handled separately below.
_NON_DISTRIBUTABLE = ("test_",)
_HOST_BOUND_OPERATIONAL_FILES = frozenset(
    {
        Path("career_automation/network_witnessed_fixture.py"),
        Path("career_automation/production_handoff_runner.py"),
        Path("career_automation/production_preparation_runner.py"),
        Path("docs/JAA_CONTACT_AUTHORITY_ENROLLMENT_20260810.md"),
        Path("scripts/install_gigabyte_current_time.py"),
        Path("scripts/install_market_handoff_config.py"),
        Path("testing_repository.py"),
    }
)
_ALLOWED_TEXT_SUFFIXES = {
    ".md",
    ".py",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".txt",
    ".sh",
    ".cfg",
    ".ini",
}
_ABSOLUTE_PATH = re.compile(
    r"(?<![\w/])(?:/Users/|/home/|[A-Za-z]:[\\/])", re.IGNORECASE
)
_PRIVATE_OR_SECRET = re.compile(
    r"(?:\b(?:api[_ -]?key|secret|password|access[_ -]?token)\s*[:=]\s*"
    r"(?:['\"][^'\"]{8,}['\"]|[A-Za-z0-9_-]{24,})|"
    r"-----BEGIN [A-Z ]+PRIVATE KEY-----|"
    r"\b\d{8,10}:[A-Za-z0-9_-]{20,}\b|"
    r"(?:linkedin\.com/in|(?:gmail|outlook|icloud)\.com))",
    re.IGNORECASE,
)


def _tracked_distributable_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    )
    files = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(raw.decode("utf-8"))
        if relative.name.startswith(_NON_DISTRIBUTABLE) or relative.name.endswith(
            "_test.py"
        ):
            continue
        # These are explicit Gigabyte deployment or historical-path mapping
        # owners.  Their fixed paths are authority boundaries, not candidate
        # profile defaults distributed for arbitrary hosts.
        if relative in _HOST_BOUND_OPERATIONAL_FILES:
            continue
        if relative.suffix.lower() in _ALLOWED_TEXT_SUFFIXES:
            files.append(ROOT / relative)
    return files


def test_tracked_distributable_material_is_generic_and_path_free() -> None:
    """Shipping material must never smuggle an operator's profile into defaults."""
    violations: list[str] = []
    for path in _tracked_distributable_files():
        text = path.read_text(encoding="utf-8")
        for pattern, label in (
            (_ABSOLUTE_PATH, "absolute path"),
            (_PRIVATE_OR_SECRET, "private value"),
        ):
            match = pattern.search(text)
            if match:
                violations.append(
                    f"{path.relative_to(ROOT)}: {label}: {match.group(0)!r}"
                )

    config = yaml.safe_load((ROOT / "skeleton/config.yaml").read_text(encoding="utf-8"))
    assert config["candidate_fit_profile"] == {}
    candidate_path = str(config["io"]["candidate_profile"])
    assert not Path(candidate_path).is_absolute()
    assert candidate_path == "profiler/data/candidate_profile.yaml"
    assert "profiler/data/" in (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert not violations, "\n".join(violations)


def test_new_candidate_profile_is_operator_supplied_not_a_legacy_filename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An arbitrary new candidate path drives the profile; no guided-pass file is needed."""
    evidence = {
        "meta": {"subject": "New Candidate", "version": "operator-v1"},
        "evidence": [
            {
                "id": "portfolio-1",
                "kind": "project",
                "claim": "Built a public demo",
                "source": "operator supplied portfolio",
                "status": "verified",
                "confidence": 0.9,
            }
        ],
        "career_tracks": {
            "Applied_AI": {
                "interest": 8,
                "skill": 4,
                "confidence": 0.7,
                "market_readiness": 4,
                "evidence": ["portfolio-1"],
                "rationale": "Evidence-backed starting point",
            }
        },
        "capabilities": {"python": ["portfolio-1"]},
        "constraints": {"target_geography": "configured by operator"},
    }
    output = tmp_path / "any-new-candidate-name.yaml"
    write_profile(build_profile(evidence), output)
    assert load_public_llm_context(output)["subject"] == "New Candidate"

    monkeypatch.setenv("CANDIDATE_PROFILE_PATH", str(output))
    profile = _profile_block(
        {"io": {"candidate_profile": "legacy-personal-profile.yaml"}}
    )
    assert profile["subject"] == "New Candidate"
    assert not (ROOT / "profiler/data/sample_answers.yaml").exists()
    assert not (ROOT / "profiler/data/candidate_preferences.yaml").exists()


def test_canonical_marker_and_cli_require_explicit_historical_roots() -> None:
    marker = json.loads(
        (ROOT / "canonical-repository.json").read_text(encoding="utf-8")
    )
    assert marker["canonical_repository"] == {
        "marker": "canonical-repository.json",
        "id": "market-aligner",
        "product_name": "Market Aligner",
        "status": "active",
        "role": "neutral-versioned-successor",
        "identity_rule": (
            "canonical only at a checked-out revision that passes fail-closed "
            "marker and source verification"
        ),
    }
    assert marker["historical_copies"] == {
        "canonical": False,
        "status": "historical-only",
        "identities": [
            "giga-user/market-aligner:historical-copy-1",
            "giga-user/market-aligner:historical-copy-2",
        ],
        "discovery": "operator_supplied_only",
        "prohibition": (
            "not canonical and not valid for certification, publication, or deployment"
        ),
    }
    assert marker["brownfield_import_contract"]["implicit_host_paths"] is False
    assert marker["brownfield_import_contract"]["required_operator_paths"] == [
        "source_root",
        "runtime_data_root",
        "repository_root",
    ]

    parser = cli._parser()
    for command in ("adopt", "adopt-online"):
        with pytest.raises(SystemExit) as missing_paths:
            parser.parse_args([command])
        assert missing_paths.value.code == 2
        parsed = parser.parse_args(
            [
                command,
                "--source-root",
                "/operator/source",
                "--data-root",
                "/operator/data",
                "--repository",
                str(ROOT),
            ]
        )
        assert parsed.source_root == "/operator/source"
        assert parsed.data_root == "/operator/data"
        assert parsed.repository == str(ROOT)


def test_bootstrap_script_uses_only_declared_locked_inputs() -> None:
    """The clean-environment command is deterministic and has no hidden profile input."""
    script = (ROOT / "scripts/bootstrap-test-env.sh").read_text(encoding="utf-8")
    lock = (ROOT / "requirements-test.lock").read_text(encoding="utf-8")
    assert "PYTHON_BOOTSTRAP=${PYTHON_BOOTSTRAP:-python3.12}" in script
    assert '"$PYTHON_BOOTSTRAP" -m venv "$TEST_ENV"' in script
    assert "--requirement requirements-test.lock" in script
    assert "--no-deps --editable ." in script
    assert "CANDIDATE_" not in script and "profiler/data" not in script
    assert "pytest==9.0.3" in lock
