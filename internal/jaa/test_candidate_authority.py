import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from career_automation.candidate_authority import (
    APPROVED_EVIDENCE_PATH,
    APPROVED_CANDIDATE_SOURCE_HASHES,
    APPROVED_EVIDENCE_IDS,
    TYPED_EVIDENCE_SCHEMA,
    CandidateAuthoritySources,
    _matched_evidence,
    _tokens,
    fit_from_evidence_matrix,
    materialize_candidate_authority,
    typed_evidence_projection,
)


PRODUCTION_DISCOVERY_PATH = (
    Path(__file__).resolve().parents[2]
    / ".market-aligner-data"
    / "authority-inputs"
    / "objects"
    / "39"
    / "39e60f8d278d8a07427c8bc25eff85bd357e98451cce87983d70d3d85e935f47"
)


def _require_complete_private_authority_inputs() -> None:
    sources = CandidateAuthoritySources()
    required = (
        PRODUCTION_DISCOVERY_PATH,
        sources.availability,
        sources.approved_evidence,
        sources.operator_answers,
        sources.negative_claim_suppressors,
        sources.jobs_database,
    )
    if not all(path.is_file() for path in required):
        pytest.skip(
            "requires the exact private discovery and candidate source set; "
            "synthetic substitution would not test certified materialization"
        )


def test_named_aws_service_and_deployment_require_exact_evidence() -> None:
    lambda_evidence = (
        {
            "id": "E-002",
            "statement": (
                "My final-year dissertation project, SCAFAD, investigated anomaly "
                "detection within AWS Lambda environments using serverless telemetry."
            ),
        },
    )

    assert _matched_evidence(
        "Hands-on experience deploying models with AWS SageMaker is required",
        lambda_evidence,
    ) == ()
    assert _matched_evidence("Experience with AWS Lambda", lambda_evidence) == (
        "E-002",
    )
    assert _matched_evidence(
        "Experience deploying AWS Lambda models", lambda_evidence
    ) == ()
    direct_sagemaker_evidence = (
        {
            "id": "E-999",
            "statement": "Deployed production models with AWS SageMaker.",
        },
    )
    assert _matched_evidence(
        "Hands-on experience deploying models with AWS SageMaker is required",
        direct_sagemaker_evidence,
    ) == ("E-999",)


# Evidence statements that carry the generic tokens the prior len>=2 rule falsely
# matched. Matching must ignore the generic overlap and demand a named material
# subject instead.
_SYSTEM_ARCHITECTURE_EVIDENCE = (
    {
        "id": "E-012",
        "statement": (
            "For my multi-agent orchestrator I own system architecture and "
            "acceptance decisions; AI agents generated the implementation."
        ),
    },
)
_PUBLIC_EVIDENCE = (
    {
        "id": "E-017",
        "statement": (
            "The public scafad-delta repository is supporting evidence for my "
            "dissertation, and it is not production experience."
        ),
    },
)
_QUESTION_EVIDENCE = (
    {
        "id": "E-016",
        "statement": (
            "Learning Accelerator is a prototype for LLM-assisted question "
            "generation; it supports review sessions and analytics."
        ),
    },
)
_PROJECT_EVIDENCE = (
    {
        "id": "E-002",
        "statement": (
            "My final-year dissertation project gave me hands-on experience with "
            "anomaly detection."
        ),
    },
)


@pytest.mark.parametrize(
    "requirement, evidence, shared",
    [
        # experience+public
        ("Experience of the public charging network", _PUBLIC_EVIDENCE,
         {"experience", "public"}),
        # experience+not
        ("Relevant experience, although certification is not essential",
         _PUBLIC_EVIDENCE, {"experience", "not"}),
        # evidence+support
        ("Ability to gather evidence and support delivery", _PUBLIC_EVIDENCE,
         {"evidence"}),
        # it+question
        ("Willing to question it and iterate", _QUESTION_EVIDENCE,
         {"it", "question"}),
        # evidence+it
        ("Provide evidence and communicate it clearly", _PUBLIC_EVIDENCE,
         {"evidence", "it"}),
        # architecture+system
        ("Distributed systems and scalable software architecture",
         _SYSTEM_ARCHITECTURE_EVIDENCE, {"system", "architecture"}),
        # experience+project
        ("Experience with complex integration projects", _PROJECT_EVIDENCE,
         {"experience", "project"}),
    ],
)
def test_generic_token_overlap_never_mints_support(requirement, evidence, shared):
    # The generic tokens really are shared with the evidence ...
    overlap = _tokens(requirement) & _tokens(str(evidence[0]["statement"]))
    assert shared.issubset(overlap), (requirement, overlap)
    # ... yet without a named material subject the requirement stays a gap.
    assert _matched_evidence(requirement, evidence) == ()


def test_named_material_and_multi_agent_positive_controls():
    multi_agent_evidence = (
        {
            "id": "E-012",
            "statement": (
                "For my multi-agent orchestrator I own system architecture and "
                "acceptance decisions."
            ),
        },
    )
    assert _matched_evidence(
        "Experience building multi-agent systems", multi_agent_evidence
    ) == ("E-012",)
    python_evidence = (
        {"id": "E-P", "statement": "Delivered production backend services in Python."},
    )
    assert _matched_evidence(
        "Strong commercial Python experience", python_evidence
    ) == ("E-P",)
    # A named material subject with no attesting evidence is a gap, never invented.
    assert _matched_evidence(
        "Strong commercial Python experience", multi_agent_evidence
    ) == ()


def test_typed_projection_binds_evidence_ids_and_statement_hashes():
    statement = "Deployed a multi-agent orchestrator with AWS SageMaker in production."
    projection = typed_evidence_projection(({"id": "E-012", "statement": statement},))
    assert set(projection) == {"E-012"}
    entry = projection["E-012"]
    assert entry["schema"] == TYPED_EVIDENCE_SCHEMA
    assert entry["statement_sha256"] == hashlib.sha256(statement.encode()).hexdigest()
    facts = {(f["entity"], f["action"], f["modality"]) for f in entry["facts"]}
    # The parser types entity, action and modality — not a bag of shared tokens.
    assert ("multi-agent", "deployed", "production") in facts
    assert ("sagemaker", "deployed", "production") in facts
    # Generic words never become entities.
    assert not any(f["entity"] in {"system", "architecture"} for f in entry["facts"])


def test_approved_atlas_covers_exactly_the_eighteen_statements(tmp_path):
    # The explicit hash-bound atlas is materialized against the real approved
    # packet: every atlas key is a current statement hash and every statement is
    # covered, so any change to the shared source both misses the atlas and fails
    # the pinned-hash gate.
    from career_automation.candidate_authority import (
        _APPROVED_EVIDENCE_ATLAS,
        _approved_evidence,
    )

    evidence = _approved_evidence(
        APPROVED_EVIDENCE_PATH.read_bytes()
    )
    statement_hashes = {
        hashlib.sha256(str(row["statement"]).encode()).hexdigest() for row in evidence
    }
    assert set(_APPROVED_EVIDENCE_ATLAS) == statement_hashes
    # Production matching serves every approved statement from the atlas, never the
    # fallback parser.
    projection = typed_evidence_projection(evidence)
    for row in evidence:
        digest = hashlib.sha256(str(row["statement"]).encode()).hexdigest()
        atlas = _APPROVED_EVIDENCE_ATLAS[digest]
        served = {
            (f["entity"], f["action"], f["modality"])
            for f in projection[str(row["id"])]["facts"]
        }
        assert served == set(atlas)


# Realistic full-vacancy requirement clauses scored against the REAL eighteen-
# statement approved atlas (not a synthetic single-statement fixture). This is an
# integration guard: the single-statement negative/positive controls prove the
# algorithm is conservative, but only a whole-atlas battery catches a future atlas
# edit that would let a realistic requirement false-positive across the combined
# evidence set. Expected tuples are the exact conservative matches; every trap that
# names an attested technology under an unentailed action/modality/numeric/scale
# constraint must stay a gap.
_REAL_ATLAS_REQUIREMENT_BATTERY = [
    # False-positive traps: each names an attested technology but demands an
    # action/modality/numeric/scale the approved evidence never attests.
    ("Strong production experience deploying ML models on AWS SageMaker", ()),
    ("Operate and maintain production AWS Lambda services on-call", ()),
    ("5+ years commercial Python experience", ()),
    ("Kubernetes operations in production", ()),
    ("Experience with Bazel remote build caching", ()),
    ("Reinforcement learning research experience", ()),
    ("Distributed backend architecture at scale serving millions of users", ()),
    ("Operate production LLM systems with paying customers", ()),
    ("Django or Flask production experience", ()),
    ("Experience engaging with members of the public", ()),
    ("Strong system architecture and design experience", ()),
    # Genuine conservative matches drawn from the exact approved statements.
    ("Built multi-agent orchestration systems", ("E-012",)),
    # E-008 attests design OR implementation. It cannot satisfy a conjunction
    # requiring both, but it remains valid professional website experience.
    ("Designed and built a client-facing website", ()),
    ("Professional website experience", ("E-008",)),
    ("Built and shipped features using SQLite", ("E-011",)),
    ("Academic study of serverless anomaly detection", ("E-002",)),
    ("Built an LLM prototype", ("E-016",)),
]


@pytest.mark.parametrize("requirement,expected", _REAL_ATLAS_REQUIREMENT_BATTERY)
def test_real_atlas_requirement_battery(requirement, expected):
    from career_automation.candidate_authority import (
        _approved_evidence,
    )

    evidence = _approved_evidence(
        APPROVED_EVIDENCE_PATH.read_bytes()
    )
    assert _matched_evidence(requirement, evidence) == expected


def _ev(statement, ident="E-X"):
    return ({"id": ident, "statement": statement},)


# Mandatory semantic-entailment adversarial matrix. Each negative shares a named
# token with its evidence yet must NOT match because the action, modality, numeric
# extent, negation, or a co-named unattested technology is not entailed.
_NEGATIVE_MATRIX = [
    # numeric shortfall: one/five-year Python
    ("5 years commercial Python experience", "Delivered production Python services."),
    ("3+ years of Python", "Built a Python tool."),
    # prototype vs production
    ("Operate production LLM services", "Built an LLM prototype."),
    # academic vs commercial
    ("Commercial anomaly detection experience",
     "Studied anomaly detection in my dissertation."),
    # used/experience vs owned/led
    ("Ownership of the React platform", "Used React on a project."),
    ("Lead delivery of Kubernetes operators", "Familiar with Kubernetes."),
    # AWS Lambda vs SageMaker
    ("Hands-on AWS SageMaker experience", "Studied AWS Lambda environments."),
    # generic AWS vs exact service
    ("AWS SageMaker deployment", "Familiar with AWS."),
    # Python vs Django
    ("Django experience", "Strong Python developer."),
    # single-agent vs multi-agent
    ("Single-agent reinforcement learning", "Built a multi-agent system."),
    # backend vs distributed backend at scale
    ("Distributed backend at scale", "Built a backend service."),
    # explicit negation on the evidence side
    ("B2B sales experience", "It was not a B2B sales role."),
    # explicit negation on the requirement side (no prior experience wanted)
    ("No prior Python experience required", "Strong Python developer."),
    # conjunction not fully covered
    ("Django and PostgreSQL", "Experience with Flask and Django."),
    # shared entity embedded with an unattested co-named technology
    ("Remote build caching with Bazel", "Directed AI agents to add a caching layer."),
    # a shared entity buried in an unrelated sentence never mints support
    ("Kafka streaming experience", "Built a caching layer with retries."),
]


@pytest.mark.parametrize("requirement, statement", _NEGATIVE_MATRIX)
def test_entailment_negative_controls(requirement, statement):
    assert _matched_evidence(requirement, _ev(statement)) == ()


# Positive controls: the evidence genuinely entails the exact typed requirement.
_POSITIVE_MATRIX = [
    ("Commercial Python experience", "Delivered production Python services."),
    ("Experience with LLM systems", "Built an LLM prototype."),
    ("Experience with anomaly detection", "Studied anomaly detection in my dissertation."),
    ("Ownership of the React platform", "Owned and operated the React platform."),
    ("AWS experience", "Familiar with AWS."),
    ("Python experience", "Strong Python developer."),
    ("Experience building multi-agent systems", "Built a multi-agent system."),
    ("Backend experience", "Built a backend service."),
    ("Sales experience", "Customer-facing direct sales role."),
    ("Experience with caching", "Directed AI agents to add a caching layer."),
    # disjunction: either branch suffices
    ("Django or Flask", "Experience with Flask."),
    # conjunction fully covered by one item
    ("Django and PostgreSQL", "Built services with Django and PostgreSQL."),
    # exact named service + deployment action
    ("Hands-on experience deploying models with AWS SageMaker",
     "Deployed production models with AWS SageMaker."),
]


@pytest.mark.parametrize("requirement, statement", _POSITIVE_MATRIX)
def test_entailment_positive_controls(requirement, statement):
    assert _matched_evidence(requirement, _ev(statement)) == ("E-X",)


def test_materializer_builds_content_addressed_candidate_authority(
    tmp_path: Path,
) -> None:
    _require_complete_private_authority_inputs()
    result = materialize_candidate_authority(
        discovery_path=PRODUCTION_DISCOVERY_PATH,
        archive_root=tmp_path,
        repository_root=Path.cwd(),
    )

    assert result.value == result.object_path.read_bytes()
    assert result.value == result.authority_path.read_bytes()
    assert hashlib.sha256(result.value).hexdigest() == result.sha256
    assert (
        result.object_path == tmp_path / "objects" / result.sha256[:2] / result.sha256
    )

    document = json.loads(result.value)
    duplicate_digest = document["duplicate_snapshot_sha256"]
    duplicate_snapshot = (
        tmp_path / "objects" / duplicate_digest[:2] / duplicate_digest
    ).read_bytes()
    assert hashlib.sha256(duplicate_snapshot).hexdigest() == duplicate_digest
    assert isinstance(json.loads(duplicate_snapshot), list)
    projection = document["candidate_projection"]
    assert projection["source_hashes"] == APPROVED_CANDIDATE_SOURCE_HASHES
    assert [row["id"] for row in projection["approved_evidence"]] == list(
        APPROVED_EVIDENCE_IDS
    )
    assert [row["id"] for row in projection["claim_suppressors"]["items"]] == [
        f"Q-{index:03d}" for index in range(1, 11)
    ]

    decisions = [row["receipt"] for row in document["decisions"]]
    assert len(decisions) == 21
    assert sum(row["decision"] == "eligible" for row in decisions) == 15
    assert sum(row["decision"] == "ineligible" for row in decisions) == 3
    assert sum(row["decision"] == "unresolved" for row in decisions) == 3
    for receipt in decisions:
        assert receipt["role_title"]
        assert receipt["company_name"]
        assert receipt["vacancy_description_sha256"]
        assert (
            receipt["duplicate_snapshot_sha256"]
            == document["duplicate_snapshot_sha256"]
        )
        assert receipt["evidence_matrix"]
        assert all(row["requirement_text"] for row in receipt["evidence_matrix"])
        if receipt["decision"] == "eligible":
            assert receipt["fit"] == fit_from_evidence_matrix(
                receipt["evidence_matrix"]
            )
        else:
            assert receipt["fit"] is None


def _write_canonical_discovery(path: Path, discovery: dict) -> Path:
    path.write_text(
        json.dumps(discovery, sort_keys=True, separators=(",", ":")) + "\n"
    )
    return path


def test_materializer_accepts_terminally_observed_cohort_shrinkage(
    tmp_path: Path,
) -> None:
    _require_complete_private_authority_inputs()
    discovery = deepcopy(json.loads(PRODUCTION_DISCOVERY_PATH.read_bytes()))
    removed = discovery["live_pending_eligibility"].pop()
    observation = next(
        row for row in discovery["observations"]
        if row["job_key"] == removed["job_key"]
    )
    observation["verdict"] = {
        "active_markers": [],
        "closed_markers": [],
        "live": False,
        "reason": "requisition_identity_mismatch",
        "requisition_bound": False,
        "title_bound": False,
    }
    discovery_path = _write_canonical_discovery(
        tmp_path / "shrunk-discovery.json", discovery
    )
    archive = tmp_path / "archive"
    archive.mkdir()

    result = materialize_candidate_authority(
        discovery_path=discovery_path,
        archive_root=archive,
        repository_root=Path.cwd(),
    )

    decision_keys = {row["job_key"] for row in result.document["decisions"]}
    assert removed["job_key"] not in decision_keys
    assert len(decision_keys) == 20


def test_materializer_rejects_silent_cohort_shrinkage(tmp_path: Path) -> None:
    _require_complete_private_authority_inputs()
    discovery = deepcopy(json.loads(PRODUCTION_DISCOVERY_PATH.read_bytes()))
    discovery["live_pending_eligibility"].pop()
    discovery_path = _write_canonical_discovery(
        tmp_path / "silently-shrunk-discovery.json", discovery
    )

    with pytest.raises(ValueError, match="without terminal evidence"):
        materialize_candidate_authority(
            discovery_path=discovery_path,
            archive_root=tmp_path,
            repository_root=Path.cwd(),
        )


def test_materializer_rejects_unknown_pending_vacancy(tmp_path: Path) -> None:
    _require_complete_private_authority_inputs()
    discovery = deepcopy(json.loads(PRODUCTION_DISCOVERY_PATH.read_bytes()))
    unknown = deepcopy(discovery["live_pending_eligibility"][0])
    unknown["job_key"] = "greenhouse:unknown:999999"
    discovery["live_pending_eligibility"].append(unknown)
    discovery_path = _write_canonical_discovery(
        tmp_path / "unknown-discovery.json", discovery
    )

    with pytest.raises(ValueError, match="differs from approved policy"):
        materialize_candidate_authority(
            discovery_path=discovery_path,
            archive_root=tmp_path,
            repository_root=Path.cwd(),
        )


def test_materializer_is_deterministic_and_create_only(tmp_path: Path) -> None:
    _require_complete_private_authority_inputs()
    first = materialize_candidate_authority(
        discovery_path=PRODUCTION_DISCOVERY_PATH,
        archive_root=tmp_path,
        repository_root=Path.cwd(),
    )
    second = materialize_candidate_authority(
        discovery_path=PRODUCTION_DISCOVERY_PATH,
        archive_root=tmp_path,
        repository_root=Path.cwd(),
    )
    assert second.sha256 == first.sha256
    assert second.value == first.value

    first.authority_path.unlink()
    first.authority_path.symlink_to(PRODUCTION_DISCOVERY_PATH)
    with pytest.raises(ValueError, match="create-only"):
        materialize_candidate_authority(
            discovery_path=PRODUCTION_DISCOVERY_PATH,
            archive_root=tmp_path,
            repository_root=Path.cwd(),
        )


def test_materializer_rejects_mutated_candidate_source(tmp_path: Path) -> None:
    _require_complete_private_authority_inputs()
    sources = CandidateAuthoritySources()
    mutated = tmp_path / "approved-evidence.json"
    mutated.write_bytes(sources.approved_evidence.read_bytes() + b"\n")
    archive = tmp_path / "archive"
    archive.mkdir()

    with pytest.raises(ValueError, match="approved_evidence"):
        materialize_candidate_authority(
            discovery_path=PRODUCTION_DISCOVERY_PATH,
            archive_root=archive,
            repository_root=Path.cwd(),
            sources=CandidateAuthoritySources(approved_evidence=mutated),
        )


def test_materializer_rejects_symlinked_archive_namespace(tmp_path: Path) -> None:
    _require_complete_private_authority_inputs()
    archive = tmp_path / "archive"
    external = tmp_path / "external"
    archive.mkdir()
    external.mkdir()
    (archive / "objects").symlink_to(external, target_is_directory=True)

    with pytest.raises(ValueError, match="parent cannot be a symlink"):
        materialize_candidate_authority(
            discovery_path=PRODUCTION_DISCOVERY_PATH,
            archive_root=archive,
            repository_root=Path.cwd(),
        )
    assert not tuple(external.iterdir())


def test_materializer_discards_legacy_numeric_fit(tmp_path: Path) -> None:
    _require_complete_private_authority_inputs()
    result = materialize_candidate_authority(
        discovery_path=PRODUCTION_DISCOVERY_PATH,
        archive_root=tmp_path,
        repository_root=Path.cwd(),
    )
    discovery = json.loads(PRODUCTION_DISCOVERY_PATH.read_bytes())
    old_fit = {
        row["job_key"]: row["fit"] for row in discovery["live_pending_eligibility"]
    }
    eligible = [
        row["receipt"]
        for row in result.document["decisions"]
        if row["receipt"]["decision"] == "eligible"
    ]
    assert any(receipt["fit"] != old_fit[receipt["job_key"]] for receipt in eligible)
    assert all(
        receipt["fit"] == fit_from_evidence_matrix(receipt["evidence_matrix"])
        for receipt in eligible
    )


import career_automation.candidate_authority as cohort_authority

_APPROVED = {"synthetic-alpha", "synthetic-beta"}
_TERMINAL_REASONS = frozenset({"synthetic_vacancy_closed", "synthetic_identity_lost"})
_THIS = cohort_authority


class _SourceBoundarySentinel(RuntimeError):
    pass


def _synthetic_pending(job_key, sha):
    return {
        "job_key": job_key,
        "vacancy_sha256": sha,
        "source_url": f"https://synthetic.invalid/vacancies/{job_key}",
        "role_title": f"Synthetic Role {job_key}",
        "company_name": "Synthetic Company",
    }


def _synthetic_live_observation(job_key, sha):
    return {
        "job_key": job_key,
        "body_sha256": sha,
        "requested_url": f"https://synthetic.invalid/vacancies/{job_key}",
        "role_title": f"Synthetic Role {job_key}",
        "company_name": "Synthetic Company",
        "verdict": {
            "live": True,
            "reason": "live_application_form_observed",
            "requisition_bound": True,
            "title_bound": True,
        },
    }


def _synthetic_terminal_observation(job_key, sha, reason="synthetic_vacancy_closed"):
    return {
        "job_key": job_key,
        "body_sha256": sha,
        "requested_url": f"https://synthetic.invalid/vacancies/{job_key}",
        "role_title": f"Synthetic Role {job_key}",
        "company_name": "Synthetic Company",
        "verdict": {
            "live": False,
            "reason": reason,
            "requisition_bound": True,
            "title_bound": True,
            "closed_markers": ["synthetic_closed_banner"],
        },
    }


def _synthetic_discovery(pending, observations, **overrides):
    document = {
        "schema_version": "jaa.greenhouse-live-discovery.v2",
        "eligibility_authority": False,
        "ranking_candidate_profile": "empty",
        "live_pending_eligibility": pending,
        "observations": observations,
    }
    document.update(overrides)
    return document


def _full_live_discovery():
    return _synthetic_discovery(
        pending=[
            _synthetic_pending("synthetic-alpha", "a" * 64),
            _synthetic_pending("synthetic-beta", "b" * 64),
        ],
        observations=[
            _synthetic_live_observation("synthetic-alpha", "a" * 64),
            _synthetic_live_observation("synthetic-beta", "b" * 64),
        ],
    )


def _terminal_shrink_discovery():
    return _synthetic_discovery(
        pending=[_synthetic_pending("synthetic-alpha", "a" * 64)],
        observations=[
            _synthetic_live_observation("synthetic-alpha", "a" * 64),
            _synthetic_terminal_observation("synthetic-beta", "b" * 64),
        ],
    )


def _patch_cohort(monkeypatch):
    monkeypatch.setattr(_THIS, "APPROVED_COHORT", _APPROVED)
    monkeypatch.setattr(_THIS, "TERMINAL_DISCOVERY_REASONS", _TERMINAL_REASONS)


def test_synthetic_cohort_valid_full_live_cohort_is_accepted(monkeypatch):
    _patch_cohort(monkeypatch)
    discovery = _full_live_discovery()
    pending_by_key = cohort_authority._validated_pending_cohort(
        discovery, discovery["live_pending_eligibility"]
    )
    assert set(pending_by_key) == _APPROVED


def test_synthetic_cohort_full_live_cohort_tolerates_foreign_observations(monkeypatch):
    _patch_cohort(monkeypatch)
    discovery = _full_live_discovery()
    discovery["observations"].append(
        _synthetic_live_observation("synthetic-foreign", "f" * 64)
    )
    pending_by_key = cohort_authority._validated_pending_cohort(
        discovery, discovery["live_pending_eligibility"]
    )
    assert set(pending_by_key) == _APPROVED


def test_synthetic_cohort_terminal_shrink_is_accepted(monkeypatch):
    _patch_cohort(monkeypatch)
    discovery = _terminal_shrink_discovery()
    pending_by_key = cohort_authority._validated_pending_cohort(
        discovery, discovery["live_pending_eligibility"]
    )
    assert set(pending_by_key) == {"synthetic-alpha"}


def test_synthetic_cohort_terminal_shrink_via_identity_failure_is_accepted(monkeypatch):
    _patch_cohort(monkeypatch)
    observation = _synthetic_terminal_observation("synthetic-beta", "b" * 64)
    observation["verdict"]["closed_markers"] = []
    observation["verdict"]["requisition_bound"] = False
    observation["verdict"]["reason"] = "synthetic_identity_lost"
    discovery = _synthetic_discovery(
        pending=[_synthetic_pending("synthetic-alpha", "a" * 64)],
        observations=[
            _synthetic_live_observation("synthetic-alpha", "a" * 64),
            observation,
        ],
    )
    assert cohort_authority._validated_pending_cohort(
        discovery, discovery["live_pending_eligibility"]
    ) == {"synthetic-alpha": discovery["live_pending_eligibility"][0]}


def test_synthetic_cohort_duplicate_pending_rows_are_rejected(monkeypatch):
    _patch_cohort(monkeypatch)
    discovery = _full_live_discovery()
    pending = list(discovery["live_pending_eligibility"])
    pending.append(deepcopy(pending[0]))
    with pytest.raises(ValueError, match="duplicate candidate vacancies"):
        cohort_authority._validated_pending_cohort(discovery, pending)


def test_synthetic_cohort_duplicate_observations_are_rejected(monkeypatch):
    _patch_cohort(monkeypatch)
    discovery = _full_live_discovery()
    discovery["observations"].append(deepcopy(discovery["observations"][0]))
    with pytest.raises(ValueError, match="duplicate observations"):
        cohort_authority._validated_pending_cohort(discovery, discovery["live_pending_eligibility"])


def test_synthetic_cohort_missing_observations_list_is_rejected(monkeypatch):
    _patch_cohort(monkeypatch)
    discovery = _full_live_discovery()
    del discovery["observations"]
    with pytest.raises(ValueError, match="observations are missing"):
        cohort_authority._validated_pending_cohort(discovery, discovery["live_pending_eligibility"])


def test_synthetic_cohort_omitted_observation_is_rejected(monkeypatch):
    _patch_cohort(monkeypatch)
    discovery = _full_live_discovery()
    discovery["observations"] = [
        row for row in discovery["observations"] if row["job_key"] != "synthetic-beta"
    ]
    with pytest.raises(ValueError, match="silently omits approved vacancies"):
        cohort_authority._validated_pending_cohort(discovery, discovery["live_pending_eligibility"])


def test_synthetic_cohort_silent_removal_with_live_observation_is_rejected(monkeypatch):
    _patch_cohort(monkeypatch)
    discovery = _full_live_discovery()
    discovery["live_pending_eligibility"] = [
        row
        for row in discovery["live_pending_eligibility"]
        if row["job_key"] != "synthetic-beta"
    ]
    with pytest.raises(ValueError, match="without terminal evidence"):
        cohort_authority._validated_pending_cohort(discovery, discovery["live_pending_eligibility"])


def test_synthetic_cohort_silent_removal_without_closed_markers_or_identity_failure_is_rejected(
    monkeypatch,
):
    _patch_cohort(monkeypatch)
    observation = _synthetic_terminal_observation("synthetic-beta", "b" * 64)
    observation["verdict"]["closed_markers"] = []
    discovery = _synthetic_discovery(
        pending=[_synthetic_pending("synthetic-alpha", "a" * 64)],
        observations=[
            _synthetic_live_observation("synthetic-alpha", "a" * 64),
            observation,
        ],
    )
    with pytest.raises(ValueError, match="without terminal evidence"):
        cohort_authority._validated_pending_cohort(discovery, discovery["live_pending_eligibility"])


@pytest.mark.parametrize(
    ("live", "reason"),
    [
        (True, "synthetic_vacancy_closed"),
        (False, "unrecognized_synthetic_reason"),
    ],
)
def test_synthetic_cohort_terminal_observation_with_wrong_live_or_reason_is_rejected(monkeypatch, live, reason):
    _patch_cohort(monkeypatch)
    observation = _synthetic_terminal_observation("synthetic-beta", "b" * 64)
    observation["verdict"]["reason"] = reason
    observation["verdict"]["live"] = live
    discovery = _synthetic_discovery(
        pending=[_synthetic_pending("synthetic-alpha", "a" * 64)],
        observations=[
            _synthetic_live_observation("synthetic-alpha", "a" * 64),
            observation,
        ],
    )
    with pytest.raises(ValueError, match="without terminal evidence"):
        cohort_authority._validated_pending_cohort(discovery, discovery["live_pending_eligibility"])


@pytest.mark.parametrize(
    ("mutation", "field"),
    [
        (lambda row: row.update({"vacancy_sha256": "0" * 64}), "hash"),
        (
            lambda row: row.update({"source_url": "https://synthetic.invalid/other"}),
            "url",
        ),
        (lambda row: row.update({"role_title": "Other Synthetic Role"}), "title"),
        (lambda row: row.update({"company_name": "Other Synthetic Co"}), "company"),
    ],
)
def test_synthetic_cohort_pending_observation_mismatch_is_rejected(monkeypatch, mutation, field):
    _patch_cohort(monkeypatch)
    discovery = _full_live_discovery()
    row = discovery["live_pending_eligibility"][0]
    before = deepcopy(row)
    mutation(row)
    assert row != before
    with pytest.raises(ValueError, match="differs from its network observation"):
        cohort_authority._validated_pending_cohort(discovery, discovery["live_pending_eligibility"])


def test_synthetic_cohort_pending_observation_company_casefold_mismatch_only_is_accepted(monkeypatch):
    _patch_cohort(monkeypatch)
    discovery = _full_live_discovery()
    discovery["observations"][0]["company_name"] = "  SYNTHETIC COMPANY  "
    assert set(
        cohort_authority._validated_pending_cohort(discovery, discovery["live_pending_eligibility"])
    ) == _APPROVED


def test_synthetic_cohort_live_observation_verdict_not_mapping_is_rejected(monkeypatch):
    _patch_cohort(monkeypatch)
    discovery = _full_live_discovery()
    discovery["observations"][0]["verdict"] = ["not", "a", "mapping"]
    with pytest.raises(ValueError, match="verdict is malformed"):
        cohort_authority._validated_pending_cohort(discovery, discovery["live_pending_eligibility"])


@pytest.mark.parametrize(
    "build",
    [
        _full_live_discovery,
        _terminal_shrink_discovery,
    ],
)
def test_synthetic_cohort_entrypoint_valid_discovery_reaches_source_boundary(
    tmp_path, monkeypatch, build
):
    _patch_cohort(monkeypatch)
    archive_root = tmp_path / "archive"
    repository_root = tmp_path / "repository"
    archive_root.mkdir()
    repository_root.mkdir()
    discovery_path = tmp_path / "discovery.json"
    discovery_path.write_bytes(cohort_authority._json_bytes(build()))

    def _sentinel_source_bytes(sources):
        raise _SourceBoundarySentinel("validated discovery reached private-source boundary")

    monkeypatch.setattr(_THIS, "_source_bytes", _sentinel_source_bytes)
    with pytest.raises(_SourceBoundarySentinel):
        cohort_authority.build_candidate_authority_document(
            discovery_path=discovery_path,
            archive_root=archive_root,
            repository_root=repository_root,
        )


def test_synthetic_cohort_entrypoint_duplicate_pending_rejected_before_boundary(tmp_path, monkeypatch):
    _patch_cohort(monkeypatch)
    archive_root = tmp_path / "archive"
    repository_root = tmp_path / "repository"
    archive_root.mkdir()
    repository_root.mkdir()
    discovery = _full_live_discovery()
    discovery["live_pending_eligibility"].append(
        deepcopy(discovery["live_pending_eligibility"][0])
    )
    discovery_path = tmp_path / "discovery.json"
    discovery_path.write_bytes(cohort_authority._json_bytes(discovery))

    def _sentinel_source_bytes(sources):
        raise _SourceBoundarySentinel("must not reach private-source boundary")

    monkeypatch.setattr(_THIS, "_source_bytes", _sentinel_source_bytes)
    with pytest.raises(ValueError, match="duplicate candidate vacancies"):
        cohort_authority.build_candidate_authority_document(
            discovery_path=discovery_path,
            archive_root=archive_root,
            repository_root=repository_root,
        )


def test_synthetic_cohort_entrypoint_non_canonical_json_rejected_before_boundary(tmp_path, monkeypatch):
    _patch_cohort(monkeypatch)
    archive_root = tmp_path / "archive"
    repository_root = tmp_path / "repository"
    archive_root.mkdir()
    repository_root.mkdir()
    discovery_path = tmp_path / "discovery.json"
    discovery_path.write_bytes(
        json.dumps(_full_live_discovery(), indent=2).encode()
    )

    def _sentinel_source_bytes(sources):
        raise _SourceBoundarySentinel("must not reach private-source boundary")

    monkeypatch.setattr(_THIS, "_source_bytes", _sentinel_source_bytes)
    with pytest.raises(ValueError, match="not canonical JSON"):
        cohort_authority.build_candidate_authority_document(
            discovery_path=discovery_path,
            archive_root=archive_root,
            repository_root=repository_root,
        )
