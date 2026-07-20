"""Versioned career-pipeline blueprints and least-privilege backend manifests."""

from __future__ import annotations

from .observability import ComponentContract, ComponentDefinition, FlowDefinition, FlowStep
from .security import (
    BackendCapabilityManifest,
    CapabilityAuthorizer,
    CapabilityGrant,
)


BORROWED_REVISIONS = {
    "coolify": "e7dff30b7c998c301fd91bd169727b90c59ec291",
    "openhands": "11d4ecf21fc144d10a614ddba63b84de5c90bfd4",
    "maxun": "ca3138a2dbc81564d16d1cf1beca2b52bef96104",
    "open_webui": "ecd48e2f718220a6400ecf49eafd4867a38feb10",
    "browser_use": "950eb03617e67548d759c02beac1ad122c6b6458",
    "langflow": "54281f7cef4f57de25ab0c0a69f6402f6236fbbc",
    "supabase": "fc72a6b25920dce4ab012d41f9400c14ae9a72d5",
    "stirling_pdf": "8b179fbc55d7bb912c98bec5423ed268b042b9dc",
    "crawl4ai": "7e801521428ee12509994d39151006f64055ebe3",
    "dify": "5ea884f799d3279655b72a4eadf804bd95dbf433",
    "scrapling": "5320319155127519b46c0d35cc7a5037b936af05",
}


def _contract(
    required_inputs: tuple[str, ...],
    required_outputs: tuple[str, ...],
    *,
    side_effects: tuple[str, ...] = (),
) -> ComponentContract:
    def schema(required: tuple[str, ...]) -> dict:
        return {
            "type": "object",
            "required": list(required),
            "additionalProperties": True,
        }

    return ComponentContract(
        input_schema=schema(required_inputs),
        output_schema=schema(required_outputs),
        side_effects=side_effects,
    )


def career_pipeline_flow() -> FlowDefinition:
    """Return the content-addressed, current orchestration contract.

    This definition records ordering and side-effect boundaries.  It does not
    replace the deterministic state machine, which remains authoritative.
    """
    components = (
        ComponentDefinition(
            "viability", "career.viability", "1.0.0", "deterministic",
            _contract(("raw_job_id",), ("viable", "reasons")),
        ),
        ComponentDefinition(
            "opportunity_gate", "career.opportunity_gate", "1.0.0", "deterministic",
            _contract(("job_snapshot_hash", "opportunity_axes"), ("decision", "priority"), side_effects=("queue.write",)),
        ),
        ComponentDefinition(
            "employer_research", "career.employer_research", "1.0.0", "probabilistic",
            _contract(("job_snapshot_hash", "source_policy_hash"), ("dossier_hash", "source_ids"), side_effects=("network.public_read", "dossier.write")),
        ),
        ComponentDefinition(
            "evidence_match", "career.evidence_match", "1.0.0", "probabilistic",
            _contract(("requirement_ids", "evidence_projection_hash"), ("matches", "gaps")),
        ),
        ComponentDefinition(
            "application_draft", "career.application_draft", "1.0.0", "probabilistic",
            _contract(("requirement_ids", "approved_evidence_ids", "dossier_hash"), ("draft_hash", "claim_ids"), side_effects=("application.write",)),
        ),
        ComponentDefinition(
            "style_critic", "career.style_critic", "1.0.0", "probabilistic",
            _contract(("draft_hash", "voice_projection_hash"), ("atomic_edit_proposals",)),
        ),
        ComponentDefinition(
            "release_validate", "career.release_validate", "1.0.0", "deterministic",
            _contract(("draft_hash", "claim_ids", "requirement_ids"), ("release_manifest_hash", "release_gate_token"), side_effects=("release.write",)),
        ),
        ComponentDefinition(
            "submit", "career.submit", "1.0.0", "external",
            _contract(("release_manifest_hash", "release_gate_token"), ("receipt_hash",), side_effects=("browser.interact", "application.submit")),
        ),
    )
    steps = (
        FlowStep("verify_job", "viability"),
        FlowStep("admit_opportunity", "opportunity_gate", depends_on=("verify_job",)),
        FlowStep("research_employer", "employer_research", depends_on=("admit_opportunity",)),
        FlowStep("match_evidence", "evidence_match", depends_on=("research_employer",)),
        FlowStep("draft_application", "application_draft", depends_on=("match_evidence",)),
        FlowStep("critique_style", "style_critic", depends_on=("draft_application",)),
        FlowStep("validate_release", "release_validate", depends_on=("critique_style",)),
        FlowStep("submit_application", "submit", depends_on=("validate_release",)),
    )
    return FlowDefinition(
        flow_id="career.application.pipeline",
        version="1.1.0",
        components=components,
        steps=steps,
        metadata={
            "canonical_state_authority": "career_automation.database.CareerDatabase",
            "probabilistic_output_advances_state": False,
            "borrowed_revisions": BORROWED_REVISIONS,
        },
    )


def backend_capability_authorizer() -> CapabilityAuthorizer:
    """Return the default-deny capability boundary for pipeline workers."""
    manifests = (
        BackendCapabilityManifest(
            "collector",
            (
                CapabilityGrant("network.public_read", ("web/jobs/*",)),
                CapabilityGrant("network.challenge_solve", ("web/jobs/*",)),
                CapabilityGrant("proxy.rotate", ("web/jobs/*",)),
                CapabilityGrant("browser.dynamic", ("web/jobs/*",)),
                CapabilityGrant("browser.stealth", ("web/jobs/*",)),
                CapabilityGrant("browser.cdp_connect", ("browser/cdp/*",)),
                CapabilityGrant("browser.page_hook", ("browser/hooks/*",)),
                CapabilityGrant("snapshot.write", ("jobs/raw/*",)),
            ),
        ),
        BackendCapabilityManifest(
            "employer-research",
            (
                CapabilityGrant("network.public_read", ("web/employers/*",)),
                CapabilityGrant("job.read", ("jobs/opportunity-admitted/*",)),
                CapabilityGrant("dossier.write", ("employer-dossiers/*",)),
            ),
        ),
        BackendCapabilityManifest(
            "evidence-retriever",
            (CapabilityGrant("evidence.read", ("evidence/projections/*",)),),
        ),
        BackendCapabilityManifest(
            "style-critic",
            (
                CapabilityGrant("application.read", ("applications/drafts/*",)),
                CapabilityGrant("evidence.read", ("evidence/projections/*",)),
                CapabilityGrant("edit-proposal.write", ("applications/edit-proposals/*",)),
            ),
        ),
        BackendCapabilityManifest(
            "submission-browser",
            (
                CapabilityGrant("release.read", ("applications/releases/*",)),
                CapabilityGrant("browser.interact", ("application-forms/*",)),
                CapabilityGrant("application.submit", ("applications/releases/*",)),
                CapabilityGrant("receipt.write", ("applications/receipts/*",)),
            ),
        ),
    )
    return CapabilityAuthorizer(manifests)


__all__ = [
    "BORROWED_REVISIONS",
    "backend_capability_authorizer",
    "career_pipeline_flow",
]
