"""Autonomous career-application control plane.

This package consumes the scraper/scorer outputs.  It deliberately does not
own collection or LLM extraction; its responsibility is durable state,
deterministic policy, queues, provenance, and outcome tracking.
"""

from .database import CareerDatabase
from .candidate_graph import CandidateGraph, WorkRightResolution
from .blueprints import backend_capability_authorizer, career_pipeline_flow
from .browser_workflows import BrowserWorkflowStore
from .deployment import DeploymentStore
from .documents import DocumentSidecarPolicy
from .engine import OpportunityGate, OpportunityPolicy
from .fetching import FetchControlStore, default_job_fetch_policy
from .migrations import (
    JAA_01_MIGRATIONS, JAA_02_MIGRATIONS, MigrationRunner,
    apply_jaa_01_migrations, apply_jaa_02_migrations,
)
from .lifecycle import (
    LEGAL_TRANSITIONS, IdempotencyConflict, InvalidTransition, LedgerDivergence, LifecycleError,
    LifecycleReducer, ModelIdentity, PolicyIdentity, TransitionReceipt,
    canonical_hash, canonical_json,
)
from .models import ActorKind, PipelineState
from .observability import ObservabilityStore
from .retrieval import HybridEvidenceIndex
from .security import OutboundURLPolicy

__all__ = [
    "ActorKind",
    "BrowserWorkflowStore",
    "CareerDatabase",
    "CandidateGraph",
    "DeploymentStore",
    "DocumentSidecarPolicy",
    "FetchControlStore",
    "HybridEvidenceIndex",
    "JAA_01_MIGRATIONS",
    "JAA_02_MIGRATIONS",
    "LEGAL_TRANSITIONS",
    "LifecycleReducer",
    "LifecycleError",
    "PolicyIdentity",
    "ModelIdentity",
    "TransitionReceipt",
    "InvalidTransition",
    "IdempotencyConflict",
    "LedgerDivergence",
    "MigrationRunner",
    "ObservabilityStore",
    "OpportunityGate",
    "OpportunityPolicy",
    "OutboundURLPolicy",
    "PipelineState",
    "backend_capability_authorizer",
    "apply_jaa_01_migrations",
    "apply_jaa_02_migrations",
    "career_pipeline_flow",
    "canonical_hash",
    "canonical_json",
    "default_job_fetch_policy",
    "WorkRightResolution",
]
