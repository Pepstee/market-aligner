"""Autonomous career-application control plane.

This package consumes the scraper/scorer outputs.  It deliberately does not
own collection or LLM extraction; its responsibility is durable state,
deterministic policy, queues, provenance, and outcome tracking.
"""

from .database import CareerDatabase
from .blueprints import backend_capability_authorizer, career_pipeline_flow
from .browser_workflows import BrowserWorkflowStore
from .deployment import DeploymentStore
from .documents import DocumentSidecarPolicy
from .engine import OpportunityGate, OpportunityPolicy
from .fetching import FetchControlStore, default_job_fetch_policy
from .migrations import MigrationRunner
from .models import ActorKind, PipelineState
from .observability import ObservabilityStore
from .retrieval import HybridEvidenceIndex
from .security import OutboundURLPolicy

__all__ = [
    "ActorKind",
    "BrowserWorkflowStore",
    "CareerDatabase",
    "DeploymentStore",
    "DocumentSidecarPolicy",
    "FetchControlStore",
    "HybridEvidenceIndex",
    "MigrationRunner",
    "ObservabilityStore",
    "OpportunityGate",
    "OpportunityPolicy",
    "OutboundURLPolicy",
    "PipelineState",
    "backend_capability_authorizer",
    "career_pipeline_flow",
    "default_job_fetch_policy",
]
