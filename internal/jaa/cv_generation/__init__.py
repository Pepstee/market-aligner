"""Public CV-generation boundary for JAA.

Callers should import CV construction and policy from this package.  The
``career_automation`` imports retained behind :mod:`cv_generation.service` are
temporary compatibility seams, not part of the public API.
"""

from .constraints import (
    ARTIOM_GUTU_CV_POLICY,
    BASE_CV_POLICY,
    CVConstraintError,
    CVConstraintReceipt,
    CVPolicy,
    policy_for_candidate,
    validate_generated_cv,
)
from .adversarial_rebuild import (
    AdversarialRebuildError,
    AppliedRecruiterImprovement,
    EvidenceSafeRebuildResult,
    FinalizedRebuiltCV,
    RebuildRoadmapItem,
    RecruiterImprovementBinding,
    bind_recruiter_improvement,
    finalize_rebuilt_cv,
    rebuild_from_recruiter_assessment,
    render_editorial_cv_text,
)
from .editorial_composition import (
    ApprovedCVClaim,
    CVEditorialDraft,
    CVEditorialRequest,
    CVSection,
    CandidateEditorialAuthority,
    EditorialAtom,
    EditorialCompositionError,
    EditorialCompositionReceipt,
    EditorialStageEvidence,
    EditorialStageReceipt,
    admit_editorial_composition,
    build_editorial_draft,
    build_editorial_request,
    humanizer_request_sha256,
    validate_editorial_draft,
)
from .document_quality import (
    DocumentQualityError,
    DocumentQualityReceipt,
    PdfQualityResult,
    PopplerRuntime,
    QUALITY_POLICY_SHA256,
    resolve_poppler_runtime,
    verify_document_quality,
)


_SERVICE_EXPORTS = frozenset(
    {
        "CVCompositionOrchestrationResult",
        "CVCompositionServiceError",
        "ImprovementBinder",
        "RecruiterAssessor",
        "run_cv_composition_orchestration",
    }
)


def __getattr__(name: str) -> object:
    """Load the orchestration facade only when a caller asks for it.

    ``candidate_application_factory`` depends on the constraints submodule.
    Eagerly importing the service facade from this package initializer would
    re-enter that partially initialized factory.  The facade remains part of
    the public API, but its compatibility dependency is now loaded lazily.
    """

    if name not in _SERVICE_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from . import service

    for export in _SERVICE_EXPORTS:
        globals()[export] = getattr(service, export)
    return globals()[name]


def __dir__() -> list[str]:
    return sorted((*globals(), *_SERVICE_EXPORTS))

__all__ = [
    "ARTIOM_GUTU_CV_POLICY",
    "AdversarialRebuildError",
    "AppliedRecruiterImprovement",
    "ApprovedCVClaim",
    "BASE_CV_POLICY",
    "CVConstraintError",
    "CVConstraintReceipt",
    "CVCompositionOrchestrationResult",
    "CVCompositionServiceError",
    "CVEditorialDraft",
    "CVEditorialRequest",
    "CVPolicy",
    "CVSection",
    "CandidateEditorialAuthority",
    "EditorialAtom",
    "EditorialCompositionError",
    "EditorialCompositionReceipt",
    "EditorialStageEvidence",
    "EditorialStageReceipt",
    "EvidenceSafeRebuildResult",
    "FinalizedRebuiltCV",
    "DocumentQualityError",
    "DocumentQualityReceipt",
    "ImprovementBinder",
    "PdfQualityResult",
    "PopplerRuntime",
    "QUALITY_POLICY_SHA256",
    "RebuildRoadmapItem",
    "RecruiterImprovementBinding",
    "RecruiterAssessor",
    "admit_editorial_composition",
    "build_editorial_draft",
    "build_editorial_request",
    "bind_recruiter_improvement",
    "finalize_rebuilt_cv",
    "humanizer_request_sha256",
    "policy_for_candidate",
    "rebuild_from_recruiter_assessment",
    "render_editorial_cv_text",
    "resolve_poppler_runtime",
    "run_cv_composition_orchestration",
    "validate_editorial_draft",
    "validate_generated_cv",
    "verify_document_quality",
]
