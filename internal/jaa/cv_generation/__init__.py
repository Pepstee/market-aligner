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
    CoverLetterEvidenceSafeRebuildResult,
    CoverLetterRecruiterImprovementBinding,
    EvidenceSafeRebuildResult,
    FinalizedRebuiltCV,
    RebuildRoadmapItem,
    RecruiterImprovementBinding,
    bind_cover_letter_recruiter_improvement,
    bind_recruiter_improvement,
    finalize_rebuilt_cv,
    rebuild_cover_letter_from_recruiter_assessment,
    rebuild_from_recruiter_assessment,
    render_editorial_cv_text,
)
from .editorial_composition import (
    ApprovedCoverLetterClaim,
    ApprovedCVClaim,
    CVEditorialDraft,
    CVEditorialRequest,
    CVSection,
    CandidateEditorialAuthority,
    CoverLetterEditorialCompositionReceipt,
    CoverLetterEditorialDraft,
    CoverLetterEditorialRequest,
    CoverLetterSection,
    EditorialAtom,
    EditorialCompositionError,
    EditorialCompositionReceipt,
    EditorialStageEvidence,
    EditorialStageReceipt,
    admit_cover_letter_editorial_composition,
    admit_editorial_composition,
    build_cover_letter_editorial_draft,
    build_cover_letter_editorial_request,
    build_editorial_draft,
    build_editorial_request,
    cover_letter_humanizer_request_sha256,
    humanizer_request_sha256,
    run_cover_letter_composition_runtime,
    validate_cover_letter_editorial_draft,
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
from .benchmark_learning import (
    CVBenchmarkDiagnosticReceipt,
    CVBenchmarkEntry,
    CVBenchmarkError,
    CVBenchmarkFeatures,
    CVBenchmarkManifest,
    build_benchmark_manifest,
    evaluate_cv_benchmark,
    extract_cv_features,
    load_benchmark_manifest,
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
    "ApprovedCoverLetterClaim",
    "ApprovedCVClaim",
    "BASE_CV_POLICY",
    "CVConstraintError",
    "CVConstraintReceipt",
    "CVBenchmarkDiagnosticReceipt",
    "CVBenchmarkEntry",
    "CVBenchmarkError",
    "CVBenchmarkFeatures",
    "CVBenchmarkManifest",
    "CVCompositionOrchestrationResult",
    "CVCompositionServiceError",
    "CVEditorialDraft",
    "CVEditorialRequest",
    "CVPolicy",
    "CVSection",
    "CandidateEditorialAuthority",
    "CoverLetterEditorialCompositionReceipt",
    "CoverLetterEditorialDraft",
    "CoverLetterEditorialRequest",
    "CoverLetterEvidenceSafeRebuildResult",
    "CoverLetterRecruiterImprovementBinding",
    "CoverLetterSection",
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
    "admit_cover_letter_editorial_composition",
    "admit_editorial_composition",
    "bind_cover_letter_recruiter_improvement",
    "build_cover_letter_editorial_draft",
    "build_cover_letter_editorial_request",
    "build_editorial_draft",
    "build_benchmark_manifest",
    "build_editorial_request",
    "bind_recruiter_improvement",
    "cover_letter_humanizer_request_sha256",
    "finalize_rebuilt_cv",
    "humanizer_request_sha256",
    "evaluate_cv_benchmark",
    "extract_cv_features",
    "load_benchmark_manifest",
    "policy_for_candidate",
    "rebuild_cover_letter_from_recruiter_assessment",
    "rebuild_from_recruiter_assessment",
    "render_editorial_cv_text",
    "resolve_poppler_runtime",
    "run_cover_letter_composition_runtime",
    "run_cv_composition_orchestration",
    "validate_cover_letter_editorial_draft",
    "validate_editorial_draft",
    "validate_generated_cv",
    "verify_document_quality",
]
