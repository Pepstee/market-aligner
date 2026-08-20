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

__all__ = [
    "ARTIOM_GUTU_CV_POLICY",
    "ApprovedCVClaim",
    "BASE_CV_POLICY",
    "CVConstraintError",
    "CVConstraintReceipt",
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
    "admit_editorial_composition",
    "build_editorial_draft",
    "build_editorial_request",
    "humanizer_request_sha256",
    "policy_for_candidate",
    "validate_editorial_draft",
    "validate_generated_cv",
]
