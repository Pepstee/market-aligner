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

__all__ = [
    "ARTIOM_GUTU_CV_POLICY",
    "BASE_CV_POLICY",
    "CVConstraintError",
    "CVConstraintReceipt",
    "CVPolicy",
    "policy_for_candidate",
    "validate_generated_cv",
]
