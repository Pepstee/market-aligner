"""Public form-filling boundary for JAA.

This module owns provider-field binding and browser execution.  It consumes
approved application artifacts; it does not compose or rewrite CV content.
"""

from .ats_forensics import (
    ATSForensicReceipt,
    ATSForensicRecorder,
    verify_forensic_receipt,
)
from .provider_diagnostics import (
    ASHBY_DIAGNOSTIC_POLICY,
    WORKABLE_DIAGNOSTIC_POLICY,
    ProviderDiagnosticObservation,
    ProviderDiagnosticPolicy,
    inspect_provider_page,
)
from .service import (
    ProductionFormBindingError,
    approved_authority_values,
    approved_form_mapping_bytes,
)

__all__ = [
    "ASHBY_DIAGNOSTIC_POLICY",
    "WORKABLE_DIAGNOSTIC_POLICY",
    "ATSForensicReceipt",
    "ATSForensicRecorder",
    "ProductionFormBindingError",
    "ProviderDiagnosticObservation",
    "ProviderDiagnosticPolicy",
    "approved_authority_values",
    "approved_form_mapping_bytes",
    "inspect_provider_page",
    "verify_forensic_receipt",
]
