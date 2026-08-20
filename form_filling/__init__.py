"""Public form-filling boundary for JAA.

This module owns provider-field binding and browser execution.  It consumes
approved application artifacts; it does not compose or rewrite CV content.
"""

from .service import (
    ProductionFormBindingError,
    approved_authority_values,
    approved_form_mapping_bytes,
)

__all__ = [
    "ProductionFormBindingError",
    "approved_authority_values",
    "approved_form_mapping_bytes",
]
