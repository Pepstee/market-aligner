"""Verified, non-destructive adoption of the frozen JAA-00 SQLite baseline."""

from .core import (
    AdoptionError,
    adopt,
    reconcile,
    rollback_manifest,
)

__all__ = ["AdoptionError", "adopt", "reconcile", "rollback_manifest"]
