"""Adapters to external infrastructure, not embedded implementations."""

from .orchestrator import OrchestratorAdapter, WorkRequest, WorkReceipt

__all__ = ["OrchestratorAdapter", "WorkRequest", "WorkReceipt"]
