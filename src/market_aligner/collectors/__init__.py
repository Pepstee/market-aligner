"""Uncapped, resumable collection and full Scrapling integration."""

from __future__ import annotations

from typing import Any


__all__ = ["Collector"]


def __getattr__(name: str) -> Any:
    if name == "Collector":
        from .engine import Collector

        return Collector
    raise AttributeError(name)
