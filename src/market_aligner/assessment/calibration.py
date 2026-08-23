"""Calibration readiness ledger; scoring remains uncalibrated until certified."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CalibrationPolicy:
    minimum_operator_judgments: int = 30
    minimum_real_outcomes: int = 10


@dataclass(frozen=True)
class CalibrationReadiness:
    ready: bool
    operator_judgments: int
    real_outcomes: int
    blockers: tuple[str, ...]


def readiness(
    operator_judgments: int,
    real_outcomes: int,
    policy: CalibrationPolicy | None = None,
) -> CalibrationReadiness:
    policy = policy or CalibrationPolicy()
    blockers: list[str] = []
    if operator_judgments < policy.minimum_operator_judgments:
        blockers.append("insufficient_operator_judgments")
    if real_outcomes < policy.minimum_real_outcomes:
        blockers.append("insufficient_real_outcomes")
    return CalibrationReadiness(
        ready=not blockers,
        operator_judgments=operator_judgments,
        real_outcomes=real_outcomes,
        blockers=tuple(blockers),
    )
