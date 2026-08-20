"""Stable public core contracts during the legacy namespace migration."""

from __future__ import annotations

import re
from dataclasses import dataclass

from career_automation.evidence_matching import MatchResult, Requirement


_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_FORBIDDEN_MARKUP = (
    "<table",
    "</table",
    "<img",
    "<svg",
    "display:none",
    "visibility:hidden",
    "font-size:0",
    "opacity:0",
    "position:absolute",
    "[image:",
    "![",
)


def _safe_plain_text(value: str, label: str) -> None:
    clean = value.strip()
    if not clean:
        raise ValueError(f"{label} is required")
    folded = clean.casefold().replace(" ", "")
    if any(marker.replace(" ", "") in folded for marker in _FORBIDDEN_MARKUP):
        raise ValueError(f"{label} contains forbidden rich or hidden content")
    if "\x00" in clean or "\r" in clean:
        raise ValueError(f"{label} must be normalized plain text")


@dataclass(frozen=True)
class CandidateContact:
    """Versioned core contact projection; excludes sensitive address fields."""

    full_name: str
    email: str
    phone: str | None
    city: str
    record_id: str
    record_version: int
    provenance_sha256: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.full_name, "candidate name"),
            (self.city, "candidate city"),
            (self.record_id, "contact record ID"),
        ):
            _safe_plain_text(value, label)
        if self.phone is not None:
            _safe_plain_text(self.phone, "candidate phone")
        if not _EMAIL.fullmatch(self.email):
            raise ValueError("candidate email is invalid")
        if self.record_version < 1:
            raise ValueError("contact record version must be positive")
        if not _HEX_64.fullmatch(self.provenance_sha256):
            raise ValueError(
                "contact provenance hash must be a lowercase SHA-256 digest"
            )
        if "\n" in self.city or "," in self.city:
            raise ValueError("contact location must be city only")

    def document(self) -> dict[str, object]:
        return {
            "full_name": self.full_name,
            "email": self.email,
            "phone": self.phone,
            "city": self.city,
            "record_id": self.record_id,
            "record_version": self.record_version,
            "provenance_sha256": self.provenance_sha256,
        }


__all__ = ["CandidateContact", "MatchResult", "Requirement"]
