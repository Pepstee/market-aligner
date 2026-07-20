"""Candidate profiler.

The default profiler is evidence-led and subject-generic. The guided-pass
implementation remains available as ``profiler.score_profile`` with generic
contracts and private runtime inputs.

Exports are loaded lazily so ``python -m profiler.candidate_profile`` can run
without importing the target module twice.
"""

__all__ = [
    "CandidateProfile",
    "CareerTrack",
    "EvidenceItem",
    "build_profile",
    "load_evidence",
    "profile_to_dict",
    "write_profile",
]


def __getattr__(name: str):
    if name not in __all__:
        raise AttributeError(name)
    from . import candidate_profile

    return getattr(candidate_profile, name)
