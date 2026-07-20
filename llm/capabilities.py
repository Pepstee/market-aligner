"""
llm/capabilities.py — the module's public verbs (Architecture.md):

    extract_job(raw)               -> dict   (schema: job_extract)
    rate_axes(job, profile)        -> dict   (schema: axis_ratings)
    assess_portfolio(items)        -> dict   (schema: portfolio_assess)
    normalise_skill(term, aliases) -> canonical_id (str)

The LLM module exposes CAPABILITIES, not a pipeline. The scraper calls
extract_job + rate_axes; the profiler calls assess_portfolio. All four run
through LLMClient so they get caching, retries, cost logging, and (via
MockBackend) deterministic offline behaviour for tests.

normalise_skill is RULE-FIRST: it matches config.skill_aliases (English AND
Korean) before ever touching a model, and any LLM fallback merge is logged to a
review file (llm/data/skill_merges.jsonl) for human approval — Build Spec §4.
"""

from __future__ import annotations

import json
import re
import time
import unicodedata
from pathlib import Path
from typing import Any, Optional

from .client import (
    LLMClient,
    MockBackend,
    load_skill_aliases,
    register_mock_handler,
    task_marker,
)
from .prompt_loader import load_prompt
from .schema_loader import load_schema

_MODULE_DIR = Path(__file__).resolve().parent
_MERGE_LOG = _MODULE_DIR / "data" / "skill_merges.jsonl"

# The 10 canonical careers (mirrors skeleton.contracts.CAREERS; kept local so the
# LLM module stays importable without the skeleton present, per the boundary rule).
_CAREERS = (
    "UX_UI", "Spatial_VMD", "Exhibition", "Brand_Space", "ArchViz",
    "3D_Generalist", "Environment_Art", "XR_Spatial", "Technical_Artist",
    "Motion_Graphic",
)


# --------------------------------------------------------------------------- #
# Default shared client. Offline & deterministic (MockBackend) so importing this
# module never needs an API key. Swap via set_client() to go live.
# --------------------------------------------------------------------------- #
_client: LLMClient = LLMClient.from_config(backend=MockBackend())


def set_client(client: LLMClient) -> None:
    """Override the shared client (e.g. a StubBackend one, once wired)."""
    global _client
    _client = client


def get_client() -> LLMClient:
    return _client


# --------------------------------------------------------------------------- #
# extract_job
# --------------------------------------------------------------------------- #
def extract_job(
    raw: dict[str, Any],
    profile: Optional[dict[str, Any]] = None,
    client: Optional[LLMClient] = None,
) -> dict[str, Any]:
    """Extract a structured job row from a raw posting (JobRow-shaped subset).

    `raw` is a dict form of a RawPosting (board/job_id/url + raw_text/raw_json).
    Returns the job_extract-schema fields; provenance & dedup_key are added by
    the caller (the scraper) which owns those.
    """
    client = client or _client
    prompt = load_prompt("extract_job")
    schema = load_schema("job_extract")
    payload: dict[str, Any] = {"raw_posting": raw}
    if profile:
        payload["candidate_dossier"] = profile
    user = prompt.render_user(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return client.complete_json(prompt.system, user, schema=schema, task="extract_job")


# --------------------------------------------------------------------------- #
# rate_axes
# --------------------------------------------------------------------------- #
def rate_axes(
    job: dict[str, Any],
    profile: Optional[dict[str, Any]] = None,
    client: Optional[LLMClient] = None,
) -> dict[str, Any]:
    """Rate one posting on the seven 0-10 axes (axis_ratings schema).

    `job` is an extracted row; `profile` is optional context (e.g. Hyun's field
    priors) that nudges relevance. The deterministic scoring stays in the skeleton.
    """
    client = client or _client
    prompt = load_prompt("rate_axes")
    schema = load_schema("axis_ratings")
    payload = {"job": job, "profile": profile or {}}
    user = prompt.render_user(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return client.complete_json(prompt.system, user, schema=schema, task="rate_axes")


# --------------------------------------------------------------------------- #
# assess_portfolio
# --------------------------------------------------------------------------- #
def assess_portfolio(
    items: list[dict[str, Any]],
    client: Optional[LLMClient] = None,
) -> dict[str, Any]:
    """Rough read of Hyun's portfolio items → per-field evidence (profiler-facing).

    Only the item titles/descriptions passed in are sent to the model — never the
    whole profiler/data tree (privacy rule).
    """
    client = client or _client
    prompt = load_prompt("assess_portfolio")
    schema = load_schema("portfolio_assess")
    user = prompt.render_user(json.dumps({"items": items}, ensure_ascii=False, sort_keys=True))
    return client.complete_json(prompt.system, user, schema=schema, task="assess_portfolio")


# --------------------------------------------------------------------------- #
# normalise_skill  (rule-first; LLM fallback logged for review)
# --------------------------------------------------------------------------- #
def _norm(term: str) -> str:
    """Casefold + NFKC + strip so 'UE5', 'ue5', ' Ue5 ' all collapse together.

    NFKC also flattens full-width forms; Korean is preserved as-is.
    """
    t = unicodedata.normalize("NFKC", term).strip()
    return t.casefold()


def _build_alias_index(aliases: dict[str, list[str]]) -> dict[str, str]:
    """{normalised surface form -> canonical_id}. Canonical id also maps to itself."""
    index: dict[str, str] = {}
    for canonical, surfaces in aliases.items():
        index[_norm(canonical)] = canonical
        for s in surfaces or []:
            index[_norm(str(s))] = canonical
    return index


def normalise_skill(
    term: str,
    aliases: Optional[dict[str, list[str]]] = None,
    client: Optional[LLMClient] = None,
    *,
    log_merges: bool = True,
    min_confidence: float = 0.5,
    llm_fallback: bool = True,
) -> str:
    """Map a raw skill mention (EN or KO) to a canonical id.

    Rule-first: exact alias-dictionary match (from config.skill_aliases) wins and
    never calls the model. On a miss, fall back to the LLM and LOG the proposed
    merge to llm/data/skill_merges.jsonl for human approval (Build Spec §4).

    Returns the canonical id, or "" if the term isn't a recognisable tool/skill.
    """
    if aliases is None:
        aliases = load_skill_aliases()
    index = _build_alias_index(aliases)

    key = _norm(term)
    if key in index:                      # rule hit — deterministic, no model call
        return index[key]

    # A light second pass: some surfaces carry version suffixes ("unreal engine 5",
    # "3ds max 2024"). Try progressively stripped forms before the model.
    stripped = re.sub(r"[\s\-]*\d[\d.]*$", "", key).strip()
    if stripped and stripped != key and stripped in index:
        return index[stripped]

    if not llm_fallback:
        return ""   # rule-only mode (pipeline hot path): miss = no canonical id

    # Fallback: the LLM. Runs on MockBackend offline → deterministic.
    client = client or _client
    prompt = load_prompt("normalise_skill")
    schema = load_schema("skill_normalise")
    payload = {"term": term, "known_ids": sorted(aliases.keys())}
    user = prompt.render_user(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    result = client.complete_json(prompt.system, user, schema=schema, task="normalise_skill")

    canonical = str(result.get("canonical_id", "") or "")
    confidence = float(result.get("confidence", 0.0) or 0.0)

    if log_merges and canonical:
        _log_merge(term, canonical, confidence, approved=confidence >= min_confidence)

    # Below the confidence floor we still return the id, but the merge stays
    # UNAPPROVED in the review log so the human can veto it before it's trusted.
    return canonical


def _log_merge(term: str, canonical: str, confidence: float, approved: bool) -> None:
    _MERGE_LOG.parent.mkdir(parents=True, exist_ok=True)
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "term": term,
        "canonical_id": canonical,
        "confidence": round(confidence, 4),
        "source": "llm_fallback",
        "approved": approved,
    }
    with _MERGE_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


# =========================================================================== #
# Deterministic MOCK handlers — the offline stand-in for the real model.
# These make capabilities reproducible in tests with NO API key. They are pure
# functions of the input payload and produce schema-valid output.
# =========================================================================== #
_SKILL_HINTS = {
    "python": ["python"],
    "aws": ["aws", "amazon web services", "lambda"],
    "docker": ["docker", "containerisation", "containerization"],
    "kubernetes": ["kubernetes", "k8s"],
    "terraform": ["terraform", "infrastructure as code"],
    "fastapi": ["fastapi"],
    "django": ["django"],
    "flask": ["flask"],
    "pytorch": ["pytorch"],
    "tensorflow": ["tensorflow"],
    "llm": ["large language model", "llm", "generative ai"],
    "rag": ["retrieval augmented", " rag "],
    "agents": ["ai agent", "agentic ai", "multi-agent"],
    "mcp": ["model context protocol", " mcp "],
    "sql": [" sql", "postgres", "mysql"],
    "git": [" git", "github", "gitlab"],
    "ci_cd": ["ci/cd", "continuous integration", "continuous delivery"],
}

# Ordered most-specific-first: the extractor takes the FIRST career whose hints
# match, so narrow signals (VMD, exhibition) must precede broad ones (UX/UI).
# Hints are career signals, NOT tool names — a tool like Figma can appear in many
# postings, so it must not decide the career on its own.
_CAREER_HINTS = [
    ("Agentic_AI_Engineer", ["agentic ai", "ai agents", "multi-agent", "model context protocol", " mcp "]),
    ("AI_Automation_Engineer", ["ai automation", "workflow automation", "process automation", "llm integration"]),
    ("Technical_Solutions_Engineer", ["solutions engineer", "solution architect", "solutions architect", "technical architect", "customer engineer"]),
    ("Security_Detection_Engineer", ["detection engineer", "security engineer", "ai security", "security analytics", "threat detection"]),
    ("ML_MLOps_Engineer", ["mlops", "ml platform", "model serving", "model deployment", "machine learning infrastructure"]),
    ("Cloud_Platform_Engineer", ["cloud engineer", "platform engineer", "site reliability", "sre", "kubernetes platform"]),
    ("Applied_AI_Engineer", ["applied ai", "ai engineer", "artificial intelligence", "machine learning", "generative ai", "large language model", "llm"]),
    ("Full_Stack_Engineer", ["full stack", "full-stack"]),
    ("Backend_Engineer", ["backend engineer", "back-end engineer", "python engineer", "software engineer"]),
]

_ENTRY_TOKENS = ("graduate", "junior", "intern", "fellow", "entry-level", "entry level", "0-2 years")
_SENIOR_TOKENS = ("senior", "staff", "principal", "lead", "director", "head of", "manager", "5+ years")
# Lifestyle signals (mirror config.lifestyle keyword seeds).
_REMOTE_TOKENS = ("재택", "원격", "하이브리드", "remote", "hybrid")
_OFFICE_ONLY_TOKENS = ("출근 필수", "사무실 근무", "office only", "on-site only", "onsite only")
_SITE_TOKENS = ("현장", "시공", "설치", "감리", "출장", "매장", "야간작업")


def _text_of(payload: dict[str, Any]) -> str:
    """Flatten a raw-posting payload into one lowercased search string."""
    parts: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(payload)
    return " ".join(parts).lower()


def _mock_extract_job(payload: dict[str, Any]) -> dict[str, Any]:
    posting = payload.get("raw_posting") or payload
    raw = posting.get("raw_json") or posting
    text = _text_of(posting)

    title = ""
    company = ""
    location = ""
    salary = ""
    contract = ""
    if isinstance(raw, dict):
        title = str(raw.get("title") or raw.get("job_title") or raw.get("position") or "")
        company = str(raw.get("company") or raw.get("company_name") or raw.get("employer") or "")
        location = str(raw.get("location_text") or (raw.get("location") or {}).get("name") or "")
        salary = str(raw.get("salary") or raw.get("salary_text") or "")
        contract = str(raw.get("contract_type") or raw.get("employment_type") or "")

    title_text = title.casefold()
    mapped = "other"
    for career, hints in _CAREER_HINTS:
        if any(h in title_text for h in hints):
            mapped = career
            break
    if mapped == "other":
        for career, hints in _CAREER_HINTS:
            if any(h in text for h in hints):
                mapped = career
                break

    entry: Optional[bool]
    if any(tok in title_text for tok in _SENIOR_TOKENS):
        entry = False
    elif any(tok in title_text for tok in _ENTRY_TOKENS):
        entry = True
    elif re.search(r"\b(?:[3-9]|\d{2,})\+?\s*(?:years?|yrs?)\b", text):
        entry = False
    elif any(tok in text for tok in ("entry-level", "entry level", "graduate applicants", "junior role")):
        entry = True
    else:
        entry = None

    exp_match = re.search(r"\b(?:[1-9]|\d{2,})\+?\s*(?:years?|yrs?)[^.;]{0,80}", text)
    experience = exp_match.group(0).strip() if exp_match else (
        "graduate or early-career" if entry else
        "senior/lead experience" if entry is False else "not explicit"
    )
    salary_match = re.search(
        r"£\s?[\d,]+(?:\s*(?:-|–|—|to)\s*£?\s?[\d,]+)?(?:\s*(?:GBP|per week|per year))?",
        text,
        re.IGNORECASE,
    )
    if not salary and salary_match:
        salary = salary_match.group(0)
    if "unable to provide visa sponsorship" in text or "must have the legal right to work" in text:
        sponsorship = "not_available"
    elif "we do sponsor visas" in text or "visa sponsorship is available" in text:
        sponsorship = "available"
    elif "sponsor visas" in text or "visa sponsorship" in text:
        sponsorship = "conditional"
    else:
        sponsorship = "unknown"

    software = sorted(
        cid for cid, hints in _SKILL_HINTS.items() if any(h in text for h in hints)
    )

    # Lifestyle signals — deterministic keyword read (the real model judges duties).
    remote: Optional[bool]
    if any(tok in text for tok in _REMOTE_TOKENS):
        remote = True
    elif any(tok in text for tok in _OFFICE_ONLY_TOKENS):
        remote = False
    else:
        remote = None
    fit = (
        f"Maps to {mapped}; "
        + ("entry-level friendly" if entry else "experience expected" if entry is False else "seniority unclear")
        + ". Strongest evidence is systems/automation architecture; verify production-depth requirements."
    )
    # Confidence: high when we found a title and a concrete career, lower otherwise.
    conf = 0.9 if (title and mapped != "other") else 0.6 if title else 0.4

    return {
        "job_title": title,
        "company": company,
        "location": location,
        "salary_text": salary,
        "contract_type": contract,
        "experience_required": experience,
        "sponsorship_signal": sponsorship,
        "mapped_career": mapped,
        "entry_level": entry,
        "required_software": software,
        "job_description": text,
        "responsibilities": [],
        "required_skills": software,
        "preferred_skills": [],
        "education_required": "",
        "certifications_required": [],
        "benefits": [],
        "application_deadline": "",
        "remote_flag": remote,
        "why_it_fits": fit,
        "skills_to_learn": software,
        "extraction_confidence": conf,
    }


def _mock_rate_axes(payload: dict[str, Any]) -> dict[str, Any]:
    job = payload.get("job", {}) if isinstance(payload, dict) else {}
    career = str(job.get("mapped_career", "other"))
    entry = job.get("entry_level")

    # Deterministic per-career baselines (integers, 0-10). Not calibrated — this
    # is a mock stand-in; the real model replaces these.
    base = {
        "Agentic_AI_Engineer": dict(technical_alignment=9, evidence_match=7, growth_potential=9, market_demand=7, barrier_to_entry=6),
        "AI_Automation_Engineer": dict(technical_alignment=9, evidence_match=8, growth_potential=9, market_demand=8, barrier_to_entry=4),
        "Applied_AI_Engineer": dict(technical_alignment=8, evidence_match=6, growth_potential=9, market_demand=8, barrier_to_entry=6),
        "ML_MLOps_Engineer": dict(technical_alignment=6, evidence_match=4, growth_potential=8, market_demand=8, barrier_to_entry=7),
        "Cloud_Platform_Engineer": dict(technical_alignment=7, evidence_match=5, growth_potential=8, market_demand=8, barrier_to_entry=6),
        "Security_Detection_Engineer": dict(technical_alignment=7, evidence_match=5, growth_potential=8, market_demand=7, barrier_to_entry=6),
        "Backend_Engineer": dict(technical_alignment=7, evidence_match=5, growth_potential=8, market_demand=8, barrier_to_entry=6),
        "Full_Stack_Engineer": dict(technical_alignment=5, evidence_match=4, growth_potential=7, market_demand=7, barrier_to_entry=6),
        "Technical_Solutions_Engineer": dict(technical_alignment=8, evidence_match=7, growth_potential=8, market_demand=7, barrier_to_entry=5),
        "other": dict(technical_alignment=3, evidence_match=3, growth_potential=5, market_demand=5, barrier_to_entry=7),
    }
    axes = dict(base.get(career, base["other"]))

    if entry is True:
        axes["barrier_to_entry"] = max(0, axes["barrier_to_entry"] - 3)
        axes["growth_potential"] = min(10, axes["growth_potential"] + 1)
    elif entry is False:
        axes["barrier_to_entry"] = min(10, axes["barrier_to_entry"] + 2)
        axes["evidence_match"] = max(0, axes["evidence_match"] - 2)

    return {k: float(v) for k, v in axes.items()}


def _mock_assess_portfolio(payload: dict[str, Any]) -> dict[str, Any]:
    items = payload.get("items", []) if isinstance(payload, dict) else []
    text = _text_of({"items": items})

    per_field: list[dict[str, Any]] = []
    detected: set[str] = set()
    for career, hints in _CAREER_HINTS:
        hits = sum(1 for h in hints if h in text)
        if hits:
            per_field.append(
                {
                    "career": career,
                    "evidence_strength": float(min(10, 3 + 2 * hits)),
                    "note": f"Portfolio text references {career.replace('_', ' ')} work.",
                }
            )
    for cid, hints in _SKILL_HINTS.items():
        if any(h in text for h in hints):
            detected.add(cid)

    per_field.sort(key=lambda e: e["evidence_strength"], reverse=True)
    if per_field:
        top = per_field[0]["career"].replace("_", " ")
        summary = f"Portfolio is strongest in {top}."
    else:
        summary = "No clear field signal detected in the provided items."

    return {
        "per_field": per_field,
        "detected_skills": sorted(detected),
        "overall_summary": summary,
    }


def _mock_normalise_skill(payload: dict[str, Any]) -> dict[str, Any]:
    term = str(payload.get("term", "")).lower().strip()
    known = payload.get("known_ids", [])
    # The mock only "recognises" a term if it already looks like a known id, or a
    # couple of common extras — otherwise it declines (empty id, low confidence),
    # which is the honest behaviour: the rule layer handles the aliases.
    extra = {
        "substance": "substance_painter",
        "substance painter": "substance_painter",
        "zbrush": "zbrush",
        "houdini": "houdini",
    }
    if term in known:
        return {"canonical_id": term, "confidence": 0.95}
    if term in extra:
        return {"canonical_id": extra[term], "confidence": 0.8}
    return {"canonical_id": "", "confidence": 0.2}


# Register the deterministic handlers into MockBackend's routing table.
register_mock_handler("extract_job", _mock_extract_job)
register_mock_handler("rate_axes", _mock_rate_axes)
register_mock_handler("assess_portfolio", _mock_assess_portfolio)
register_mock_handler("normalise_skill", _mock_normalise_skill)


# Silence unused-import linters while keeping task_marker importable for callers.
_ = task_marker
