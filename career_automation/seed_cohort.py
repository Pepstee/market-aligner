"""Hydrate the checked JAA-04 seed into a byte-backed Opportunity-0 queue.

The checked v1 file is an identity projection, not decision evidence.  This
module retrieves the official vacancy representation for every seed row,
recomputes viability and Opportunity-0 from the captured bytes, and emits the
strict v2 input consumed by ``capture_jaa_04.py``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from html import unescape
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from career_automation.employer_research import (
    Citation,
    IntelligenceKind,
    PortableAuthorityRetriever,
    RawResponseCache,
    ScraplingPublicRetriever,
)
from career_automation.official_cohort import (
    COHORT_SIZE,
    VACANCY_FRESHNESS_DAYS,
    _canonical,
    _normal_url,
    _opportunity,
)
from career_automation.opportunity_calibration import (
    DECISION_RULE_VERSION,
    CalibrationPolicy,
    calibration_policy_json,
    decide_opportunity0,
)
from scraper.viability import Vacancy, canonical_key, local_decision


CHECKED_SEED_RECORDS_HASH = "2e5114bd1f01b75cd598061a07356ac7424c2914833f15d40f0f0d671327e348"


@dataclass(frozen=True)
class SeedVacancy:
    job_key: str
    board: str
    company: str
    title: str
    url: str
    payload_hash: str


def load_seed(
    path: Path,
    *,
    expected_records_hash: str = CHECKED_SEED_RECORDS_HASH,
) -> list[SeedVacancy]:
    """Load only the privacy-minimised, hash-bound v1 identity projection."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    records = payload.get("records")
    if payload.get("schema_version") != "jaa04.admitted-queue.v1":
        raise ValueError("JAA-04 seed must use jaa04.admitted-queue.v1")
    if not isinstance(records, list) or len(records) != COHORT_SIZE:
        raise ValueError(f"JAA-04 seed must contain exactly {COHORT_SIZE} records")
    actual_records_hash = hashlib.sha256(_canonical(records)).hexdigest()
    if actual_records_hash != payload.get("records_hash"):
        raise ValueError("JAA-04 seed records hash mismatch")
    if actual_records_hash != expected_records_hash:
        raise ValueError("JAA-04 seed differs from the reviewed identity authority")
    if payload.get("source_queue_count", 0) < COHORT_SIZE:
        raise ValueError("JAA-04 seed does not identify its source queue")
    required = {"job_key", "board", "company", "title", "url", "payload_hash"}
    result: list[SeedVacancy] = []
    identities: set[str] = set()
    urls: set[str] = set()
    employers: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != required:
            raise ValueError("JAA-04 seed rows must contain only the checked identity fields")
        if any(not isinstance(record[key], str) or not record[key].strip() for key in required):
            raise ValueError("JAA-04 seed identity fields must be non-empty strings")
        try:
            parsed = urlsplit(record["url"])
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("not a public HTTP(S) URL")
            normal_url = _normal_url(record["url"])
        except (TypeError, ValueError) as exc:
            raise ValueError("JAA-04 seed contains an invalid public URL") from exc
        employer = re.sub(r"[^a-z0-9]+", " ", record["company"].casefold()).strip()
        if (record["job_key"] in identities or normal_url in urls
                or not employer or employer in employers):
            raise ValueError("JAA-04 seed identities, URLs, and employers must be distinct")
        identities.add(record["job_key"])
        urls.add(normal_url)
        employers.add(employer)
        result.append(SeedVacancy(**record))
    return result


def _structured_documents(body: bytes) -> list[dict[str, Any]]:
    text = body.decode("utf-8", "strict")
    documents: list[dict[str, Any]] = []
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        decoded = None
    if isinstance(decoded, dict):
        documents.append(decoded)
    elif isinstance(decoded, list):
        documents.extend(item for item in decoded if isinstance(item, dict))
    for match in re.finditer(
        r"<script\b[^>]*type\s*=\s*([\"'])application/ld\+json\1[^>]*>(.*?)</script\s*>",
        text,
        re.I | re.S,
    ):
        try:
            decoded = json.loads(unescape(match.group(2)).strip())
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            documents.append(decoded)
        elif isinstance(decoded, list):
            documents.extend(item for item in decoded if isinstance(item, dict))
    return documents


def _walk(value: Any) -> list[tuple[str, Any]]:
    result: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            result.append((str(key).casefold(), item))
            result.extend(_walk(item))
    elif isinstance(value, list):
        for item in value:
            result.extend(_walk(item))
    return result


def _text(value: Any) -> str:
    if isinstance(value, str):
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", unescape(value))).strip()
    if isinstance(value, dict):
        preferred = [
            value.get(key) for key in (
                "name", "title", "streetAddress", "addressLocality",
                "addressRegion", "addressCountry",
            ) if value.get(key)
        ]
        return ", ".join(filter(None, (_text(item) for item in (preferred or value.values()))))
    if isinstance(value, list):
        return "; ".join(filter(None, (_text(item) for item in value)))
    return str(value) if value not in (None, "") else ""


def _field(documents: list[dict[str, Any]], names: tuple[str, ...]) -> str:
    wanted = {name.casefold() for name in names}
    for document in documents:
        for key, value in _walk(document):
            if key in wanted and (result := _text(value)):
                return result
    return ""


def _plain_body(body: bytes) -> str:
    text = body.decode("utf-8", "strict")
    text = re.sub(r"<(?:script|style)\b.*?</(?:script|style)\s*>", " ", text,
                  flags=re.I | re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", unescape(text))).strip()


def _vacancy(seed: SeedVacancy, citation: Citation, body: bytes) -> Vacancy:
    documents = _structured_documents(body)
    plain = _plain_body(body)
    location = _field(documents, (
        "jobLocation", "jobLocationType", "applicantLocationRequirements",
        "location", "locations", "location_text", "workplace",
    ))
    if not location:
        matches = re.findall(
            r"\b(?:London|Bristol|Cambridge|Manchester|Birmingham|Edinburgh|"
            r"Glasgow|Leeds|Liverpool|Newcastle|Nottingham|Reading|Oxford|"
            r"Cardiff|Belfast|United Kingdom|UK|Remote|Europe|EMEA)\b",
            plain,
            re.I,
        )
        location = ", ".join(dict.fromkeys(matches))
    body_text = _field(documents, (
        "description", "descriptionPlain", "jobDescription", "content_text",
        "contents", "requirements", "text",
    )) or plain
    return Vacancy(
        key=seed.job_key,
        board=seed.board,
        job_id=seed.job_key.split(":", 1)[1],
        url=citation.url,
        posted_at=citation.updated_at or citation.published_at or "",
        raw_text=plain,
        raw_json=documents[0] if documents else {},
        title=seed.title,
        company=seed.company,
        location=location,
        body=body_text,
        expiry=_field(documents, (
            "validThrough", "expiryDate", "expires_at", "expirationDate", "deadline",
        )),
    )


def _authority_citation(
    citations: list[Citation], plan: list[dict[str, Any]],
) -> Citation:
    role = next(
        (row for row in plan
         if row.get("kind") == IntelligenceKind.ROLE.value
         and row.get("outcome") == "supported"),
        None,
    )
    if role is None or role.get("source_type") != "official_vacancy":
        raise ValueError("seed hydration found no supported official vacancy authority")
    matches = [item for item in citations if item.id == role.get("source_id")]
    if len(matches) != 1 or matches[0].source_kind != "official_vacancy":
        raise ValueError("seed hydration has ambiguous official vacancy authority")
    return matches[0]


def _raw_reference(citation: Citation) -> dict[str, Any]:
    chain = [
        citation.requested_url or citation.url,
        *(str(item["url"]) for item in citation.redirect_history),
        citation.url,
    ]
    chain = list(dict.fromkeys(chain))
    return {
        "sha256": citation.content_sha256,
        "raw_response": citation.raw_response_ref,
        "requested_url": citation.requested_url or citation.url,
        "final_url": citation.url,
        "response_url": citation.url,
        "status": citation.status_code,
        "redirect_sequence": len(chain) - 1,
        "redirect_chain": chain,
        "observed_at": citation.captured_at,
        "retrieval_engine": citation.retrieval_engine,
    }


def _temporal(citation: Citation, as_of: datetime) -> dict[str, Any]:
    value = citation.updated_at or citation.published_at
    if not value or not citation.publisher_date_evidence:
        raise ValueError("official vacancy authority lacks byte-backed publisher time")
    publisher = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if publisher.tzinfo is None:
        raise ValueError("official vacancy publisher time has no timezone")
    publisher = publisher.astimezone(timezone.utc)
    if publisher > as_of:
        raise ValueError("official vacancy publisher time is in the future")
    if as_of - publisher > timedelta(days=VACANCY_FRESHNESS_DAYS):
        raise ValueError("official vacancy publisher time is stale")
    return {
        "admitted": True,
        "reason": "publisher_time_current",
        "publisher_time": publisher.isoformat(),
        "published_at": citation.published_at,
        "updated_at": citation.updated_at,
        "publisher_date_evidence": citation.publisher_date_evidence,
        "temporal_semantics": "publisher_time",
        "as_of": as_of.isoformat(),
        "as_of_date": as_of.date().isoformat(),
        "freshness_days": VACANCY_FRESHNESS_DAYS,
        "authority_response_sha256": citation.content_sha256,
    }


def _hydrate_one(
    seed: SeedVacancy,
    retriever: PortableAuthorityRetriever,
    cache: RawResponseCache,
    policy: CalibrationPolicy,
    as_of: datetime,
) -> dict[str, Any]:
    citations, plan = retriever.retrieve_plan(seed)
    authority = _authority_citation(citations, plan)
    body = cache.resolve(authority.raw_response_ref, authority.content_sha256)
    vacancy = _vacancy(seed, authority, body)
    viability = local_decision(vacancy, today=as_of.date())
    if viability.decision != "include" or viability.reason != "viable":
        raise ValueError(f"current official vacancy is not viable: {viability.reason}")
    inputs, confidence = _opportunity(vacancy)
    decision = decide_opportunity0(inputs, confidence, viability_reason="viable", policy=policy)
    if decision.decision != "pass":
        raise ValueError(f"current official vacancy fails Opportunity-0: {decision.reason}")
    temporal = _temporal(authority, as_of)
    refs = [_raw_reference(item) for item in citations]
    payload = asdict(vacancy)
    payload_hash = hashlib.sha256(_canonical({
        "source_identity": seed.job_key,
        "official_response_hashes": sorted({item.content_sha256 for item in citations}),
        "vacancy": payload,
    })).hexdigest()
    return {
        "job_key": seed.job_key,
        "board": seed.board,
        "company": seed.company,
        "title": seed.title,
        "url": vacancy.url,
        "payload_hash": payload_hash,
        "seed_payload_hash": seed.payload_hash,
        "seed_url": seed.url,
        "canonical_vacancy_key": canonical_key(vacancy),
        "content_sha256": hashlib.sha256(vacancy.body.encode("utf-8")).hexdigest(),
        "observed_at": authority.captured_at,
        "source": {
            "identity": seed.job_key,
            "adapter": seed.board,
            "authority": "official-public-employer-or-ats",
            "official_vacancy_url": authority.url,
        },
        "raw_response_refs": refs,
        "payload": payload,
        "viability_decision": asdict(viability),
        "opportunity0_input": asdict(inputs),
        "confidence": asdict(confidence),
        "opportunity0_decision": asdict(decision),
        "temporal_admission": temporal,
    }


def hydrate_seed(
    seed_path: Path,
    output: Path,
    raw_root: Path,
    *,
    maximum_routes: int = 12,
    timeout_seconds: int = 45,
    as_of: datetime | None = None,
    authority_retriever: PortableAuthorityRetriever | None = None,
    expected_seed_records_hash: str = CHECKED_SEED_RECORDS_HASH,
) -> dict[str, Any]:
    """Create a strict v2 queue or publish nothing."""
    if output.exists():
        raise RuntimeError("official admitted queue output already exists")
    if maximum_routes < 1 or timeout_seconds < 1:
        raise ValueError("retrieval limits must be positive")
    seeds = load_seed(seed_path, expected_records_hash=expected_seed_records_hash)
    as_of = as_of or datetime.now(timezone.utc)
    if as_of.tzinfo is None:
        raise ValueError("as_of must include a timezone")
    as_of = as_of.astimezone(timezone.utc)
    cache = RawResponseCache(raw_root)
    retriever = authority_retriever
    if retriever is None:
        transport = ScraplingPublicRetriever(
            cache,
            timeout_seconds=timeout_seconds,
            root=Path(__file__).resolve().parents[1],
        )
        retriever = PortableAuthorityRetriever(
            cache,
            retriever=transport,
            maximum_routes=maximum_routes,
            exact_canaries=False,
        )
    policy = CalibrationPolicy()
    records = [
        _hydrate_one(seed, retriever, cache, policy, as_of)
        for seed in seeds
    ]
    urls = {_normal_url(str(record["url"])) for record in records}
    bodies = {str(record["content_sha256"]) for record in records}
    if len(urls) != COHORT_SIZE or len(bodies) != COHORT_SIZE:
        raise RuntimeError("hydrated cohort contains duplicate official vacancies or bodies")
    envelope = {
        "schema_version": "jaa04.official-admitted-queue.v2",
        "created_at": as_of.isoformat(),
        "selection": "exact checked v1 identities; current official authority replay; exact 30",
        "seed": {
            "schema_version": "jaa04.admitted-queue.v1",
            "sha256": hashlib.sha256(seed_path.read_bytes()).hexdigest(),
            "records_hash": hashlib.sha256(_canonical([asdict(seed) for seed in seeds])).hexdigest(),
        },
        "policy": {
            "identity": DECISION_RULE_VERSION,
            "hash": policy.policy_hash,
            "parameters": calibration_policy_json(policy),
        },
        "raw_store": {
            "layout": "sha256/content-addressed",
            "root": str(raw_root.resolve()),
        },
        "temporal_policy": {
            "purposes": [IntelligenceKind.ROLE.value, IntelligenceKind.HIRING.value],
            "temporal_semantics": "publisher_time",
            "as_of": as_of.isoformat(),
            "as_of_date": as_of.date().isoformat(),
            "freshness_days": VACANCY_FRESHNESS_DAYS,
        },
        "records": records,
        "records_hash": hashlib.sha256(_canonical(records)).hexdigest(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    if temporary.exists():
        raise RuntimeError("official admitted queue temporary output already exists")
    temporary.write_bytes(_canonical(envelope) + b"\n")
    temporary.replace(output)
    return envelope
