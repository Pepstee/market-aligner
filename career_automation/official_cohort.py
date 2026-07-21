"""Build an exact JAA-04 queue from live, configured official authorities.

Discovery configuration is an allow-list of employer ATS accounts.  Search
engines and aggregators are deliberately outside this command's input model.
Every HTTP response consumed by an adapter is retained byte-for-byte.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit, urlunsplit

import yaml

from career_automation.opportunity_calibration import (
    DECISION_RULE_VERSION, CalibrationPolicy, Confidence, Opportunity0Input,
    decide_opportunity0,
)
from scraper.adapters.base import load_adapter
from scraper.viability import Vacancy, canonical_key, local_decision

COHORT_SIZE = 30
OFFICIAL_ADAPTERS = frozenset({
    "ashby", "greenhouse", "lever", "personio", "recruitee",
    "smartrecruiters", "workable", "workday",
})
AGGREGATORS = frozenset({
    "adzuna", "arbeitnow", "himalayas", "jobicy", "jooble", "muse",
    "reed", "remotefirst", "remoteok", "remotive", "weworkremotely",
})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def _normal_url(value: str) -> str:
    parts = urlsplit(value)
    return urlunsplit((parts.scheme.casefold(), parts.netloc.casefold(),
                       parts.path.rstrip("/"), "", ""))


class ResponseRecorder:
    """Record response bodies and redirect chains without changing adapters."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.records: list[dict[str, Any]] = []

    def record(self, response: Any, observed_at: str) -> None:
        chain = [*response.history, response]
        redirect_chain = [str(item.url) for item in chain]
        for sequence, item in enumerate(chain):
            body = bytes(item.content)
            digest = hashlib.sha256(body).hexdigest()
            relative = Path(digest[:2]) / f"{digest}.response"
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise RuntimeError("raw response hash collision")
            if not path.exists():
                path.write_bytes(body)
            self.records.append({
                "sha256": digest, "raw_response": relative.as_posix(),
                "requested_url": str(item.request.url), "final_url": str(response.url),
                "response_url": str(item.url), "status": int(item.status_code),
                "redirect_sequence": sequence, "redirect_chain": redirect_chain,
                "observed_at": observed_at,
            })

    @contextmanager
    def installed(self) -> Iterator[None]:
        import requests

        original = requests.sessions.Session.send
        recorder = self

        def send(session: Any, request: Any, **kwargs: Any) -> Any:
            response = original(session, request, **kwargs)
            recorder.record(response, datetime.now(timezone.utc).isoformat())
            return response

        requests.sessions.Session.send = send
        try:
            yield
        finally:
            requests.sessions.Session.send = original


def _field(payload: dict[str, Any], names: tuple[str, ...]) -> str:
    for name in names:
        value = payload.get(name)
        if value not in (None, "", [], {}):
            if isinstance(value, (dict, list)):
                return json.dumps(value, ensure_ascii=False)
            return str(value)
    return ""


def _vacancy(raw: Any, posted_at: str | None, config: dict[str, Any] | None = None) -> Vacancy:
    payload = raw.raw_json if isinstance(raw.raw_json, dict) else {}
    body = _field(payload, ("content_text", "descriptionPlain", "description",
                            "jobDescription", "contents", "text", "requirements"))
    token = str(raw.job_id).split(":", 1)[0]
    companies = (config or {}).get("companies") or {}
    configured_company = companies.get(token, "") if isinstance(companies, dict) else token
    return Vacancy(
        key=raw.key, board=raw.board, job_id=raw.job_id, url=raw.url,
        posted_at=str(posted_at or _field(payload, ("datePosted", "postedAt", "published_at", "createdAt"))),
        raw_text=str(raw.raw_text or ""), raw_json=payload,
        title=_field(payload, ("title", "job_title", "jobTitle", "name", "position", "text")),
        company=_field(payload, ("company", "companyName", "employerName", "organization")) or str(configured_company),
        location=_field(payload, ("location_text", "location", "locations", "jobLocation", "city", "country", "workplace")),
        body=body or str(raw.raw_text or ""),
        expiry=_field(payload, ("expiryDate", "expires_at", "expirationDate", "validThrough", "deadline")),
    )


def _opportunity(vacancy: Vacancy) -> tuple[Opportunity0Input, Confidence]:
    """Deterministic, candidate-independent extraction from official content."""
    text = f"{vacancy.title}\n{vacancy.body}".casefold()
    market = 8500 if re.search(r"\b(ai|machine learning|software|data|security|platform|cloud)\b", text) else 6500
    quality = 8000
    if re.search(r"\b(unpaid|volunteer|zero[- ]hours)\b", text):
        quality = 2500
    elif re.search(r"\b(fixed[- ]term|temporary|internship|contract)\b", text):
        quality = 6000
    accessibility = 9000
    complete = bool(vacancy.title and vacancy.company and vacancy.location and len(vacancy.body) >= 120)
    confidence = 9000 if complete else 6500
    return (Opportunity0Input(market, quality, accessibility),
            Confidence(confidence, confidence, confidence, confidence))


def _validate_config(payload: Any) -> tuple[list[str], dict[str, dict[str, Any]], list[str]]:
    if not isinstance(payload, dict):
        raise ValueError("configuration must be an object")
    boards = payload.get("official_sources")
    if not isinstance(boards, dict) or not boards:
        raise ValueError("configuration requires non-empty official_sources mapping")
    names = sorted(str(name) for name in boards)
    forbidden = set(names) & AGGREGATORS
    unsupported = set(names) - OFFICIAL_ADAPTERS
    if forbidden:
        raise ValueError(f"aggregators cannot be evidence sources: {sorted(forbidden)}")
    if unsupported:
        raise ValueError(f"non-official or unsupported adapters: {sorted(unsupported)}")
    terms = payload.get("search_terms") or []
    if not isinstance(terms, list):
        raise ValueError("search_terms must be a list")
    return names, {name: dict(boards[name] or {}) for name in names}, [str(x) for x in terms]


def build(config_path: Path, output: Path, raw_root: Path) -> dict[str, Any]:
    if output.exists():
        raise RuntimeError("output snapshot already exists")
    boards, configs, terms = _validate_config(yaml.safe_load(config_path.read_text(encoding="utf-8")))
    recorder = ResponseRecorder(raw_root)
    candidates: list[dict[str, Any]] = []
    errors: list[str] = []
    policy = CalibrationPolicy()
    seen_identity: set[str] = set()
    seen_url: set[str] = set()
    seen_body: set[str] = set()
    with recorder.installed():
        for board in boards:
            adapter = load_adapter(board, config=configs[board])
            discovery_start = len(recorder.records)
            try:
                discovered = list(adapter.discover(terms, live=True))
            except Exception as exc:
                errors.append(f"{board}: discovery failed: {exc}")
                continue
            discovery_refs = recorder.records[discovery_start:]
            for job in sorted(discovered, key=lambda row: (row.job_id, row.url)):
                detail_start = len(recorder.records)
                try:
                    raw = adapter.fetch(job, live=True)
                    vacancy = _vacancy(raw, job.posted_at, configs[board])
                    decision = local_decision(vacancy)
                except Exception as exc:
                    errors.append(f"{job.key}: detail failed: {exc}")
                    continue
                refs = [*discovery_refs, *recorder.records[detail_start:]]
                if not refs or refs[-1]["status"] != 200:
                    continue
                inputs, confidence = _opportunity(vacancy)
                opportunity = decide_opportunity0(
                    inputs, confidence,
                    viability_reason="viable" if decision.reason == "viable" else (
                        decision.reason if decision.reason in {"expired", "inaccessible", "ineligible", "implausibly_senior"}
                        else "ineligible"),
                    policy=policy,
                )
                if decision.decision != "include" or opportunity.decision != "pass":
                    continue
                identity = f"{board}:{job.job_id}"
                url = _normal_url(vacancy.url)
                body_hash = hashlib.sha256(vacancy.body.encode("utf-8")).hexdigest()
                if identity in seen_identity or url in seen_url or body_hash in seen_body:
                    continue
                seen_identity.add(identity); seen_url.add(url); seen_body.add(body_hash)
                official_hashes = sorted({ref["sha256"] for ref in refs})
                payload_hash = hashlib.sha256(_canonical({
                    "source_identity": identity, "official_response_hashes": official_hashes,
                    "vacancy": asdict(vacancy),
                })).hexdigest()
                candidates.append({
                    "job_key": identity, "board": board, "company": vacancy.company,
                    "title": vacancy.title, "url": vacancy.url, "payload_hash": payload_hash,
                    "canonical_vacancy_key": canonical_key(vacancy), "content_sha256": body_hash,
                    "observed_at": refs[-1]["observed_at"],
                    "source": {"identity": identity, "adapter": board, "authority": "official-public-employer-or-ats"},
                    "raw_response_refs": refs,
                    "payload": asdict(vacancy),
                    "viability_decision": asdict(decision),
                    "opportunity0_input": asdict(inputs), "confidence": asdict(confidence),
                    "opportunity0_decision": asdict(opportunity),
                })
    candidates.sort(key=lambda row: (-row["opportunity0_decision"]["score_bp"], row["job_key"]))
    if len(candidates) < COHORT_SIZE:
        raise RuntimeError(f"only {len(candidates)} current unique official vacancies survived; need exactly 30; "
                           + "; ".join(errors[:10]))
    records = candidates[:COHORT_SIZE]
    envelope = {
        "schema_version": "jaa04.official-admitted-queue.v2",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "selection": "highest Opportunity-0 score then vacancy identity; exact 30",
        "policy": {"identity": DECISION_RULE_VERSION, "hash": policy.policy_hash,
                   "parameters": asdict(policy)},
        "raw_store": {"layout": "sha256-prefix/content-sha256.response",
                      "root": str(raw_root)},
        "records": records,
        "records_hash": hashlib.sha256(_canonical(records)).hexdigest(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_canonical(envelope) + b"\n")
    return envelope


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--raw-root", type=Path, required=True,
                        help="external runtime directory for exact official response bytes")
    args = parser.parse_args()
    try:
        envelope = build(args.config.resolve(), args.output.resolve(), args.raw_root.resolve())
    except Exception as exc:
        print(f"JAA-04 official cohort: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "SUCCESS", "count": len(envelope["records"]),
                      "records_hash": envelope["records_hash"], "snapshot": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
