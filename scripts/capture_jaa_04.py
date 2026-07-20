#!/usr/bin/env python3
"""Capture JAA-04 public evidence with the configured Scrapling sidecar.

Nothing is published unless all 30 requests and dossier validations succeed.
The destination is a newly created directory so an earlier certified capture
can never be partially overwritten by a failed run.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from email.utils import parsedate_to_datetime
from types import SimpleNamespace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.employer_research import (  # noqa: E402
    Citation, RawResponseCache, build_reconnaissance_dossier, content_hash,
    load_frozen_dossiers,
)
from scraper.scrapling_client import ScraplingClient  # noqa: E402


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode()


def title_excerpt(body: bytes) -> str:
    match = re.search(br"<title(?:\s[^>]*)?>(.*?)</title\s*>", body,
                      flags=re.IGNORECASE | re.DOTALL)
    if not match:
        raise RuntimeError("captured response has no byte-resolvable HTML title")
    excerpt = match.group(1).decode("utf-8", errors="strict")
    if not excerpt.strip():
        raise RuntimeError("captured response has an empty HTML title")
    return excerpt


def publisher_timestamp(value: object) -> str | None:
    """Normalise only publisher/server supplied HTTP dates; never use fetch time."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def capture(plan_path: Path, destination: Path) -> None:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    records = plan.get("records")
    if plan.get("schema_version") != "jaa04.capture-plan.v2" or not isinstance(records, list) or len(records) != 30:
        raise RuntimeError("capture plan must contain exactly 30 records")
    if destination.exists():
        raise RuntimeError("capture destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="jaa04-capture-", dir=destination.parent))
    cache = RawResponseCache(stage / "raw")
    client = ScraplingClient(ROOT, {"fallback_chain": [
        {"engine": "static", "method": "get", "kwargs": {"timeout": 45}},
    ]})
    if not client.available:
        raise RuntimeError("configured Scrapling runtime is unavailable")
    dossiers: list[dict[str, object]] = []
    captured_records: list[dict[str, object]] = []
    try:
        seen_urls: set[str] = set()
        seen_bodies: set[str] = set()
        for record in records:
            specifications = record.get("sources")
            if not isinstance(specifications, list) or len(specifications) != 5:
                raise RuntimeError("each capture record requires five authoritative sources")
            citations = []
            source_plan = []
            source_attempts = []
            for specification in specifications:
                required = {"kind", "url", "source_type", "relevance_terms",
                            "published_at", "updated_at", "requires_current"}
                missing = required.difference(specification)
                if missing:
                    raise RuntimeError(f"capture source is missing required fields: {sorted(missing)}")
                if not isinstance(specification["relevance_terms"], list) or not specification["relevance_terms"]:
                    raise RuntimeError("capture source requires relevance terms")
                requested_url = str(specification["url"])
                if "?" in requested_url or requested_url in seen_urls:
                    raise RuntimeError("source URL is non-canonical or duplicated")
                started = datetime.now(timezone.utc).isoformat()
                result = client.fetch_with_chain(requested_url)
                response = result.response
                status = int(response["status"])
                if not 200 <= status < 300:
                    raise RuntimeError(f"retrieval failed with HTTP {status}: {requested_url}")
                body = base64.b64decode(response["body_base64"], validate=True)
                if len(body) != int(response["body_bytes"]):
                    raise RuntimeError("retriever body length mismatch")
                digest, reference = cache.store(body)
                if digest in seen_bodies:
                    raise RuntimeError("duplicate response body cannot be independent evidence")
                final_url = str(response["url"])
                if "?" in final_url or final_url in seen_urls:
                    raise RuntimeError("redirect produced a URL alias or non-canonical URL")
                seen_urls.add(final_url)
                seen_bodies.add(digest)
                history = [{"url": str(item["url"]), "status_code": int(item["status"])}
                           for item in response.get("history", [])]
                kind = str(specification["kind"])
                source_id = f"source:{record['id']}:{kind}"
                source = {
                    "id": source_id, "url": final_url, "requested_url": requested_url,
                    "captured_at": started, "retrieved_at": datetime.now(timezone.utc).isoformat(),
                    "content_sha256": digest, "raw_response_ref": reference,
                    "status_code": status, "redirect_history": history,
                    "published_at": specification.get("published_at"),
                    "updated_at": (specification.get("updated_at") or publisher_timestamp(
                        dict(response.get("headers") or {}).get("last-modified")
                    )),
                }
                citations.append(Citation(**source))
                source_plan.append({
                    "id": f"plan:{kind}", "kind": kind, "source_id": source_id,
                    "source_type": specification["source_type"],
                    "permitted_purposes": [kind],
                    "freshness_days": __import__("career_automation.employer_research", fromlist=["FRESHNESS_DAYS"]).FRESHNESS_DAYS[
                        __import__("career_automation.models", fromlist=["IntelligenceKind"]).IntelligenceKind(kind)],
                    "relevance_terms": specification["relevance_terms"],
                    "requires_current": specification["requires_current"],
                    **({"excerpt_sha256": specification["excerpt_sha256"]}
                       if specification.get("excerpt_sha256") else {}),
                })
                source_attempts.append({"source_id": source_id, "engine": result.engine})
            company = str(record.get("company") or "").strip()
            if not company:
                raise RuntimeError("capture record requires the reviewed employer name")
            task = SimpleNamespace(job_key=record["id"], company=company,
                                   title=str(record.get("role") or "Technology role"))
            dossier = build_reconnaissance_dossier(
                task, citations, cache, source_plan=source_plan,
            )
            dossier["raw_cache_root"] = "raw"
            dossiers.append(dossier)
            attempts = []
            for attempt in result.attempts:
                summary = {"engine": attempt["engine"], "ok": bool(attempt["ok"])}
                if attempt["ok"]:
                    attempted_response = attempt["response"]
                    summary.update({"status_code": int(attempted_response["status"]),
                                    "final_url": str(attempted_response["url"]),
                                    "body_bytes": int(attempted_response["body_bytes"]),
                                    "content_sha256": hashlib.sha256(base64.b64decode(
                                        attempted_response["body_base64"], validate=True)).hexdigest()})
                else:
                    summary.update({"error": str(attempt.get("error", "")),
                                    "message": str(attempt.get("message", ""))})
                attempts.append(summary)
            captured_records.append({"job_key": record["id"],
                                     "source_ids": [item["id"] for item in dossier["sources"]],
                                     "sources": dossier["sources"],
                                     "source_plan": dossier["source_plan"],
                                     "company": company, "role": task.title,
                                     "intelligence_kinds": sorted({claim["kind"] for claim in dossier["claims"]}),
                                     "classifications": sorted({claim["classification"] for claim in dossier["claims"]}),
                                     "edge_relations": sorted({edge["relation"] for edge in dossier["edges"]}),
                                     "retrievals": source_attempts})
        envelope = {"schema_version": "jaa04.frozen-dossiers.v1", "dossiers": dossiers,
                    "dossiers_hash": content_hash(dossiers)}
        (stage / "frozen_dossiers.json").write_bytes(canonical(envelope))
        manifest = {"schema_version": "jaa04.research-manifest.v2", "records": captured_records,
                    "records_hash": content_hash(captured_records)}
        (stage / "research_manifest.json").write_bytes(canonical(manifest))
        load_frozen_dossiers(stage / "frozen_dossiers.json", cache, strict_corpus=True)
        corpus = sorted((stage / "raw").rglob("*"))
        corpus_hash = hashlib.sha256(b"".join(
            path.relative_to(stage).as_posix().encode() + b"\0" + path.read_bytes()
            for path in corpus if path.is_file())).hexdigest()
        receipt = {"schema_version": "jaa04.capture-receipt.v2", "status": "SUCCESS",
                   "captured_count": 30, "source_count": 150,
                   "capture_plan_sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
                   "manifest_sha256": hashlib.sha256((stage / "research_manifest.json").read_bytes()).hexdigest(),
                   "dossiers_sha256": hashlib.sha256((stage / "frozen_dossiers.json").read_bytes()).hexdigest(),
                   "raw_corpus_sha256": corpus_hash}
        receipt["source_plan_contract"] = {
            "intelligence_kinds": sorted(kind.value for kind in __import__(
                "career_automation.models", fromlist=["IntelligenceKind"]
            ).IntelligenceKind),
            "coverage": "one-plan-one-source-one-claim-per-kind",
            "byte_binding": "sha256-and-exact-byte-range",
            "semantic_validation": "source-type-purpose-and-byte-resolvable-excerpt",
            "temporal_policy": "historical-never-satisfies-requires-current",
        }
        (stage / "capture_receipt.json").write_bytes(canonical(receipt))
        os.rename(stage, destination)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, default=ROOT / "career_automation/fixtures/jaa04_capture_plan.json")
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        capture(args.plan.resolve(), args.destination.resolve())
    except Exception as exc:
        print(f"JAA-04 capture: ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "SUCCESS", "capture": str(args.destination)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
