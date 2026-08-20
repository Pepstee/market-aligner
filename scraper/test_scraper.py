"""
scraper/test_scraper.py — standalone self-test for the SCRAPER module.

Runs discover + fetch over the hand-made fixtures (no network) and asserts:
  * every discovered record is a valid C1 JobUrl and round-trips via contracts
  * job_urls.jsonl is real JSONL of C1 records
  * every fetched record is a valid C2 RawPosting (raw_json or raw_text set)
    and round-trips off disk via contracts
  * the resume/seen set (keyed board:job_id) skips already-seen ids on re-run
  * non-design postings (backend eng, accounting, sales) are filtered out

Run:  python scraper/test_scraper.py      (from the repo root)
      python -m scraper.test_scraper
Exits non-zero on failure; prints a summary on success.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve()
_REPO_ROOT = _HERE.parents[1]
_SKELETON = _REPO_ROOT / "skeleton"
for p in (str(_SKELETON), str(_REPO_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

import contracts  # noqa: E402
from contracts import JobUrl, RawPosting, from_dict, read_jsonl, to_dict  # noqa: E402
from scraper import crawl  # noqa: E402

EXPECTED_KEYS = {
    "wanted:210031", "wanted:210077", "wanted:210102",
    "saramin:48211903", "saramin:48219547",
    "jobkorea:45872301", "jobkorea:45880114",
    "notefolio:nf-30219", "notefolio:nf-30251",
}
# Deliberately-excluded noise in the fixtures (non-design postings):
EXCLUDED_KEYS = {
    "wanted:210145",        # backend engineer
    "saramin:48225110",     # tax accountant
    "jobkorea:45890777",    # sales manager
}


def _config():
    cfg = crawl.load_config()
    # The self-test is OFFLINE and adapter-complete: pin all four boards and
    # fixture mode, regardless of the runtime config (which may be live and
    # narrowed to a subset of boards, e.g. Phase-1 = wanted only).
    cfg.setdefault("boards", {})
    cfg["boards"]["enabled"] = ["wanted", "saramin", "jobkorea", "notefolio"]
    cfg["boards"]["mode"] = "fixture"
    cfg["search_terms"] = ["디자인", "UX", "VMD", "3D", "XR", "ArchViz", "모션"]
    return cfg


def main() -> int:
    cfg = _config()
    tmp = Path(tempfile.mkdtemp(prefix="scraper_selftest_"))
    urls_path = tmp / "job_urls.jsonl"
    cache_dir = tmp / "raw_cache"
    try:
        # -- stage 1: discover ------------------------------------------------
        new = crawl.discover(cfg, out_path=urls_path, sleep=0)
        keys = {u.key for u in new}
        assert keys == EXPECTED_KEYS, f"discover keys mismatch: {keys ^ EXPECTED_KEYS}"
        assert not (keys & EXCLUDED_KEYS), "non-design postings leaked into discover"

        # each is a valid C1 and round-trips through contracts
        for u in new:
            assert isinstance(u, JobUrl)
            assert u.board and u.job_id and u.url
            assert from_dict(JobUrl, to_dict(u)) == u, f"C1 round-trip failed for {u.key}"

        # job_urls.jsonl is real JSONL of C1 records
        on_disk = list(read_jsonl(urls_path, JobUrl))
        assert len(on_disk) == len(EXPECTED_KEYS)
        assert all(isinstance(r, JobUrl) for r in on_disk)
        assert {r.key for r in on_disk} == EXPECTED_KEYS

        # resume: a second discover discovers nothing new
        again = crawl.discover(cfg, out_path=urls_path, sleep=0)
        assert again == [], f"resume should skip seen urls, got {[u.key for u in again]}"

        # -- stage 2: fetch ---------------------------------------------------
        fetched = crawl.fetch(cfg, urls_path=urls_path, cache_dir=cache_dir, sleep=0)
        fkeys = {r.key for r in fetched}
        assert fkeys == EXPECTED_KEYS, f"fetch keys mismatch: {fkeys ^ EXPECTED_KEYS}"

        for r in fetched:
            assert isinstance(r, RawPosting)
            assert r.board and r.job_id and r.url and r.fetched_at
            # a posting must carry SOMETHING raw for the LLM to extract
            assert (r.raw_json is not None) or bool(r.raw_text), f"{r.key} has no raw payload"
            assert from_dict(RawPosting, to_dict(r)) == r, f"C2 round-trip failed for {r.key}"
            # cached file round-trips off disk as a valid C2
            loaded = crawl.read_raw(r.board, r.job_id, cache_dir=cache_dir)
            assert isinstance(loaded, RawPosting) and loaded.key == r.key

        # HTML boards carried raw_text; JSON boards carried raw_json
        by_key = {r.key: r for r in fetched}
        assert by_key["saramin:48211903"].raw_text, "saramin should carry raw_text (JD HTML)"
        assert by_key["jobkorea:45872301"].raw_text, "jobkorea should carry raw_text (HTML)"
        assert by_key["wanted:210031"].raw_json, "wanted should carry raw_json (API)"
        assert by_key["notefolio:nf-30219"].raw_json, "notefolio should carry raw_json (API)"

        # resume: a second fetch fetches nothing new
        again_f = crawl.fetch(cfg, urls_path=urls_path, cache_dir=cache_dir, sleep=0)
        assert again_f == [], f"resume should skip cached postings, got {[r.key for r in again_f]}"

        print("test_scraper: PASS")
        print(f"  discover : {len(new)} C1 JobUrl records (round-trip OK, resume OK)")
        print(f"  fetch    : {len(fetched)} C2 RawPosting records (round-trip OK, resume OK)")
        print(f"  filtered : {len(EXCLUDED_KEYS)} non-design postings correctly excluded")
        print(f"  config   : boards={crawl.enabled_boards(cfg)} "
              f"rate_limit={crawl.rate_limit_seconds(cfg)}s "
              f"terms={len(crawl.search_terms(cfg))}")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
