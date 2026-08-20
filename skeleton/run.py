"""
skeleton/run.py — the resumable pipeline runner + CLI (Architecture.md: the
orchestrator owns "the pipeline runner, the config, resume/caching/logging").

Five stages, each idempotent and cached to disk so a crash resumes without
redoing the expensive work (Build-Spec §1):

    discover → fetch → extract → score → report

    [discover] search config → job_urls.jsonl        (C1, keyed board:id)
    [fetch]    each detail    → raw_cache/{board}/{id}.json  (C2)
    [extract]  LLM pass       → jobs.jsonl            (C3 + confidence)
    [score]    pure maths     → jobs_scored.jsonl     (C4)
    [report]   reporter       → outputs/*.xlsx + fit_opportunity.png

Design constraints honoured here:
  • Everything is read from skeleton/config.yaml — nothing hardcoded.
  • Stages are skippable (--only / --skip) and RESUMABLE: a stage whose output
    already exists is skipped unless --force, and fetch/extract skip per-item
    work that's already cached (a `seen` set keyed board:id).
  • Degrades gracefully if a sibling module isn't present yet: discover/fetch
    need the scraper, extract needs the llm module — each is behind an import
    guard, so on a skeleton-only checkout the runner still scores + reports from
    a fixture (or from whatever jobs.jsonl already exists).
  • score + report are wired FOR REAL (scoring.py + reporter.py); the scraper
    and llm calls are wired through the contracts with a clear hook where the
    live module plugs in.

Run from the repo root:

    python skeleton/run.py all
    python skeleton/run.py score report --force
    python skeleton/run.py --only report
    python skeleton/run.py --fixture skeleton/fixtures/jobs_20.jsonl score report
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import contracts  # noqa: E402
from contracts import (  # noqa: E402
    JobUrl, RawPosting, JobRow, ScoredRow, CandidateFitProfile,
    read_jsonl, write_jsonl, to_dict, from_dict,
)
import scoring  # noqa: E402
import reporter  # noqa: E402
from skeleton.configuration import load_config  # noqa: E402

STAGES: tuple[str, ...] = ("discover", "fetch", "extract", "score", "report")


# --------------------------------------------------------------------------- #
# Config + paths.
# --------------------------------------------------------------------------- #
@dataclass
class Paths:
    """All on-disk locations, derived from config + the repo root."""

    root: Path
    job_urls: Path
    raw_cache: Path
    processing_job_urls: Path | None
    jobs: Path
    jobs_scored: Path
    outputs: Path

    @classmethod
    def build(cls, root: Path, cfg: dict[str, Any]) -> "Paths":
        io = dict((cfg or {}).get("io", {}) or {})
        # Scraper- and llm-owned stage outputs live in scraper/data/ (their
        # folder); the skeleton only READS them and never creates that folder
        # itself. The one intermediate the SKELETON owns — jobs_scored.jsonl,
        # the C4 output of its own scoring stage — defaults inside skeleton/data
        # so a standalone skeleton run never writes into a sibling's folder.
        scraper_data = root / "scraper" / "data"
        skeleton_data = root / "skeleton" / "data"
        return cls(
            root=root,
            job_urls=root / io.get("job_urls", str(scraper_data / "job_urls.jsonl")),
            raw_cache=root / io.get("raw_cache", str(scraper_data / "raw_cache")),
            processing_job_urls=(
                root / str(io["processing_job_urls"])
                if io.get("processing_job_urls") else None
            ),
            jobs=root / io.get("jobs", str(scraper_data / "jobs.jsonl")),
            jobs_scored=root / io.get("jobs_scored", str(skeleton_data / "jobs_scored.jsonl")),
            outputs=root / io.get("outputs_dir", "outputs"),
        )


@dataclass
class RunContext:
    cfg: dict[str, Any]
    paths: Paths
    force: bool = False
    fixture: Optional[Path] = None
    log: Callable[[str], None] = field(default=lambda m: print(m, flush=True))


# --------------------------------------------------------------------------- #
# Optional sibling modules — import guards so the skeleton runs alone.
# --------------------------------------------------------------------------- #
def _try_scraper():
    """The scraper module's adapter loader, or None if the module isn't here."""
    try:
        from scraper.adapters.base import load_adapter  # type: ignore
        return load_adapter
    except Exception:  # noqa: BLE001 - any import failure means "not available"
        return None


def _try_llm():
    """The llm module's extract/rate capabilities, or None if absent."""
    try:
        from llm.capabilities import extract_job, rate_axes  # type: ignore
        return extract_job, rate_axes
    except Exception:  # noqa: BLE001
        return None


def _profile_block(cfg: dict[str, Any]) -> dict[str, Any]:
    """Load the candidate's public-safe evidence profile for LLM context.

    Prefer the profiler's generated, privacy-screened projection.  The compact
    config block remains a fallback so the skeleton can still run by itself.
    """
    configured = os.environ.get("CANDIDATE_PROFILE_PATH") or str(
        ((cfg or {}).get("io", {}) or {}).get(
            "candidate_profile", "profiler/data/candidate_profile.yaml"
        )
    )
    profile_path = Path(configured)
    if not profile_path.is_absolute():
        profile_path = _REPO_ROOT / profile_path
    try:
        from profiler.candidate_profile import load_public_llm_context  # type: ignore

        return load_public_llm_context(profile_path)
    except (ImportError, OSError, ValueError, TypeError):
        return dict((cfg or {}).get("candidate_fit_profile", {}) or {})


def _assemble_job_row(rp: RawPosting, extracted: dict[str, Any], ratings: dict[str, Any]) -> JobRow:
    """Marshal the llm's extract + rate dicts into a C3 JobRow.

    Provenance (board/job_id/url/posted_at/scraped_at) and dedup_key are the
    caller's to own (the llm module deliberately omits them). We fill them from
    the RawPosting, layer the extracted schema fields, then the axis ratings.
    """
    merged: dict[str, Any] = {
        "board": rp.board,
        "job_id": rp.job_id,
        "url": rp.url,
        "scraped_at": rp.fetched_at,
    }
    if isinstance(rp.raw_json, dict):
        merged["posted_at"] = rp.raw_json.get("updated_at")
    merged.update({k: v for k, v in (extracted or {}).items() if v is not None})
    merged.update({k: v for k, v in (ratings or {}).items() if v is not None})
    if not merged.get("job_description"):
        raw_description = rp.raw_text or ""
        if isinstance(rp.raw_json, dict):
            raw_description = str(
                rp.raw_json.get("content_text")
                or rp.raw_json.get("jobDescription")
                or rp.raw_json.get("description")
                or raw_description
                or ""
            )
        try:
            from scraper.adapters.uk_common import plain_text  # type: ignore
            merged["job_description"] = plain_text(raw_description)
        except ImportError:
            merged["job_description"] = raw_description
    if not merged.get("dedup_key"):
        company = str(merged.get("company", "")).strip().lower()
        title = str(merged.get("job_title", "")).strip().lower()
        merged["dedup_key"] = f"{company}|{title}"
    return from_dict(JobRow, merged)


# --------------------------------------------------------------------------- #
# Stage 1 — discover  (scraper: search config → C1 job_urls.jsonl)
# --------------------------------------------------------------------------- #
def stage_discover(ctx: RunContext) -> Optional[Path]:
    out = ctx.paths.job_urls
    if out.exists() and not ctx.force:
        ctx.log(f"[discover] skip — {out} exists (use --force to redo)")
        return out

    load_adapter = _try_scraper()
    if load_adapter is None:
        ctx.log("[discover] scraper module not present — skipping (sibling not built yet)")
        return None

    boards_cfg = dict(ctx.cfg.get("boards", {}) or {})
    boards = list(boards_cfg.get("enabled", []) or [])
    terms = list(ctx.cfg.get("search_terms", []) or [])
    rate = float(boards_cfg.get("rate_limit_seconds", 0) or 0)
    # boards.mode: "live" (default — real HTTP) or "fixture" (offline test data).
    live = str(boards_cfg.get("mode", "live")).lower() != "fixture"
    ctx.log(f"[discover] mode={'live' if live else 'fixture'} boards={boards} cap=none")

    existing = list(read_jsonl(out, JobUrl)) if out.exists() else []
    seen: set[str] = {row.key for row in existing}
    urls: list[JobUrl] = list(existing)
    for board in boards:
        try:
            adapter = load_adapter(board, config=(ctx.cfg.get(board) or {}))
        except Exception as e:  # noqa: BLE001 - a missing board adapter shouldn't kill the run
            ctx.log(f"[discover] board '{board}' unavailable: {e}")
            continue
        try:
            for ju in adapter.discover(terms, live=live):
                if ju.key in seen:
                    continue
                seen.add(ju.key)
                urls.append(ju)
        except Exception as e:  # noqa: BLE001 — a mid-crawl blip must not kill the run
            ctx.log(f"[discover] board '{board}' failed mid-crawl: {e} — "
                    f"keeping the {len(urls)} urls collected so far")
        if rate:
            time.sleep(rate)  # polite between boards; the adapter paces within a board

    n = write_jsonl(out, urls)
    ctx.log(f"[discover] wrote {n} job urls → {out}")
    return out


# --------------------------------------------------------------------------- #
# Stage 2 — fetch  (scraper: each C1 → raw_cache/{board}/{id}.json = C2)
# --------------------------------------------------------------------------- #
def _raw_path(ctx: RunContext, board: str, job_id: str) -> Path:
    return ctx.paths.raw_cache / board / f"{job_id}.json"


def stage_fetch(ctx: RunContext) -> Optional[Path]:
    if not ctx.paths.job_urls.exists():
        ctx.log("[fetch] no job_urls.jsonl — run discover first (skipping)")
        return None

    load_adapter = _try_scraper()
    if load_adapter is None:
        ctx.log("[fetch] scraper module not present — skipping")
        return None

    boards_cfg = dict(ctx.cfg.get("boards", {}) or {})
    rate = float(boards_cfg.get("rate_limit_seconds", 0) or 0)
    live = str(boards_cfg.get("mode", "live")).lower() != "fixture"
    urls = list(read_jsonl(ctx.paths.job_urls, JobUrl))
    fetched = skipped = failed = 0
    adapters: dict[str, Any] = {}
    for ju in urls:
        dest = _raw_path(ctx, ju.board, ju.job_id)
        if dest.exists() and not ctx.force:          # per-item resume (seen set on disk)
            skipped += 1
            continue
        if ju.board not in adapters:
            try:
                adapters[ju.board] = load_adapter(ju.board, config=(ctx.cfg.get(ju.board) or {}))
            except Exception as e:  # noqa: BLE001
                ctx.log(f"[fetch] board '{ju.board}' unavailable: {e}")
                adapters[ju.board] = None
        adapter = adapters[ju.board]
        if adapter is None:
            continue
        try:
            rp: RawPosting = adapter.fetch(ju, live=live)
        except Exception as e:  # noqa: BLE001 — one bad posting must not kill the run
            failed += 1
            ctx.log(f"[fetch] FAILED {ju.key}: {e}")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        write_jsonl(dest, [rp])  # one C2 record per file
        fetched += 1
        if rate:
            time.sleep(rate)
    suffix = f", {failed} failed (resume will retry them)" if failed else ""
    ctx.log(f"[fetch] fetched {fetched}, skipped {skipped} cached{suffix} → {ctx.paths.raw_cache}")
    return ctx.paths.raw_cache


# --------------------------------------------------------------------------- #
# Stage 3 — extract  (llm: C2 → C3 jobs.jsonl, structured + rated)
# --------------------------------------------------------------------------- #
def _iter_raw_postings(ctx: RunContext):
    base = ctx.paths.raw_cache
    if not base.exists():
        return
    selection = ctx.paths.processing_job_urls or ctx.paths.job_urls
    if ctx.paths.processing_job_urls is not None and not selection.exists():
        raise RuntimeError(
            f"deterministic viability input is missing: {selection}; "
            "run scripts/prepare_jobs_for_llm.py first"
        )
    allowed = {
        rec.key for rec in read_jsonl(selection, JobUrl)
    } if selection.exists() else set()
    for f in sorted(base.rglob("*.json")):
        if "_scrapling_failures" in f.parts:
            continue
        try:
            records = list(read_jsonl(f, RawPosting))
        except (OSError, ValueError) as error:
            ctx.log(
                f"[extract] skip malformed raw cache file {f}: "
                f"{type(error).__name__}: {error}"
            )
            continue
        for rec in records:
            if not allowed or rec.key in allowed:
                yield rec


def stage_extract(ctx: RunContext) -> Optional[Path]:
    out = ctx.paths.jobs

    # INCREMENTAL RESUME: rows already in jobs.jsonl are kept as-is and their
    # postings are never re-sent to the model — only raw postings without a row
    # get extracted. This makes incremental crawls cheap and, crucially, makes
    # the handoff between machines/backends free: rows extracted by claude_cli
    # on one laptop are reused verbatim by codex_cli on another. --force
    # discards existing rows and redoes everything.
    existing: dict[str, JobRow] = {}
    if out.exists() and not ctx.force:
        existing = {r.key: r for r in read_jsonl(out, JobRow)}
        if ctx.paths.processing_job_urls and ctx.paths.processing_job_urls.exists():
            allowed = {r.key for r in read_jsonl(ctx.paths.processing_job_urls, JobUrl)}
            existing = {key: row for key, row in existing.items() if key in allowed}

    llm = _try_llm()
    if llm is None:
        ctx.log("[extract] llm module not present — skipping (sibling not built yet)")
        return None
    extract_job, rate_axes = llm

    # Activate the CONFIGURED backend (llm.backend in config.yaml). Without this
    # the llm module's default client is the offline MockBackend — canned answers.
    # (Bug caught 2026-07-14: a live run extracted 22 real postings in 0.09s.)
    try:
        from llm.client import LLMClient, make_backend  # type: ignore
        from llm import capabilities as _caps  # type: ignore
        llm_cfg = dict((ctx.cfg.get("llm", {}) or {}))
        client = LLMClient(
            backend=make_backend(llm_cfg),
            model=str(llm_cfg.get("model", "REPLACE_ME") or "REPLACE_ME"),
            temperature=float(llm_cfg.get("temperature", 0.0) or 0.0),
            max_retries=int(llm_cfg.get("max_retries", 3) or 3),
            cache_enabled=bool(llm_cfg.get("cache", True)),
        )
        _caps.set_client(client)
        ctx.log(f"[extract] llm backend={client.backend.name} model={client.model}")
        live_boards = str((ctx.cfg.get("boards", {}) or {}).get("mode", "live")).lower() != "fixture"
        if live_boards and client.backend.name == "mock":
            ctx.log("[extract] deterministic candidate rules active — use claude_cli "
                    "later for a deeper semantic rerank")
    except Exception as e:  # noqa: BLE001
        ctx.log(f"[extract] llm client init failed ({e}) — falling back to module default")

    # Rule-based skill normalisation at assembly time. The prompt asks the model
    # for canonical ids, but models drift (after_effects vs aftereffects) — the
    # alias table is the authority. Unknown terms are snake_cased so at least
    # identical spellings merge; extend config.skill_aliases from the report.
    aliases = dict(ctx.cfg.get("skill_aliases", {}) or {})
    def _canon(term: str) -> str:
        t = str(term).strip()
        if not t:
            return ""
        try:
            from llm.capabilities import normalise_skill  # type: ignore
            hit = normalise_skill(t, aliases, llm_fallback=False)
        except Exception:  # noqa: BLE001
            hit = ""
        return hit or t.lower().replace(" ", "_").replace("-", "_")

    def _canon_list(vals: Any) -> list[str]:
        return sorted({c for c in (_canon(v) for v in (vals or [])) if c})

    raws = list(_iter_raw_postings(ctx))
    if not raws:
        ctx.log("[extract] no cached raw postings — run fetch first (skipping)")
        return None
    todo = [rp for rp in raws if rp.key not in existing]
    if existing:
        ctx.log(f"[extract] resume — {len(existing)} rows already extracted, {len(todo)} new")
    if not todo:
        ctx.log(f"[extract] nothing new to extract → {out}")
        return out

    profile_block = _profile_block(ctx.cfg)
    rows: list[JobRow] = []
    failed = 0
    for idx, rp in enumerate(todo, 1):
        # HOOK: llm.extract_job turns a C2 raw posting (dict form) into the
        # job_extract schema fields; llm.rate_axes fills the 0–10 axis ratings.
        # Both are cached inside the llm module by (prompt-hash, input-hash), so
        # re-runs are cheap. The llm returns plain dicts (no provenance); we
        # marshal them back into a C3 JobRow here. One bad posting must not
        # kill the run: failures are logged and skipped, the rest proceed.
        try:
            # Sol sees the complete career-relevant dossier for every vacancy,
            # including extraction fields that require personal judgement
            # (why_it_fits and skills_to_learn).
            extracted = extract_job(to_dict(rp), profile_block)
            extracted["required_software"] = _canon_list(extracted.get("required_software"))
            extracted["required_skills"] = _canon_list(extracted.get("required_skills"))
            extracted["preferred_skills"] = _canon_list(extracted.get("preferred_skills"))
            extracted["skills_to_learn"] = _canon_list(extracted.get("skills_to_learn"))
            ratings = rate_axes(extracted, profile_block)
        except Exception as e:  # noqa: BLE001 — per-row fault tolerance
            failed += 1
            ctx.log(f"[extract] FAILED {rp.key} ({idx}/{len(todo)}): {e}")
            continue
        rows.append(_assemble_job_row(rp, extracted, ratings))
        # Persist after every successful Sol judgement. If the process is
        # interrupted, rerunning without --force resumes from these rows and
        # the LLM cache covers any completed calls.
        write_jsonl(out, list(existing.values()) + rows)
        ctx.log(f"[extract] {rp.key} ({idx}/{len(todo)}) → {rows[-1].mapped_career}")

    if failed and not rows and not existing:
        ctx.log(f"[extract] ALL {failed} postings failed — not writing an empty {out}. "
                "Check the errors above (auth? usage limit?) and rerun.")
        return None
    merged = list(existing.values()) + rows
    n = write_jsonl(out, merged)
    suffix = f" ({failed} failed, skipped — rerun resumes them)" if failed else ""
    ctx.log(f"[extract] wrote {n} job rows ({len(rows)} new) → {out}{suffix}")
    return out


# --------------------------------------------------------------------------- #
# Stage 4 — score (scoring.py, C3 + candidate profile → C4)
# --------------------------------------------------------------------------- #
def _load_job_rows(ctx: RunContext) -> list[JobRow]:
    """C3 rows, from the fixture override if given, else jobs.jsonl."""
    src = ctx.fixture if ctx.fixture else ctx.paths.jobs
    if not Path(src).exists():
        return []
    return list(read_jsonl(src, JobRow))


def stage_score(ctx: RunContext) -> Optional[Path]:
    out = ctx.paths.jobs_scored
    if out.exists() and not ctx.force and ctx.fixture is None:
        ctx.log(f"[score] skip — {out} exists (use --force to redo)")
        return out

    rows = _load_job_rows(ctx)
    if not rows:
        ctx.log("[score] no C3 job rows found — run extract, or pass --fixture (skipping)")
        return None

    profile_context = _profile_block(ctx.cfg)
    tracks = dict(profile_context.get("tracks") or {})
    profile_cfg = dict(ctx.cfg)
    if tracks:
        profile_cfg["candidate_fit_profile"] = {
            **tracks,
            "blind_spots": list(profile_context.get("blind_spots") or []),
        }
    profile = CandidateFitProfile.from_config(profile_cfg)
    params = scoring.ScoringParams.from_config(ctx.cfg)
    scored = scoring.score_rows(rows, profile, params)
    n = write_jsonl(out, scored_to_records(scored))
    ctx.log(f"[score] scored {n} rows → {out}")

    # A ±20% sensitivity read on the field ranking (Meta_Plan Phase 3).
    rep = scoring.sensitivity(rows, profile, params, delta=0.2)
    ctx.log(f"[score] {rep.summary()}")
    return out


def scored_to_records(scored: list[ScoredRow]) -> list[dict[str, Any]]:
    """Flatten C4 rows for JSONL — one dict carrying the row + fit/opp/final."""
    return [sr.to_dict() for sr in scored]


def _load_scored_rows(ctx: RunContext) -> list[ScoredRow]:
    """Reconstruct C4 ScoredRow objects from jobs_scored.jsonl (or fixture)."""
    src = ctx.fixture if (ctx.fixture and Path(ctx.fixture).suffix == ".jsonl"
                          and _looks_scored(ctx.fixture)) else ctx.paths.jobs_scored
    if not Path(src).exists():
        return []
    out: list[ScoredRow] = []
    for d in read_jsonl(src):
        out.append(_scored_from_flat(d))
    return out


def _looks_scored(path: str | Path) -> bool:
    try:
        for d in read_jsonl(path):
            return isinstance(d, dict) and "final" in d
    except Exception:  # noqa: BLE001
        return False
    return False


def _scored_from_flat(d: dict[str, Any]) -> ScoredRow:
    """Inverse of ScoredRow.to_dict(): pull fit/opp/final off, rebuild the JobRow."""
    fit = float(d.get("fit", 0.0))
    opp = float(d.get("opportunity", 0.0))
    final = float(d.get("final", 0.0))
    row_data = {k: v for k, v in d.items() if k not in ("fit", "opportunity", "final")}
    row = from_dict(JobRow, row_data)
    return ScoredRow(row=row, fit=fit, opportunity=opp, final=final)


# --------------------------------------------------------------------------- #
# Stage 5 — report  (WIRED FOR REAL: reporter.py, C4 → xlsx + png)
# --------------------------------------------------------------------------- #
def stage_report(ctx: RunContext) -> Optional[Path]:
    scored = _load_scored_rows(ctx)
    if not scored:
        ctx.log("[report] no C4 scored rows — run score first, or pass a scored --fixture (skipping)")
        return None
    paths = reporter.write_reports(scored, output_dir=ctx.paths.outputs)
    ctx.log(f"[report] wrote {paths.jobs_xlsx}")
    ctx.log(f"[report] wrote {paths.requirements_xlsx}")
    ctx.log(f"[report] wrote {paths.shortlist_md}")
    ctx.log(f"[report] wrote {paths.scatter_png} (exists={paths.scatter_png.exists()})")
    return paths.jobs_xlsx


# --------------------------------------------------------------------------- #
# Dispatcher.
# --------------------------------------------------------------------------- #
_STAGE_FNS: dict[str, Callable[[RunContext], Optional[Path]]] = {
    "discover": stage_discover,
    "fetch": stage_fetch,
    "extract": stage_extract,
    "score": stage_score,
    "report": stage_report,
}


def run_stages(stages: list[str], ctx: RunContext) -> None:
    for name in stages:
        fn = _STAGE_FNS[name]
        t0 = time.time()
        fn(ctx)
        ctx.log(f"[{name}] done in {time.time() - t0:.2f}s")


def _resolve_stages(args: argparse.Namespace) -> list[str]:
    if args.only:
        return [args.only]
    requested = args.stages if args.stages and "all" not in args.stages else list(STAGES)
    return [s for s in requested if s not in (args.skip or [])]


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="market-aligner",
        description="market-aligner v1 — resumable stage runner (discover → fetch → extract → score → report)",
    )
    ap.add_argument("stages", nargs="*", default=["all"],
                    help=f"stages to run: {', '.join(STAGES)} or 'all' (default)")
    ap.add_argument("--only", choices=STAGES, help="run exactly one stage")
    ap.add_argument("--skip", nargs="*", choices=STAGES, default=[], help="stages to skip")
    ap.add_argument("--force", action="store_true", help="re-run stages even if outputs exist")
    ap.add_argument("--config", default=str(_HERE / "config.yaml"), help="path to config.yaml")
    ap.add_argument("--root", default=str(_REPO_ROOT), help="repo root for on-disk paths")
    ap.add_argument("--fixture", default=None,
                    help="C3 jobs.jsonl or C4 jobs_scored.jsonl to feed score/report directly")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    root = Path(args.root).resolve()
    ctx = RunContext(
        cfg=cfg,
        paths=Paths.build(root, cfg),
        force=args.force,
        fixture=Path(args.fixture).resolve() if args.fixture else None,
    )

    stages = _resolve_stages(args)
    ctx.log(f"[run] stages: {stages}  force={args.force}  fixture={ctx.fixture}")
    if not cfg.get("meta", {}).get("calibrated", False):
        ctx.log("[run] NOTE: hiring-outcome calibration is pending; raw postings and requirements remain factual source captures.")
    run_stages(stages, ctx)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
