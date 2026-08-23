"""Dependency-free reports selectively adapted from the audited reporter."""

from __future__ import annotations

import csv
import html
import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

from market_aligner.assessment.scoring import ScoreResult
from market_aligner.domain.contracts import Vacancy
from market_aligner.profiler.schema import validate_profile_id


@dataclass(frozen=True)
class RankedVacancy:
    vacancy: Vacancy
    score: ScoreResult

    def __post_init__(self) -> None:
        if self.vacancy.key != self.score.job_key:
            raise ValueError("vacancy and score job keys differ")


@dataclass(frozen=True)
class ReportPaths:
    jobs_csv: Path
    requirements_csv: Path
    scatter_html: Path


def skill_frequency(ranked: Sequence[RankedVacancy]) -> list[dict[str, Any]]:
    total = len(ranked)
    required: Counter[str] = Counter()
    preferred: Counter[str] = Counter()
    frequency: Counter[str] = Counter()
    by_track: dict[str, Counter[str]] = defaultdict(Counter)
    for item in ranked:
        required_set = {skill.strip() for skill in item.vacancy.required_skills if skill.strip()}
        preferred_set = {skill.strip() for skill in item.vacancy.preferred_skills if skill.strip()}
        for skill in required_set:
            required[skill] += 1
        for skill in preferred_set:
            preferred[skill] += 1
        for skill in required_set | preferred_set:
            frequency[skill] += 1
            by_track[skill][item.score.track] += 1
    ordered = sorted(
        frequency.items(),
        key=lambda item: (
            -item[1],
            -required[item[0]],
            -preferred[item[0]],
            item[0].casefold(),
        ),
    )
    return [
        {
            "skill": skill,
            "required_frequency": required[skill],
            "preferred_frequency": preferred[skill],
            "any_frequency": count,
            "pct_of_postings": round(100 * count / total, 1) if total else 0.0,
            "top_tracks": ", ".join(
                f"{track}({track_count})"
                for track, track_count in by_track[skill].most_common(3)
            ),
        }
        for skill, count in ordered
    ]


def write_reports(
    profile_id: str,
    rows: Sequence[RankedVacancy],
    output_root: str | Path,
) -> ReportPaths:
    validate_profile_id(profile_id)
    if any(item.score.profile_id != profile_id for item in rows):
        raise ValueError("report cannot mix profile IDs")
    root = Path(output_root) / profile_id
    root.mkdir(parents=True, exist_ok=True)
    paths = ReportPaths(
        jobs_csv=root / "jobs_ranked.csv",
        requirements_csv=root / "requirements_ranked.csv",
        scatter_html=root / "opportunity_fit.html",
    )
    ranked = sorted(rows, key=lambda item: item.score.final, reverse=True)
    _write_jobs(ranked, paths.jobs_csv)
    _write_requirements(ranked, paths.requirements_csv)
    _write_scatter(profile_id, ranked, paths.scatter_html)
    return paths


def _write_jobs(rows: Sequence[RankedVacancy], path: Path) -> None:
    fields = (
        "rank",
        "board",
        "job_id",
        "url",
        "title",
        "company",
        "location",
        "track",
        "fit",
        "fit_status",
        "opportunity",
        "final",
        "required_skills",
        "preferred_skills",
        "required_qualifications",
        "preferred_qualifications",
    )
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for index, item in enumerate(rows, 1):
            writer.writerow(
                {
                    "rank": index,
                    "board": item.vacancy.board,
                    "job_id": item.vacancy.job_id,
                    "url": item.vacancy.url,
                    "title": item.vacancy.title,
                    "company": item.vacancy.company,
                    "location": item.vacancy.location,
                    "track": item.score.track,
                    "fit": round(item.score.fit, 6),
                    "fit_status": item.score.fit_status.value,
                    "opportunity": round(item.score.opportunity, 6),
                    "final": round(item.score.final, 4),
                    "required_skills": json.dumps(item.vacancy.required_skills, ensure_ascii=False),
                    "preferred_skills": json.dumps(item.vacancy.preferred_skills, ensure_ascii=False),
                    "required_qualifications": json.dumps(
                        item.vacancy.required_qualifications,
                        ensure_ascii=False,
                    ),
                    "preferred_qualifications": json.dumps(
                        item.vacancy.preferred_qualifications,
                        ensure_ascii=False,
                    ),
                }
            )


def _write_requirements(rows: Sequence[RankedVacancy], path: Path) -> None:
    fields = (
        "skill",
        "required_frequency",
        "preferred_frequency",
        "any_frequency",
        "pct_of_postings",
        "top_tracks",
    )
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(skill_frequency(rows))


def _write_scatter(profile_id: str, rows: Sequence[RankedVacancy], path: Path) -> None:
    points = [
        {
            "job_key": item.vacancy.key,
            "title": item.vacancy.title,
            "company": item.vacancy.company,
            "url": item.vacancy.url,
            "track": item.score.track,
            "fit": item.score.fit,
            "opportunity": item.score.opportunity,
            "final": item.score.final,
            "fit_status": item.score.fit_status.value,
        }
        for item in rows
    ]
    data = json.dumps(points, ensure_ascii=False).replace("</", "<\\/")
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Opportunity vs Fit</title><style>
body{{font:14px system-ui;margin:0;background:#0b1020;color:#eef2ff}}main{{max-width:1100px;margin:auto;padding:24px}}
#plot{{position:relative;height:620px;border:1px solid #334155;background:linear-gradient(90deg,transparent 49.9%,#334155 50%,transparent 50.1%),linear-gradient(transparent 49.9%,#334155 50%,transparent 50.1%)}}
.point{{position:absolute;width:12px;height:12px;border:0;border-radius:50%;background:#38bdf8;transform:translate(-50%,50%);cursor:pointer}}
.point:hover,.point:focus{{width:18px;height:18px;background:#fbbf24}}#detail{{min-height:74px;margin-top:16px;padding:12px;background:#111827}}
.axis{{color:#94a3b8}}a{{color:#7dd3fc}}</style></head><body><main>
<h1>Opportunity vs Fit</h1><p class="axis">Profile {html.escape(profile_id)} · fit is uncalibrated · select a point for details.</p>
<div id="plot" role="img" aria-label="Opportunity versus uncalibrated fit scatter plot"></div><div id="detail">No job selected.</div>
<script>const points={data};const plot=document.querySelector('#plot'),detail=document.querySelector('#detail');
for(const p of points){{const b=document.createElement('button');b.className='point';b.style.left=`${{p.fit*100}}%`;b.style.bottom=`${{p.opportunity*100}}%`;b.title=`${{p.title}} — ${{p.company}}`;b.onclick=()=>{{detail.innerHTML='';const a=document.createElement('a');a.href=p.url;a.textContent=p.title+' — '+p.company;a.target='_blank';detail.append(a,document.createElement('br'),`Track: ${{p.track}} · Fit: ${{p.fit.toFixed(3)}} (${{p.fit_status}}) · Opportunity: ${{p.opportunity.toFixed(3)}} · Final: ${{p.final.toFixed(1)}}`);}};plot.appendChild(b);}}
</script></main></body></html>"""
    path.write_text(document, encoding="utf-8")
