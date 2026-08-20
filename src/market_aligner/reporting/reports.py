"""Dependency-free reports selectively adapted from the audited reporter."""

from __future__ import annotations

import csv
import html
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from market_aligner.assessment.scoring import ScoreResult
from market_aligner.domain.contracts import Vacancy
from market_aligner.profiler.schema import validate_profile_id


@dataclass(frozen=True)
class RankedVacancy:
    vacancy: Vacancy
    score: ScoreResult
    preference_classification: str = "unknown_other"
    preference_rank: int = 999

    def __post_init__(self) -> None:
        if self.vacancy.key != self.score.job_key:
            raise ValueError("vacancy and score job keys differ")


@dataclass(frozen=True)
class ReportPaths:
    jobs_csv: Path
    ranked_json: Path
    requirements_csv: Path
    scatter_html: Path
    scatter_png: Path


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
    *,
    namespace: str | None = None,
) -> ReportPaths:
    validate_profile_id(profile_id)
    if any(item.score.profile_id != profile_id for item in rows):
        raise ValueError("report cannot mix profile IDs")
    if namespace is not None and not re.fullmatch(r"scope_[0-9a-f]{64}", namespace):
        raise ValueError("report namespace must be a canonical scope digest")
    root = Path(output_root) / profile_id
    if namespace is not None:
        root = root / "processing-scopes" / namespace
    root.mkdir(parents=True, exist_ok=True)
    paths = ReportPaths(
        jobs_csv=root / "jobs_ranked.csv",
        ranked_json=root / "fit_opportunity_ranked.json",
        requirements_csv=root / "requirements_ranked.csv",
        scatter_html=root / "opportunity_fit.html",
        scatter_png=root / "opportunity_fit.png",
    )
    ranked = sorted(
        rows,
        key=lambda item: (item.preference_rank, -item.score.final, item.vacancy.key),
    )
    _write_jobs(ranked, paths.jobs_csv)
    _write_ranked_json(profile_id, ranked, paths.ranked_json)
    _write_requirements(ranked, paths.requirements_csv)
    _write_scatter(profile_id, ranked, paths.scatter_html)
    _write_scatter_png(profile_id, ranked, paths.scatter_png)
    return paths


def _write_ranked_json(profile_id: str, rows: Sequence[RankedVacancy], path: Path) -> None:
    payload = {
        "fit_status": "uncalibrated",
        "jobs": [
            {
                "company": item.vacancy.company,
                "final": item.score.final,
                "fit": item.score.fit,
                "job_key": item.vacancy.key,
                "opportunity": item.score.opportunity,
                "preference_classification": item.preference_classification,
                "preference_rank": item.preference_rank,
                "title": item.vacancy.title,
                "track": item.score.track,
                "url": item.vacancy.url,
            }
            for item in rows
        ],
        "profile_id": profile_id,
        "schema_version": "market-aligner.fit-opportunity-ranked.v1",
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


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
        "preference_classification",
        "preference_rank",
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
                    "preference_classification": item.preference_classification,
                    "preference_rank": item.preference_rank,
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
            "preference_classification": item.preference_classification,
            "preference_rank": item.preference_rank,
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
for(const p of points){{const b=document.createElement('button');b.className='point';b.style.left=`${{p.fit*100}}%`;b.style.bottom=`${{p.opportunity*100}}%`;b.title=`${{p.title}} — ${{p.company}}`;b.onclick=()=>{{detail.innerHTML='';const a=document.createElement('a');a.href=p.url;a.textContent=p.title+' — '+p.company;a.target='_blank';detail.append(a,document.createElement('br'),`Preference: ${{p.preference_classification}} · Track: ${{p.track}} · Fit: ${{p.fit.toFixed(3)}} (${{p.fit_status}}) · Opportunity: ${{p.opportunity.toFixed(3)}} · Final: ${{p.final.toFixed(1)}}`);}};plot.appendChild(b);}}
</script></main></body></html>"""
    path.write_text(document, encoding="utf-8")


def _write_scatter_png(
    profile_id: str,
    rows: Sequence[RankedVacancy],
    path: Path,
) -> None:
    """Render a restrained, antialiased, headless delivery artifact."""
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure
    from matplotlib.ticker import PercentFormatter

    ink, muted, blue, accent = "#172033", "#667085", "#2563A8", "#C47A20"
    figure = Figure(figsize=(12, 8), dpi=150, facecolor="#F7F8FA")
    FigureCanvasAgg(figure)
    axis = figure.add_axes((0.105, 0.14, 0.84, 0.70), facecolor="#FFFFFF")
    axis.set_xlim(-0.02, 1.02)
    axis.set_ylim(-0.02, 1.02)
    axis.xaxis.set_major_formatter(PercentFormatter(1.0))
    axis.yaxis.set_major_formatter(PercentFormatter(1.0))
    axis.set_xticks((0, 0.25, 0.5, 0.75, 1.0))
    axis.set_yticks((0, 0.25, 0.5, 0.75, 1.0))
    axis.grid(True, color="#E5E9F0", linewidth=0.8, zorder=0)
    for side in ("top", "right"):
        axis.spines[side].set_visible(False)
    for side in ("bottom", "left"):
        axis.spines[side].set_color("#AEB7C4")
        axis.spines[side].set_linewidth(0.9)
    axis.tick_params(colors=muted, labelsize=9, length=0, pad=8)
    axis.set_xlabel("Candidate fit (uncalibrated)", color=ink, fontsize=10.5, labelpad=13)
    axis.set_ylabel("Opportunity quality", color=ink, fontsize=10.5, labelpad=13)
    figure.text(0.105, 0.925, "Job opportunities: fit vs opportunity", color=ink,
                fontsize=19, fontweight="bold", fontfamily="DejaVu Sans")
    figure.text(0.105, 0.885,
                f"{len(rows)} eligible roles · prioritised for a first professional role",
                color=muted, fontsize=10.5, fontfamily="DejaVu Sans")
    fits = [min(1.0, max(0.0, item.score.fit)) for item in rows]
    opportunities = [min(1.0, max(0.0, item.score.opportunity)) for item in rows]
    if rows:
        colors = [accent if index == 0 else blue for index in range(len(rows))]
        sizes = [78 if index == 0 else 50 for index in range(len(rows))]
        axis.scatter(fits, opportunities, s=sizes, c=colors, edgecolors="#FFFFFF",
                     linewidths=1.2, alpha=0.94, zorder=3)
        _label_top_points(axis, rows, fits, opportunities, ink)
    else:
        axis.text(0.5, 0.5, "No eligible roles in this processing scope", ha="center",
                  va="center", color=muted, fontsize=12, fontfamily="DejaVu Sans",
                  transform=axis.transAxes)
    figure.text(0.945, 0.055,
                "Labels show highest-priority roles · exact ranking is available in the companion table",
                ha="right", color=muted, fontsize=8.5, fontfamily="DejaVu Sans")
    figure.savefig(path, format="png", dpi=150, facecolor=figure.get_facecolor(),
                   metadata={"Software": "Market Aligner", "Title": "Fit vs Opportunity",
                             "Profile": profile_id})


def _label_top_points(
    axis: Any,
    rows: Sequence[RankedVacancy],
    fits: list[float],
    opportunities: list[float],
    ink: str,
) -> None:
    """Place top labels greedily using rendered bounds and deterministic candidates."""
    axis.figure.canvas.draw()
    renderer = axis.figure.canvas.get_renderer()
    plot_bounds = axis.get_window_extent(renderer)
    placed: list[Any] = []
    candidates = ((10, 10), (10, -27), (-10, 10), (-10, -27), (18, 30), (-18, 30))
    for item, fit, opportunity in list(zip(rows, fits, opportunities))[:8]:
        title = _short_label(item.vacancy.title, 38)
        company = _short_label(item.vacancy.company, 28)
        label = f"{title}\n{company}" if company else title
        selected = None
        for dx, dy in candidates:
            annotation = axis.annotate(
                label, xy=(fit, opportunity), xytext=(dx, dy), textcoords="offset points",
                ha="left" if dx >= 0 else "right", va="bottom" if dy >= 0 else "top",
                color=ink, fontsize=7.8, fontfamily="DejaVu Sans", linespacing=1.25,
                bbox={"boxstyle": "round,pad=0.32,rounding_size=0.12",
                      "facecolor": "#FFFFFF", "edgecolor": "#D7DCE5",
                      "linewidth": 0.6, "alpha": 0.97},
                arrowprops={"arrowstyle": "-", "color": "#AEB7C4", "linewidth": 0.6},
                zorder=4,
            )
            axis.figure.canvas.draw()
            bounds = annotation.get_window_extent(renderer).expanded(1.03, 1.10)
            if (plot_bounds.contains(*bounds.get_points()[0])
                    and plot_bounds.contains(*bounds.get_points()[1])
                    and not any(bounds.overlaps(other) for other in placed)):
                selected = bounds
                break
            annotation.remove()
        if selected is not None:
            placed.append(selected)


def _short_label(value: str, limit: int) -> str:
    compact = " ".join(value.split())
    return compact if len(compact) <= limit else compact[: limit - 1].rstrip() + "…"
