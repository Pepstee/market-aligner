"""Dependency-free reports selectively adapted from the audited reporter."""

from __future__ import annotations

import csv
import html
import json
import struct
import zlib
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
) -> ReportPaths:
    validate_profile_id(profile_id)
    if any(item.score.profile_id != profile_id for item in rows):
        raise ValueError("report cannot mix profile IDs")
    root = Path(output_root) / profile_id
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


_FONT = {
    " ": ("000",) * 7,
    "%": ("10001", "00010", "00100", "01000", "10001", "00000", "00000"),
    "0": ("01110", "10001", "10011", "10101", "11001", "10001", "01110"),
    "1": ("00100", "01100", "00100", "00100", "00100", "00100", "01110"),
    "2": ("01110", "10001", "00001", "00010", "00100", "01000", "11111"),
    "5": ("11111", "10000", "11110", "00001", "00001", "10001", "01110"),
    "7": ("11111", "00001", "00010", "00100", "01000", "01000", "01000"),
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "B": ("11110", "10001", "10001", "11110", "10001", "10001", "11110"),
    "C": ("01111", "10000", "10000", "10000", "10000", "10000", "01111"),
    "D": ("11110", "10001", "10001", "10001", "10001", "10001", "11110"),
    "E": ("11111", "10000", "10000", "11110", "10000", "10000", "11111"),
    "F": ("11111", "10000", "10000", "11110", "10000", "10000", "10000"),
    "I": ("11111", "00100", "00100", "00100", "00100", "00100", "11111"),
    "L": ("10000", "10000", "10000", "10000", "10000", "10000", "11111"),
    "N": ("10001", "11001", "10101", "10011", "10001", "10001", "10001"),
    "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
    "P": ("11110", "10001", "10001", "11110", "10000", "10000", "10000"),
    "R": ("11110", "10001", "10001", "11110", "10100", "10010", "10001"),
    "S": ("01111", "10000", "10000", "01110", "00001", "00001", "11110"),
    "T": ("11111", "00100", "00100", "00100", "00100", "00100", "00100"),
    "U": ("10001", "10001", "10001", "10001", "10001", "10001", "01110"),
    "V": ("10001", "10001", "10001", "10001", "10001", "01010", "00100"),
    "Y": ("10001", "10001", "01010", "00100", "00100", "00100", "00100"),
}


def _write_scatter_png(
    profile_id: str,
    rows: Sequence[RankedVacancy],
    path: Path,
) -> None:
    """Write a deterministic, headless RGB PNG without an optional plotting runtime."""
    width, height = 1200, 800
    pixels = bytearray((248, 250, 252) * width * height)
    left, top, right, bottom = 130, 120, 1120, 680
    ink = (30, 41, 59)
    muted = (100, 116, 139)
    grid = (203, 213, 225)
    blue = (2, 132, 199)
    gold = (245, 158, 11)

    for step in range(5):
        x = left + (right - left) * step // 4
        y = bottom - (bottom - top) * step // 4
        _line(pixels, width, height, x, top, x, bottom, grid)
        _line(pixels, width, height, left, y, right, y, grid)
        label = f"{step * 25}%"
        _text(pixels, width, height, x - len(label) * 9, bottom + 18, label, muted, 3)
        _text(pixels, width, height, 50, y - 10, label, muted, 3)
    _line(pixels, width, height, left, top, left, bottom, ink, 3)
    _line(pixels, width, height, left, bottom, right, bottom, ink, 3)

    _text(pixels, width, height, 130, 35, "FIT VS OPPORTUNITY", ink, 5)
    _text(pixels, width, height, 565, 738, "FIT", ink, 4)
    _text(pixels, width, height, 20, 75, "OPPORTUNITY", ink, 3)
    _text(pixels, width, height, 840, 55, "FIT UNCALIBRATED", muted, 2)

    # Draw highest-ranked points last so coincident points retain the rank-one marker.
    for index, item in reversed(list(enumerate(rows))):
        fit = min(1.0, max(0.0, item.score.fit))
        opportunity = min(1.0, max(0.0, item.score.opportunity))
        x = left + round(fit * (right - left))
        y = bottom - round(opportunity * (bottom - top))
        _circle(pixels, width, height, x, y, 10, gold if index == 0 else blue)
        _circle(pixels, width, height, x, y, 3, (255, 255, 255))

    raw = b"".join(
        b"\x00" + bytes(pixels[y * width * 3 : (y + 1) * width * 3])
        for y in range(height)
    )
    metadata = (
        ("Title", "Fit vs Opportunity"),
        ("Profile", profile_id),
        ("Fit status", "uncalibrated"),
    )
    png = bytearray(b"\x89PNG\r\n\x1a\n")
    png.extend(_png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)))
    for key, value in metadata:
        png.extend(_png_chunk(b"tEXt", f"{key}\0{value}".encode("latin-1")))
    png.extend(_png_chunk(b"IDAT", zlib.compress(raw, level=9)))
    png.extend(_png_chunk(b"IEND", b""))
    path.write_bytes(png)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    body = kind + payload
    return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def _pixel(
    pixels: bytearray,
    width: int,
    height: int,
    x: int,
    y: int,
    color: tuple[int, int, int],
) -> None:
    if 0 <= x < width and 0 <= y < height:
        offset = (y * width + x) * 3
        pixels[offset : offset + 3] = bytes(color)


def _line(
    pixels: bytearray,
    width: int,
    height: int,
    x1: int,
    y1: int,
    x2: int,
    y2: int,
    color: tuple[int, int, int],
    thickness: int = 1,
) -> None:
    steps = max(abs(x2 - x1), abs(y2 - y1), 1)
    for step in range(steps + 1):
        x = x1 + (x2 - x1) * step // steps
        y = y1 + (y2 - y1) * step // steps
        for dx in range(-(thickness // 2), thickness - thickness // 2):
            for dy in range(-(thickness // 2), thickness - thickness // 2):
                _pixel(pixels, width, height, x + dx, y + dy, color)


def _circle(
    pixels: bytearray,
    width: int,
    height: int,
    cx: int,
    cy: int,
    radius: int,
    color: tuple[int, int, int],
) -> None:
    for dy in range(-radius, radius + 1):
        for dx in range(-radius, radius + 1):
            if dx * dx + dy * dy <= radius * radius:
                _pixel(pixels, width, height, cx + dx, cy + dy, color)


def _text(
    pixels: bytearray,
    width: int,
    height: int,
    x: int,
    y: int,
    value: str,
    color: tuple[int, int, int],
    scale: int,
) -> None:
    cursor = x
    for character in value.upper():
        glyph = _FONT.get(character, _FONT[" "])
        for row, bits in enumerate(glyph):
            for column, bit in enumerate(bits):
                if bit == "1":
                    for dy in range(scale):
                        for dx in range(scale):
                            _pixel(
                                pixels,
                                width,
                                height,
                                cursor + column * scale + dx,
                                y + row * scale + dy,
                                color,
                            )
        cursor += 6 * scale
