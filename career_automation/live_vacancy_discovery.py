"""Read-only classification and ATS-authority extraction for vacancy sources."""

from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .vacancy_identity import provider_vacancy_tokens


CLOSED_MARKERS = (
    "job is no longer available",
    "job is no longer open",
    "position has been filled",
    "vacancy has closed",
    "applications are closed",
    "job not found",
)
ACTIVE_MARKERS = (
    "apply for this job",
    "apply now",
    "apply for this position",
    "submit application",
    '"@type":"jobposting"',
    '"@type": "jobposting"',
)
ATS_HOSTS = (
    "jobs.ashbyhq.com",
    "jobs.lever.co",
    "apply.workable.com",
    "jobs.smartrecruiters.com",
    "job-boards.greenhouse.io",
    "job-boards.eu.greenhouse.io",
)
SEMANTIC_STOP_WORDS = frozenset(
    {
        "about",
        "after",
        "also",
        "and",
        "apply",
        "application",
        "are",
        "at",
        "be",
        "for",
        "from",
        "have",
        "into",
        "job",
        "our",
        "position",
        "role",
        "that",
        "the",
        "their",
        "this",
        "to",
        "we",
        "will",
        "with",
        "you",
        "your",
    }
)


def _normal_text(value: str) -> str:
    without_markup = re.sub(r"<[^>]+>", " ", html.unescape(value))
    return " ".join(without_markup.casefold().split())


def _normal_requirement_text(value: str) -> str:
    normal = _normal_text(value).replace("couch db", "couchdb")
    return re.sub(
        r"\b(requests?|queries?|transactions?)\s*/\s*(sec|second|min|minute|hr|hour)\b",
        lambda match: (
            f"{match.group(1)} per "
            + {"sec": "second", "min": "minute", "hr": "hour"}.get(
                match.group(2), match.group(2)
            )
        ),
        normal,
    )


def provider_for_url(value: str) -> str | None:
    host = urlsplit(value).netloc.casefold().split(":", 1)[0]
    if host in {"job-boards.greenhouse.io", "job-boards.eu.greenhouse.io"}:
        return "greenhouse"
    if host == "jobs.ashbyhq.com":
        return "ashby"
    if host == "jobs.lever.co":
        return "lever"
    if host == "apply.workable.com":
        return "workable"
    if host == "jobs.smartrecruiters.com":
        return "smartrecruiters"
    if host.endswith(".myworkdayjobs.com"):
        return "workday"
    return None


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.forms: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        if tag.casefold() == "a" and values.get("href"):
            self._href = str(values["href"])
            self._text = []
        if tag.casefold() == "form" and values.get("action"):
            self.forms.append(str(values["action"]))

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "a" and self._href is not None:
            self.links.append((self._href, " ".join(self._text).strip()))
            self._href = None
            self._text = []


class _ProviderIdentity(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_values: list[str] = []
        self.company_values: list[str] = []
        self.visible_values: list[str] = []
        self._capture_tag: str | None = None
        self._capture_depth = 0
        self._capture_text: list[str] = []
        self._json_ld = False
        self._json_text: list[str] = []
        self._hidden_depth = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        folded_tag = tag.casefold()
        values = {str(key).casefold(): value for key, value in attrs}
        if folded_tag in {"script", "style"}:
            self._hidden_depth += 1
        if self._capture_tag is not None:
            self._capture_depth += 1
        elif folded_tag in {"h1", "title"}:
            self._capture_tag = folded_tag
            self._capture_depth = 1
            self._capture_text = []
        if folded_tag == "meta":
            label = str(values.get("property") or values.get("name") or "").casefold()
            content = values.get("content")
            if content and label in {
                "og:title",
                "twitter:title",
                "job:title",
            }:
                self.title_values.append(str(content))
        if (
            folded_tag == "script"
            and str(values.get("type") or "").casefold() == "application/ld+json"
        ):
            self._json_ld = True
            self._json_text = []

    def handle_data(self, data: str) -> None:
        if self._capture_tag is not None:
            self._capture_text.append(data)
        if self._json_ld:
            self._json_text.append(data)
        normal = " ".join(html.unescape(data).casefold().split())
        if normal and self._hidden_depth == 0:
            self.visible_values.append(normal)

    def handle_endtag(self, tag: str) -> None:
        folded_tag = tag.casefold()
        if self._capture_tag is not None:
            self._capture_depth -= 1
            if self._capture_depth == 0:
                value = " ".join("".join(self._capture_text).split())
                if value:
                    self.title_values.append(value)
                self._capture_tag = None
                self._capture_text = []
        if folded_tag == "script" and self._json_ld:
            self._read_json_ld("".join(self._json_text))
            self._json_ld = False
            self._json_text = []
        if folded_tag in {"script", "style"} and self._hidden_depth:
            self._hidden_depth -= 1

    def _read_json_ld(self, value: str) -> None:
        try:
            document = json.loads(value)
        except (TypeError, ValueError):
            return

        def visit(node: object) -> None:
            if isinstance(node, list):
                for child in node:
                    visit(child)
                return
            if not isinstance(node, dict):
                return
            node_type = node.get("@type")
            if isinstance(node_type, str):
                types = {node_type}
            elif isinstance(node_type, list):
                types = {value for value in node_type if isinstance(value, str)}
            else:
                types = set()
            if "JobPosting" in types:
                title = node.get("title") or node.get("name")
                if isinstance(title, str):
                    self.title_values.append(title)
                organisation = node.get("hiringOrganization")
                if isinstance(organisation, dict) and isinstance(
                    organisation.get("name"), str
                ):
                    self.company_values.append(organisation["name"])
            for child in node.values():
                if isinstance(child, (dict, list)):
                    visit(child)

        visit(document)


def _title_equivalent(expected_title: str, candidates: list[str]) -> bool:
    expected = _normal_text(expected_title)
    for candidate in candidates:
        normal = _normal_text(candidate)
        if normal == expected:
            return True
        segments = {
            " ".join(segment.casefold().split())
            for segment in re.split(r"\s+(?:\||-|–|—|·|at|@)\s+", html.unescape(candidate))
        }
        if expected in segments:
            return True
    return False


def _page_identity(source: str) -> _ProviderIdentity:
    parser = _ProviderIdentity()
    parser.feed(source)
    return parser


def _semantic_token_sha256s(source: str) -> tuple[str, ...]:
    """Project visible vacancy meaning without retaining employer prose."""
    identity = _page_identity(source)
    visible = _normal_requirement_text(" ".join(identity.visible_values))
    tokens = {
        token.strip(".-/")
        for token in re.findall(r"[a-z0-9][a-z0-9+#.\-/]*", visible)
        if token not in SEMANTIC_STOP_WORDS
        and (len(token) >= 3 or token.isdigit())
    }
    return tuple(sorted(hashlib.sha256(token.encode()).hexdigest() for token in tokens))


_NUMBER_WORDS = {
    "one": "1",
    "two": "2",
    "three": "3",
    "four": "4",
    "five": "5",
    "six": "6",
    "seven": "7",
    "eight": "8",
    "nine": "9",
    "ten": "10",
}
_TECHNOLOGY_ALIASES = {
    "aws": (r"\baws\b", r"amazon web services"),
    "azure": (r"\bazure\b",),
    "cloud": (r"\bcloud\b",),
    "cpp": (r"c\+\+", r"\bcpp\b"),
    "csharp": (r"c#", r"\bc sharp\b"),
    "cuda": (r"\bcuda\b",),
    "data_pipeline": (r"\bdata pipelines?\b", r"\betl\b"),
    "docker": (r"\bdocker\b",),
    "embedded": (r"\bembedded\b",),
    "firmware": (r"\bfirmware\b",),
    "gcp": (r"\bgcp\b", r"google cloud platform"),
    "golang": (r"\bgolang\b", r"\bgo programming\b"),
    "hardware": (r"\bhardware\b",),
    "java": (r"\bjava\b",),
    "javascript": (r"\bjavascript\b", r"\bnode\.js\b"),
    "kubernetes": (r"\bkubernetes\b", r"\bk8s\b"),
    "linux": (r"\blinux\b",),
    "python": (r"\bpython\b",),
    "react": (r"\breact(?:\.js)?\b",),
    "rust": (r"\brust\b",),
    "security": (r"\bcyber ?security\b", r"\binformation security\b"),
    "sql": (r"\bsql\b",),
    "typescript": (r"\btypescript\b",),
}
_UK_LOCATIONS = (
    "birmingham",
    "bristol",
    "cambridge",
    "edinburgh",
    "glasgow",
    "leeds",
    "liverpool",
    "london",
    "manchester",
    "oxford",
)

_MATERIAL_CUE = re.compile(
    r"\b(?:required|requirement|mandatory|must|need(?:ed)?|minimum|at least|"
    r"experience|expertise|proficien(?:t|cy)|knowledge|qualification|degree|"
    r"eligible|right to work|sponsorship|remote|hybrid|on[ -]?site|office|"
    r"clearance|deadline|closing date|applications close|comfortable with|"
    r"familiar(?:ity)? with|ability to)\b"
)
_MATERIAL_IMPERATIVE = re.compile(
    r"^(?:build|develop|design|maintain|create|deliver|lead|implement|operate|"
    r"use|work with|analyse|analyze)\b"
)
_KNOWN_PROVIDER_CHROME_SPAN = re.compile(
    r"^create (?:a )?(?:job )?alert(?: required)?$"
)
_OPAQUE_GENERIC_WORDS = SEMANTIC_STOP_WORDS | frozenset(
    {
        "applicant",
        "applicants",
        "candidate",
        "candidates",
        "attend",
        "commercial",
        "comfortable",
        "current",
        "each",
        "eligible",
        "engineering",
        "existing",
        "experience",
        "expertise",
        "knowledge",
        "familiar",
        "familiarity",
        "mandatory",
        "minimum",
        "need",
        "needed",
        "proficiency",
        "proficient",
        "qualification",
        "qualifications",
        "required",
        "requiring",
        "requirement",
        "requirements",
        "responsibilities",
        "responsibility",
        "right",
        "service",
        "services",
        "skills",
        "using",
        "must",
        "day",
        "days",
        "week",
        "weeks",
        "work",
        "working",
        "years",
    }
)
_KNOWN_ATOM_WORDS = frozenset(
    {
        "amazon",
        "aws",
        "azure",
        "bachelor",
        "bachelors",
        "bsc",
        "chartered",
        "cloud",
        "cpp",
        "cuda",
        "cybersecurity",
        "data",
        "docker",
        "doctorate",
        "embedded",
        "etl",
        "firmware",
        "gcp",
        "golang",
        "hardware",
        "hybrid",
        "java",
        "javascript",
        "kubernetes",
        "linux",
        "master",
        "masters",
        "node.js",
        "office",
        "onsite",
        "phd",
        "pipeline",
        "pipelines",
        "python",
        "react",
        "remote",
        "rust",
        "security",
        "sponsorship",
        "sql",
        "typescript",
        *(_UK_LOCATIONS),
    }
)


def _material_spans(source: str) -> tuple[str, ...]:
    """Select requirement-bearing visible spans and exclude provider chrome."""
    content = re.sub(
        r"<\s*(script|style|nav|footer|form)\b[^>]*>.*?<\s*/\s*\1\s*>",
        " ",
        source,
        flags=re.IGNORECASE | re.DOTALL,
    )
    content = re.sub(
        r"<\s*(div|section|aside)\b[^>]*(?:id|class)\s*=\s*"
        r"(?:['\"][^'\"]*(?:cookie|consent|privacy-banner)[^'\"]*['\"]|"
        r"[^\s>]*(?:cookie|consent|privacy-banner)[^\s>]*)[^>]*>.*?"
        r"<\s*/\s*\1\s*>",
        " ",
        content,
        flags=re.IGNORECASE | re.DOTALL,
    )
    content = re.sub(
        r"<\s*/\s*(?:p|li|h[1-6]|div|section|main|article)\s*>",
        "\n",
        content,
        flags=re.IGNORECASE,
    )
    content = re.sub(r"<\s*br\s*/?\s*>", "\n", content, flags=re.IGNORECASE)
    content = html.unescape(re.sub(r"<[^>]+>", " ", content))
    spans: list[str] = []
    for raw in content.splitlines():
        normal = _normal_requirement_text(raw)
        for clause in re.split(r"\s*;\s*|(?<=[.!?])\s+", normal):
            # Greenhouse renders this notification control inside the live job
            # page.  It is provider chrome, not a vacancy responsibility or
            # qualification.  Keep the exclusion deliberately exact so real
            # clauses beginning with "create" remain material.
            if _KNOWN_PROVIDER_CHROME_SPAN.fullmatch(clause):
                continue
            if clause and (
                _MATERIAL_CUE.search(clause) or _MATERIAL_IMPERATIVE.match(clause)
            ):
                spans.append(clause)
    return tuple(spans)


def _material_requirement_atoms(source: str) -> tuple[str, ...]:
    """Extract known constraints plus fail-closed unknown material tokens."""
    spans = _material_spans(source)
    visible = _normal_text(" ".join(spans))
    atoms: set[str] = set()
    number = r"(?:\d{1,2}|" + "|".join(_NUMBER_WORDS) + r")"
    for match in re.finditer(
        rf"\b({number})\s*(?:-|–|to)\s*({number})\s*years?\b", visible
    ):
        minimum = _NUMBER_WORDS.get(match.group(1), match.group(1))
        maximum = _NUMBER_WORDS.get(match.group(2), match.group(2))
        atoms.add(f"experience_years_range:{minimum}:{maximum}")
    for match in re.finditer(
        rf"\b({number})\+?\s*(?:or more\s+)?years?\b(?:\s+of)?(?:\s+\w+){{0,4}}\s+(?:experience|expertise)",
        visible,
    ):
        value = _NUMBER_WORDS.get(match.group(1), match.group(1))
        atoms.add(f"experience_years:{value}")
    for match in re.finditer(
        r"\b(\d+(?:\.\d+)?)\s*(requests?|queries?|transactions?)\s*"
        r"(?:/|per\s+)(second|sec|minute|min|hour|hr)\b",
        visible,
    ):
        unit = {
            "sec": "second",
            "min": "minute",
            "hr": "hour",
        }.get(match.group(3), match.group(3))
        atoms.add(
            f"capacity:{match.group(1)}:{match.group(2).rstrip('s')}_per_{unit}"
        )
    if re.search(r"\b(?:security|sc|dv) clearance\b|\bsecurity-cleared\b", visible):
        atoms.add("clearance:security")
    if re.search(r"\b(?:no|not|without|never)\b", visible):
        atoms.add("constraint_polarity:negative")
    if re.search(r"\beither\b.{0,80}\bor\b|\band/or\b", visible):
        atoms.add("constraint_logic:alternative")
    if re.search(
        r"\b(?:right|eligible|authori[sz](?:ed|ation)) to work\b.{0,30}\b(?:uk|united kingdom)\b"
        r"|\b(?:uk|united kingdom)\b.{0,30}\b(?:right|eligib|authori[sz])",
        visible,
    ):
        atoms.add("work_right:uk")
    if re.search(r"\b(?:no|not offering|unable to offer|without)\b.{0,35}\bsponsorship\b", visible):
        atoms.add("sponsorship:unavailable")
    elif re.search(r"\b(?:visa|work permit) sponsorship\b|\bsponsorship (?:is )?available\b", visible):
        atoms.add("sponsorship:available")
    if re.search(r"\bremote(?:-first| working)?\b", visible):
        atoms.add("attendance:remote")
    if re.search(r"\bhybrid\b|\battend\b.{0,35}\boffice\b|\boffice\b.{0,35}\bdays?\b", visible):
        atoms.add("attendance:hybrid")
    if re.search(r"\b(?:on[ -]?site|office based|in person)\b", visible):
        atoms.add("attendance:onsite")
    for match in re.finditer(
        rf"\b({number})\+?\s+days?\b.{{0,25}}\b(?:week|office|on[ -]?site|in person)\b"
        rf"|\b(?:office|on[ -]?site|in person)\b.{{0,25}}\b({number})\+?\s+days?\b",
        visible,
    ):
        raw = match.group(1) or match.group(2)
        atoms.add(f"attendance_days:{_NUMBER_WORDS.get(raw, raw)}")
    for location in _UK_LOCATIONS:
        if re.search(rf"\b{location}\b", visible):
            atoms.add(f"location:{location}")
    credential_patterns = {
        "bachelor": r"\b(?:bachelor(?:'s)?|bsc|ba)\b",
        "master": r"\b(?:master(?:'s)?|msc|ma)\b",
        "phd": r"\b(?:phd|doctorate)\b",
        "chartered": r"\bchartered\b",
    }
    for credential, pattern in credential_patterns.items():
        if re.search(pattern, visible):
            atoms.add(f"credential:{credential}")
    for level in ("graduate", "junior", "senior", "lead", "principal"):
        if re.search(rf"\b{level}\b", visible):
            atoms.add(f"seniority:{level}")
    for technology, patterns in _TECHNOLOGY_ALIASES.items():
        if any(re.search(pattern, visible) for pattern in patterns):
            atoms.add(f"technology:{technology}")
    for match in re.finditer(
        r"\b(?:deadline|closing date|applications close)\b.{0,25}"
        r"((?:20\d{2}[-/]\d{1,2}[-/]\d{1,2})|(?:\d{1,2}\s+[a-z]+\s+20\d{2}))",
        visible,
    ):
        atoms.add(f"deadline:{' '.join(match.group(1).split())}")
    for span in spans:
        span_tokens = []
        for raw_token in re.findall(r"[a-z0-9][a-z0-9+#.\-/]*", span):
            token = raw_token.strip(".-/")
            if (
                token not in _OPAQUE_GENERIC_WORDS
                and token not in _KNOWN_ATOM_WORDS
                and not token.isdigit()
                and token not in _NUMBER_WORDS
                and len(token) >= 3
            ):
                atoms.add(f"unparsed_material_token:{token}")
                span_tokens.append(token)
        modality = (
            "not_required"
            if re.search(r"\b(?:no|not|without|never)\b", span)
            else "capability"
            if re.search(r"\b(?:comfortable|familiar(?:ity)?|ability)\b", span)
            else "required"
        )
        for token in span_tokens:
            atoms.add(f"entity_constraint:{token}:{modality}")
    return tuple(sorted(atoms))


def _atom_sha256s(source: str) -> tuple[str, ...]:
    return tuple(
        hashlib.sha256(atom.encode()).hexdigest()
        for atom in _material_requirement_atoms(source)
    )


def _equivalence_metrics(
    source_tokens: tuple[str, ...],
    destination_tokens: tuple[str, ...],
    source_atoms: tuple[str, ...],
    destination_atoms: tuple[str, ...],
) -> dict[str, object]:
    shared = set(source_tokens).intersection(destination_tokens)
    union = set(source_tokens).union(destination_tokens)
    denominator = min(len(source_tokens), len(destination_tokens))
    overlap_bp = 10_000 * len(shared) // denominator if denominator else 0
    jaccard_bp = 10_000 * len(shared) // len(union) if union else 0
    material_bound = source_atoms == destination_atoms and (
        bool(source_atoms) or source_tokens == destination_tokens
    )
    return {
        "shared_semantic_token_count": len(shared),
        "semantic_overlap_basis_points": overlap_bp,
        "semantic_jaccard_basis_points": jaccard_bp,
        "material_requirement_bound": material_bound,
        "equivalent": (
            material_bound
            and len(source_tokens) >= 3
            and len(destination_tokens) >= 3
            and len(shared) >= 3
        ),
    }


def verify_vacancy_body_equivalence(
    source_body: bytes,
    destination_body: bytes,
) -> dict[str, object]:
    """Bind a current browser destination to the archived vacancy meaning."""
    if not source_body or not destination_body:
        raise ValueError("vacancy equivalence requires both exact bodies")
    source_tokens = _semantic_token_sha256s(
        source_body.decode("utf-8", errors="replace")
    )
    destination_tokens = _semantic_token_sha256s(
        destination_body.decode("utf-8", errors="replace")
    )
    source_atoms = _atom_sha256s(source_body.decode("utf-8", errors="replace"))
    destination_atoms = _atom_sha256s(
        destination_body.decode("utf-8", errors="replace")
    )
    metrics = _equivalence_metrics(
        source_tokens, destination_tokens, source_atoms, destination_atoms
    )
    document = {
        "schema_version": "jaa.vacancy-body-equivalence.v2",
        "source_body_sha256": hashlib.sha256(source_body).hexdigest(),
        "destination_body_sha256": hashlib.sha256(destination_body).hexdigest(),
        "source_semantic_token_sha256s": list(source_tokens),
        "destination_semantic_token_sha256s": list(destination_tokens),
        "source_material_requirement_sha256s": list(source_atoms),
        "destination_material_requirement_sha256s": list(destination_atoms),
        **metrics,
    }
    if document["equivalent"] is not True:
        raise ValueError("current destination vacancy description differs")
    return document


@dataclass(frozen=True)
class LiveVacancyVerdict:
    live: bool
    reason: str
    title_bound: bool
    active_markers: tuple[str, ...]
    closed_markers: tuple[str, ...]
    authority_urls: tuple[str, ...]
    authority_providers: tuple[str, ...]
    authority_candidates: tuple[str, ...] = ()
    destination_evidence: tuple[dict[str, object], ...] = ()
    source_final_url: str = ""
    source_body_sha256: str = ""
    source_semantic_token_sha256s: tuple[str, ...] = ()
    source_material_requirement_sha256s: tuple[str, ...] = ()

    def document(self) -> dict[str, object]:
        return {
            "live": self.live,
            "reason": self.reason,
            "title_bound": self.title_bound,
            "active_markers": list(self.active_markers),
            "closed_markers": list(self.closed_markers),
            "authority_urls": list(self.authority_urls),
            "authority_providers": list(self.authority_providers),
            "authority_candidates": list(self.authority_candidates),
            "destination_evidence": list(self.destination_evidence),
            "source_final_url": self.source_final_url,
            "source_body_sha256": self.source_body_sha256,
            "source_semantic_token_sha256s": list(
                self.source_semantic_token_sha256s
            ),
            "source_material_requirement_sha256s": list(
                self.source_material_requirement_sha256s
            ),
        }


@dataclass(frozen=True)
class AuthorityDestinationResponse:
    requested_url: str
    final_url: str
    status: int
    body: bytes
    response_artifact_sha256: str
    network_evidence_sha256: str

    def __post_init__(self) -> None:
        if (
            provider_for_url(self.requested_url) is None
            or not isinstance(self.final_url, str)
            or not self.final_url
            or not isinstance(self.status, int)
            or isinstance(self.status, bool)
            or not 100 <= self.status <= 599
            or not isinstance(self.body, bytes)
            or not self.body
            or not re.fullmatch(r"[0-9a-f]{64}", self.response_artifact_sha256)
            or self.response_artifact_sha256 != hashlib.sha256(self.body).hexdigest()
            or not re.fullmatch(r"[0-9a-f]{64}", self.network_evidence_sha256)
        ):
            raise ValueError("ATS destination response is malformed")


def _destination_evidence(
    response: AuthorityDestinationResponse,
    *,
    expected_title: str,
    expected_company: str,
    source_body_sha256: str,
    source_semantic_token_sha256s: tuple[str, ...],
    source_material_requirement_sha256s: tuple[str, ...],
) -> dict[str, object]:
    provider = provider_for_url(response.requested_url)
    final_provider = provider_for_url(response.final_url)
    requested_tokens = {
        token
        for token in provider_vacancy_tokens(
            job_key=provider or "unknown", source_url=response.requested_url
        )
        if not token.startswith("url:")
    }
    final_tokens = {
        token
        for token in provider_vacancy_tokens(
            job_key=final_provider or "unknown", source_url=response.final_url
        )
        if not token.startswith("url:")
    }
    source = response.body.decode("utf-8", errors="replace")
    normal = _normal_text(source)
    folded = source.casefold()
    identity = _page_identity(source)
    title_bound = _title_equivalent(expected_title, identity.title_values)
    expected_company_normal = _normal_text(expected_company)
    company_bound = expected_company_normal in {
        *identity.visible_values,
        *(_normal_text(value) for value in identity.company_values),
    }
    active = tuple(marker for marker in ACTIVE_MARKERS if marker in folded)
    closed = tuple(marker for marker in CLOSED_MARKERS if marker in normal)
    destination_semantic = _semantic_token_sha256s(source)
    destination_atoms = _atom_sha256s(source)
    metrics = _equivalence_metrics(
        source_semantic_token_sha256s,
        destination_semantic,
        source_material_requirement_sha256s,
        destination_atoms,
    )
    description_bound = metrics["equivalent"] is True
    shared_tokens = requested_tokens.intersection(final_tokens)
    identity_bound = bool(shared_tokens)
    if provider is None or final_provider != provider:
        reason = "destination_provider_mismatch"
    elif not 200 <= response.status < 300:
        reason = "destination_non_success_http_status"
    elif not identity_bound:
        reason = "destination_vacancy_identity_mismatch"
    elif closed:
        reason = "destination_provider_closed_marker"
    elif not title_bound:
        reason = "destination_title_mismatch"
    elif not company_bound:
        reason = "destination_company_mismatch"
    elif not description_bound:
        reason = "destination_description_mismatch"
    elif not active:
        reason = "destination_application_marker_missing"
    else:
        reason = "verified_ats_destination"
    return {
        "requested_url": response.requested_url,
        "final_url": response.final_url,
        "status": response.status,
        "provider": provider,
        "body_sha256": hashlib.sha256(response.body).hexdigest(),
        "response_artifact_sha256": response.response_artifact_sha256,
        "network_evidence_sha256": response.network_evidence_sha256,
        "source_body_sha256": source_body_sha256,
        "byte_length": len(response.body),
        "source_authority_identity_tokens": sorted(requested_tokens),
        "destination_identity_tokens": sorted(final_tokens),
        "vacancy_identity_tokens": sorted(shared_tokens),
        "title_bound": title_bound,
        "company_bound": company_bound,
        "description_bound": description_bound,
        "source_semantic_token_count": len(source_semantic_token_sha256s),
        "destination_semantic_token_count": len(destination_semantic),
        **metrics,
        "source_material_requirement_sha256s": list(
            source_material_requirement_sha256s
        ),
        "destination_material_requirement_sha256s": list(destination_atoms),
        "destination_semantic_token_sha256s": list(destination_semantic),
        "active_markers": list(active),
        "closed_markers": list(closed),
        "verified": reason == "verified_ats_destination",
        "reason": reason,
    }


def bind_authority_destinations(
    verdict: LiveVacancyVerdict,
    *,
    responses: tuple[AuthorityDestinationResponse, ...],
    expected_title: str,
    expected_company: str,
) -> LiveVacancyVerdict:
    """Fetch-bound authority: only native destinations equivalent to the source pass."""
    if not _normal_text(expected_title) or not _normal_text(expected_company):
        raise ValueError("ATS destination binding requires source title and company")
    if (
        verdict.reason != "live_source_requires_ats_destination_fetch"
        or not verdict.title_bound
        or verdict.closed_markers
        or not verdict.active_markers
    ):
        raise ValueError("source observation is not eligible for destination binding")
    if not re.fullmatch(r"[0-9a-f]{64}", verdict.source_body_sha256):
        raise ValueError("ATS destination binding requires archived source bytes")
    candidates = verdict.authority_candidates
    response_urls = tuple(row.requested_url for row in responses)
    if (
        not candidates
        or len(set(response_urls)) != len(response_urls)
        or set(response_urls) != set(candidates)
    ):
        raise ValueError("ATS destination responses must exactly cover authority candidates")
    evidence = tuple(
        _destination_evidence(
            row,
            expected_title=expected_title,
            expected_company=expected_company,
            source_body_sha256=verdict.source_body_sha256,
            source_semantic_token_sha256s=(
                verdict.source_semantic_token_sha256s
            ),
            source_material_requirement_sha256s=(
                verdict.source_material_requirement_sha256s
            ),
        )
        for row in responses
    )
    verified_urls = tuple(
        sorted(str(row["final_url"]) for row in evidence if row["verified"] is True)
    )
    providers = tuple(
        sorted({value for url in verified_urls if (value := provider_for_url(url))})
    )
    return LiveVacancyVerdict(
        live=bool(verified_urls),
        reason=(
            "live_with_verified_ats_authority"
            if verified_urls
            else "ats_destination_identity_unverified"
        ),
        title_bound=verdict.title_bound,
        active_markers=verdict.active_markers,
        closed_markers=verdict.closed_markers,
        authority_urls=verified_urls,
        authority_providers=providers,
        authority_candidates=tuple(sorted(candidates)),
        destination_evidence=evidence,
        source_final_url=verdict.source_final_url,
        source_body_sha256=verdict.source_body_sha256,
        source_semantic_token_sha256s=(
            verdict.source_semantic_token_sha256s
        ),
        source_material_requirement_sha256s=(
            verdict.source_material_requirement_sha256s
        ),
    )


def classify_live_vacancy_response(
    *, requested_url: str, final_url: str, status: int, body: bytes, expected_title: str
) -> LiveVacancyVerdict:
    source = body.decode("utf-8", errors="replace")
    folded = source.casefold()
    normal = _normal_text(source)
    identity = _page_identity(source)
    title_bound = _title_equivalent(expected_title, identity.title_values)
    active = tuple(marker for marker in ACTIVE_MARKERS if marker in folded)
    closed = tuple(marker for marker in CLOSED_MARKERS if marker in normal)
    parser = _Links()
    parser.feed(source)
    authority_urls: set[str] = set()
    for candidate, label in (*parser.links, *((form, "form") for form in parser.forms)):
        absolute = urljoin(final_url, html.unescape(candidate))
        provider = provider_for_url(absolute)
        stable_tokens = {
            token
            for token in provider_vacancy_tokens(
                job_key=provider or "source", source_url=absolute
            )
            if not token.startswith("url:")
        }
        if provider and stable_tokens:
            authority_urls.add(absolute)
        elif provider_for_url(final_url) and (
            "apply" in label.casefold() or "apply" in urlsplit(absolute).path.casefold()
        ):
            authority_urls.add(absolute)
    final_provider = provider_for_url(final_url)
    if final_provider and any(
        not token.startswith("url:")
        for token in provider_vacancy_tokens(
            job_key=final_provider, source_url=final_url
        )
    ):
        authority_urls.add(final_url)
    candidates = tuple(sorted(authority_urls))
    if not 200 <= status < 300:
        reason = "non_success_http_status"
    elif closed:
        reason = "provider_closed_marker"
    elif not title_bound:
        reason = "vacancy_title_mismatch"
    elif not active:
        reason = "no_application_marker_observed"
    elif not candidates:
        reason = "live_discovery_source_without_resolved_ats_authority"
    else:
        reason = "live_source_requires_ats_destination_fetch"
    return LiveVacancyVerdict(
        live=False,
        reason=reason,
        title_bound=title_bound,
        active_markers=active,
        closed_markers=closed,
        authority_urls=(),
        authority_providers=(),
        authority_candidates=candidates,
        destination_evidence=(),
        source_final_url=final_url,
        source_body_sha256=hashlib.sha256(body).hexdigest(),
        source_semantic_token_sha256s=_semantic_token_sha256s(source),
        source_material_requirement_sha256s=_atom_sha256s(source),
    )


__all__ = [
    "LiveVacancyVerdict",
    "AuthorityDestinationResponse",
    "bind_authority_destinations",
    "classify_live_vacancy_response",
    "provider_for_url",
    "verify_vacancy_body_equivalence",
]
