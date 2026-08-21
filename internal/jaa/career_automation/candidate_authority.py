"""Deterministic candidate projection and vacancy decision materialization.

The imported operational snapshot is opened read-only.  The only writes are
create-only, content-addressed authority objects beneath the configured JAA
application archive.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from html.parser import HTMLParser
from pathlib import Path
from typing import Mapping, Sequence

from .application_archive import verify_complete_attempt
from .evidence_matching import canonical_json


HEX_64 = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_ID = re.compile(r"^E-[0-9]{3}$")
SUPPRESSOR_ROW = re.compile(r"^\|\s*(Q-[0-9]{3})\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|$")
WORD = re.compile(r"[a-z0-9][a-z0-9+#./-]*")

def _software_factory_root() -> Path:
    """Locate operator inputs without embedding one workstation's home path."""
    configured = os.environ.get("JAA_SOFTWARE_FACTORY_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    repository_root = Path(__file__).resolve().parents[1]
    for candidate in (repository_root, *repository_root.parents):
        if (candidate / ".incoming").is_dir() and (
            candidate / "giga-user"
        ).is_dir():
            return candidate
    return repository_root.parent


SOFTWARE_FACTORY_ROOT = _software_factory_root()
INCOMING_ROOT = SOFTWARE_FACTORY_ROOT / (
    ".incoming/mac-jaa-assurance-20260805-e1bb35a/operational-state"
)
CANDIDATE_EVIDENCE_ROOT = (
    INCOMING_ROOT / "job-application-automation" / ("candidate-evidence")
)
JOBS_DATABASE_PATH = INCOMING_ROOT / (
    "job-application-automation-gutua-20260803-evidence/"
    "jaa11-rank29-inspection/jobs.sqlite3"
)
AVAILABILITY_PATH = SOFTWARE_FACTORY_ROOT / (
    "giga-user/memory/entries/2026-08-05-jaa-operator-uk-availability.md"
)
APPROVED_EVIDENCE_PATH = (
    CANDIDATE_EVIDENCE_ROOT / "approved_evidence_packet_2026-08-10.json"
)
OPERATOR_ANSWERS_PATH = CANDIDATE_EVIDENCE_ROOT / "OPERATOR_ANSWERS_2026-07-28.md"
NEGATIVE_CLAIMS_PATH = CANDIDATE_EVIDENCE_ROOT / "CAREER_CLAIM_INVENTORY_2026-07-28.md"
SCHEMA_PATH = Path(__file__).parent / "fixtures/candidate-authority-schema-v1.json"
POLICY_PATH = Path(__file__).parent / "fixtures/candidate-authority-policy-v1.json"

APPROVED_CANDIDATE_SOURCE_HASHES = {
    "availability": "02b6d79ee199e080cb59be7c740cf90ac520ad34a8879f6c5563d1e3781ced48",
    "approved_evidence": "074f036ea50a89bf75402a923fa1be1ddb6f583f385095d73fb96b61c8562eff",
    "operator_answers": "81f3f90f3653fc46785260bd131899a429f501c41c91bff54e0f44b11b308570",
    "negative_claim_suppressors": "ecbdbe901b7813d6377868171029204369ae4cd9675f11434ea9e9028fb980eb",
    "jobs_database": "67dfb680ad422ea7e1fe1e02d2362957ba3493a5eb0cdae17f0949e9ebbc88c3",
}
APPROVED_EVIDENCE_IDS = tuple(f"E-{index:03d}" for index in range(1, 19))
AVAILABILITY_AUTHORITY = {
    "uk_work_right": "unrestricted",
    "sponsorship_required": False,
    "uk_resident": True,
    "temporarily_in": "Korea",
    "availability": "as_soon_as_reasonably_possible",
    "remote_preference": "strong",
    "onsite_or_hybrid_eligibility_blocker": False,
    "suppressed_inferences": [
        "citizenship",
        "non_uk_work_right",
        "fixed_start_date",
        "relocation_funding",
        "commuter_radius",
    ],
}

HARD_INELIGIBLE = {
    "greenhouse:materiom:5150829007": {
        "mandatory_masters_degree_absent",
        "mandatory_professional_ml_experience_absent",
    },
    "greenhouse:anthropic:5030244008": {"application_deadline_passed"},
    "greenhouse:anthropic:5183051008": {"application_deadline_passed"},
}
HARD_UNRESOLVED = {
    "greenhouse:tripadvisor:6674829": {"commuter_radius"},
    "greenhouse:tripadvisor:6977663": {"commuter_radius"},
    "greenhouse:tripadvisor:7993242": {"commuter_radius"},
}
HARD_ELIGIBLE = {
    "greenhouse:graphcore:8556044002",
    "greenhouse:graphcore:8636572002",
    "greenhouse:graphcore:8636574002",
    "greenhouse:graphcore:8420314002",
    "greenhouse:graphcore:8466438002",
    "greenhouse:graphcore:8545352002",
    "greenhouse:graphcore:8545354002",
    "greenhouse:graphcore:8556059002",
    "greenhouse:graphcore:8605749002",
    "greenhouse:graphcore:8605755002",
    "greenhouse:graphcore:8636907002",
    "greenhouse:tripadvisor:8081328",
    "greenhouse:physicsx:4820418101",
    "greenhouse:anthropic:4610158008",
    "greenhouse:anthropic:5198999008",
}

APPROVED_COHORT = HARD_ELIGIBLE | set(HARD_INELIGIBLE) | set(HARD_UNRESOLVED)
TERMINAL_DISCOVERY_REASONS = {
    "provider_closed_marker",
    "requisition_identity_mismatch",
    "vacancy_title_mismatch",
}

_STOP_WORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "as",
        "at",
        "be",
        "build",
        "can",
        "for",
        "from",
        "have",
        "in",
        "including",
        "is",
        "of",
        "on",
        "or",
        "our",
        "that",
        "the",
        "their",
        "to",
        "using",
        "we",
        "with",
        "work",
        "you",
        "your",
    }
)
_AWS_SERVICE_TOKENS = frozenset(
    {
        "amplify",
        "athena",
        "aurora",
        "bedrock",
        "cloudformation",
        "cloudfront",
        "cloudwatch",
        "cognito",
        "dynamodb",
        "ec2",
        "ecr",
        "ecs",
        "eks",
        "elasticache",
        "emr",
        "fargate",
        "glue",
        "iam",
        "kinesis",
        "lambda",
        "lightsail",
        "opensearch",
        "quicksight",
        "rds",
        "redshift",
        "s3",
        "sagemaker",
        "sns",
        "sqs",
        "vpc",
    }
)
# --------------------------------------------------------------------------- #
# Typed semantic-entailment matching.                                          #
#                                                                              #
# A requirement is supported only when its material subject(s), the action /   #
# relation it asserts, its context / modality and any numeric extent are *all* #
# entailed by the same approved evidence item.  Generic token overlap never    #
# mints a qualification, ``used`` never implies ``built``, ``built`` never     #
# implies ``deployed`` / ``operated``, and ``prototype`` / ``academic`` never  #
# implies ``commercial`` / ``production``.  The evidence side is an explicit,  #
# hash-bound projection of the eighteen approved statements (the atlas below); #
# it may only make matching more conservative and can never invent a new       #
# qualification.                                                               #
# --------------------------------------------------------------------------- #

TYPED_EVIDENCE_SCHEMA = "jaa.typed-evidence-entailment.v2"

# Canonical named-entity vocabulary.  Only concrete technologies, services,
# artefacts and capabilities are entities; generic English (``system``,
# ``architecture``, ``experience``, ``project``, ``service`` …) is deliberately
# absent so it can never carry positive support.  The vocabulary is intentionally
# broad on the *requirement* side: an entity a requirement names but that no
# evidence item attests blocks the match (conjunction), so an unattested named
# technology such as Bazel or Kubernetes fails closed rather than collapsing to a
# lucky shared word.
_ENTITY_PHRASES = {
    "amazon web services": "aws",
    "large language models": "llm",
    "large language model": "llm",
    "anomaly detection": "anomaly-detection",
    "spaced repetition": "spaced-repetition",
    "reinforcement learning": "reinforcement-learning",
    "machine learning": "machine-learning",
    "deep learning": "deep-learning",
    "computer vision": "computer-vision",
    "multi agent": "multi-agent",
    "single agent": "single-agent",
    "data pipeline": "data-pipeline",
    "data pipelines": "data-pipeline",
    "node.js": "node",
    "software factory": "software-factory",
    "market aligner": "market-aligner",
}
_ENTITY_CANON = {
    **{token: token for token in _AWS_SERVICE_TOKENS},
    "aws": "aws",
    "python": "python",
    "java": "java",
    "javascript": "javascript",
    "typescript": "typescript",
    "golang": "go",
    "go": "go",
    "rust": "rust",
    "ruby": "ruby",
    "scala": "scala",
    "kotlin": "kotlin",
    "php": "php",
    "sql": "sql",
    "django": "django",
    "flask": "flask",
    "fastapi": "fastapi",
    "rails": "rails",
    "spring": "spring",
    "react": "react",
    "angular": "angular",
    "vue": "vue",
    "node": "node",
    "express": "express",
    "pytorch": "pytorch",
    "tensorflow": "tensorflow",
    "keras": "keras",
    "pandas": "pandas",
    "numpy": "numpy",
    "spark": "spark",
    "hadoop": "hadoop",
    "kafka": "kafka",
    "airflow": "airflow",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "mysql": "mysql",
    "sqlite": "sqlite",
    "mongodb": "mongodb",
    "redis": "redis",
    "couchdb": "couchdb",
    "elasticsearch": "elasticsearch",
    "cassandra": "cassandra",
    "neo4j": "neo4j",
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "docker": "docker",
    "terraform": "terraform",
    "ansible": "ansible",
    "jenkins": "jenkins",
    "bazel": "bazel",
    "nginx": "nginx",
    "linux": "linux",
    "gcp": "gcp",
    "azure": "azure",
    "multi-agent": "multi-agent",
    "single-agent": "single-agent",
    "agent": "agent",
    "orchestrator": "orchestrator",
    "llm": "llm",
    "serverless": "serverless",
    "telemetry": "telemetry",
    "observability": "observability",
    "caching": "caching",
    "cache": "caching",
    "retries": "retries",
    "retry": "retries",
    "resumability": "resumability",
    "dubbing": "dubbing",
    "synthesis": "synthesis",
    "wav": "wav",
    "spaced-repetition": "spaced-repetition",
    "tutoring": "tutoring",
    "website": "website",
    "frontend": "frontend",
    "backend": "backend",
    "distributed": "distributed",
    "microservices": "microservices",
    "microservice": "microservices",
    "api": "api",
    "reinforcement-learning": "reinforcement-learning",
    "machine-learning": "machine-learning",
    "deep-learning": "deep-learning",
    "computer-vision": "computer-vision",
    "nlp": "nlp",
    "anomaly-detection": "anomaly-detection",
    "data-pipeline": "data-pipeline",
    "etl": "etl",
    "blockchain": "blockchain",
    "sales": "sales",
    "software-factory": "software-factory",
    "scafad": "scafad",
    "market-aligner": "market-aligner",
}

# Canonical actions/relations.  ``_ACTION_SATISFIES`` maps an *evidence* action to
# the set of *requirement* actions it can entail.  The generic ``experience``
# requirement is entailed by any concrete action; the converse never holds, so a
# specific ``deployed`` / ``operated`` / ``built`` / ``led`` requirement is met
# only by explicit, compatible evidence.
_ACTION_SATISFIES = {
    "experience": {"experience"},
    "used": {"experience", "used"},
    "studied": {"experience", "studied", "used"},
    "built": {"experience", "used", "built", "designed"},
    "designed": {"experience", "used", "designed", "built"},
    "deployed": {"experience", "used", "deployed"},
    "operated": {"experience", "used", "operated"},
    "owned": {"experience", "used", "built", "designed", "owned", "operated"},
    "directed": {
        "experience", "used", "built", "designed", "owned", "operated", "directed",
    },
    "led": {"experience", "used", "built", "designed", "owned", "led"},
    "taught": {"experience", "taught"},
    "sold": {"experience", "sold"},
}
# Requirement-side action detection, highest specificity first.
_ACTION_KEYWORDS = (
    ("deployed", (
        "deploy", "deployment", "deployed", "deploying", "ship to production",
        "productionize", "productionise",
    )),
    ("operated", (
        "operate", "operating", "operated", "operation", "run production",
        "running production", "maintain", "maintaining", "on-call", "in production",
        "incident response",
    )),
    ("directed", ("direct ", "directed", "directing")),
    ("built", (
        "build", "building", "built", "develop", "developing", "developed",
        "implement", "implementing", "implemented", "code ", "coding",
        "hands-on", "hands on", "deliver", "delivered", "delivering", "create",
        "created", "creating", "provide", "provided", "providing", "write code",
        "writing code", "engineer ", "programming",
    )),
    ("designed", ("design", "designing", "designed", "architect", "architecture")),
    ("led", ("lead", "leading", "led", "manage", "managing", "mentor", "mentoring",
             "supervise", "supervising")),
    ("owned", ("own ", "owned", "owning", "ownership", "accountable")),
    ("taught", ("teach", "teaching", "taught", "train", "training", "coaching",
                "tutor", "tutoring")),
    ("sold", ("sell", "selling", "sold", "sales")),
    ("studied", ("study", "studied", "research", "researching", "investigate",
                 "investigating", "dissertation", "coursework")),
)

# Context / modality axis.  ``_MODALITY_RANK`` orders parser-detected evidence
# modality from strongest to weakest so a clause resolves to a single value.
_MODALITY_MARKERS = {
    "production": ("production", "productionize", "productionise", "in production"),
    "commercial": ("commercial", "commercially", "enterprise", "b2b", "revenue",
                   "for-profit", "paying customers"),
    "professional": ("professional", "professionally", "workplace", "industry"),
    "customer-facing": ("customer-facing", "customer facing", "client-facing"),
    "prototype": ("prototype", "mvp", "proof of concept", "proof-of-concept",
                  "experimental"),
    "academic": ("dissertation", "university", "academic", "coursework", "thesis"),
    "personal-project": ("personal project", "side project", "hobby",
                         "software factory", "directed ai"),
}
_MODALITY_RANK = (
    "production", "commercial", "professional", "customer-facing", "prototype",
    "academic", "personal-project",
)
# A requirement modality *modifier* constrains which evidence modality can support
# it.  ``production`` is strict; the softer commercial/professional family accepts
# any real-world tier; an unmodified requirement accepts any modality.
_MODALITY_REQUIREMENT = {
    "production": frozenset({"production"}),
    "commercial": frozenset(
        {"commercial", "professional", "production", "customer-facing"}
    ),
    "professional": frozenset(
        {"commercial", "professional", "production", "customer-facing"}
    ),
    "customer-facing": frozenset(
        {"commercial", "professional", "production", "customer-facing"}
    ),
}
_NEGATION_MARKERS = (
    "not ", "without", "no ", "never", "did not", "rather than", "instead of",
    "isn't", "aren't", "wasn't",
)
_YEARS = re.compile(r"(\d+)\s*\+?\s*(?:years?|yrs?)\b")
_SCALE_MARKERS = (
    "at scale", "large-scale", "large scale", "high-scale", "high scale",
    "web-scale", "internet-scale", "hyperscale", "massive scale", "millions of",
    "billions of", "high throughput", "high-throughput",
)

# Explicit, hash-bound typed projection of the eighteen approved statements.  Each
# fact is ``(entity, action, modality)`` and records only what its statement
# directly attests; clauses under negation contribute no positive fact.  The keys
# are the exact SHA-256 of each approved statement, so any change to the shared
# candidate-evidence source fails the pinned-hash gate and invalidates the atlas.
_APPROVED_EVIDENCE_ATLAS = {
    # E-001 First-Class BSc — a credential, no matchable technology.
    "45c1fcd0f77bf83d0167a54e5dab774ca65856b32d881eb3fec8d4da12ded8b1": (),
    # E-002 SCAFAD dissertation — academic study of AWS Lambda / serverless.
    "0fb20371d1701bdba3836c76b97e0d16bd28a3d0d5247888d88bd77c130c51c4": (
        ("aws", "studied", "academic"),
        ("lambda", "studied", "academic"),
        ("anomaly-detection", "studied", "academic"),
        ("serverless", "studied", "academic"),
        ("telemetry", "studied", "academic"),
        ("scafad", "built", "academic"),
    ),
    # E-003 Chamber of Commerce assistant — no matchable technology.
    "caa22fa16d4c45cacb2b7c7d1f18a653c31b6226479b9b8e625491b549046332": (),
    # E-004 translator/interpreter — no matchable technology.
    "6a2abb5202125f4143fcfc422ae07623ffadcd24fff140e1a19feee3c2d533c4": (),
    # E-005 DHL operative — no matchable technology.
    "fe3293535eb58e4e4615da0d7d9c7ecd5374f07247e048cae193a8921b050abf": (),
    # E-006 paid online English lessons.
    "e4183ae5f49eca4e037afb5560d511dc77d3f3104329276169c71cb1e2a3e0d9": (
        ("tutoring", "taught", "professional"),
    ),
    # E-007 customer-facing direct sales and new-starter support.
    "e163b3771f250c531d373ee42da653cd610df5dcaffcd7cafc44e70fe047b672": (
        ("sales", "sold", "customer-facing"),
    ),
    # E-008 Northern Ray external-client website/app. The source attests a
    # design-or-implementation disjunction, so it supports relevant website
    # experience but cannot satisfy a conjunctive designed-and-built claim.
    "6e27d9feecc2a93c84ff614bdae1433e1b529fe72c2f817424b6d48e01eb5d83": (
        ("website", "used", "professional"),
    ),
    # E-009 earlier frontend-only website project.
    "c2b7a2ce3a93fd8e5cadceafb9a6fbf480c79d9cc5e2275cb1d5dff86ffd6ec1": (
        ("website", "built", "personal-project"),
        ("frontend", "built", "personal-project"),
    ),
    # E-010 GCSEs / LIBF — credentials, no matchable technology.
    "4466c4341ab23f6721871cf9359ccbb42089d7040cf88b4a4f435a2284acf856": (),
    # E-011 directed AI agents to build Market Aligner end to end.
    "b5defc87f5f54ede146f37328e7142807b3b3387040a36da88e358cef5813165": (
        ("market-aligner", "owned", "personal-project"),
        ("caching", "built", "personal-project"),
        ("sqlite", "built", "personal-project"),
        ("retries", "built", "personal-project"),
        ("resumability", "built", "personal-project"),
        ("agent", "directed", "personal-project"),
    ),
    # E-012 multi-agent orchestrator: owns requirements/architecture/operation.
    "01bb7b16a73077a43c333060cf1259e609e276732ef3912908215e56f3539ad9": (
        ("multi-agent", "owned", "personal-project"),
        ("multi-agent", "designed", "personal-project"),
        ("orchestrator", "owned", "personal-project"),
        ("orchestrator", "operated", "personal-project"),
        ("agent", "directed", "personal-project"),
    ),
    # E-013 GitHub bodies of work: software factory, SCAFAD, factory output.
    "b5c4eea85591a68b56b5d270e4b883f455718354429ec28f86f88083d8eb7243": (
        ("software-factory", "owned", "personal-project"),
        ("scafad", "built", "academic"),
    ),
    # E-014 Dubbing Studio MVP produced through the factory (product direction).
    "e59e445b8beba48738f6ead3480e8d0c4e2b83d7844217bc2ecc6bdec52fdf30": (
        ("dubbing", "owned", "prototype"),
        ("software-factory", "operated", "personal-project"),
    ),
    # E-015 Dubbing Studio checkout: CLI synthesis produced a correct WAV.
    "f3165a611b0cfd449f835d7e282cd2a3471485ec0c6ff70a0bdc855b3cd2ed97": (
        ("synthesis", "built", "prototype"),
        ("wav", "built", "prototype"),
    ),
    # E-016 Learning Accelerator prototype (LLM-assisted, no real users yet).
    "517a5e1e1641ffc2be739687b68e3e6fed135bec51b2ecfa824ab24507e581bd": (
        ("llm", "built", "prototype"),
        ("spaced-repetition", "built", "prototype"),
    ),
    # E-017 scafad-delta repo supports the dissertation.
    "f9dcb43067ac2011752fd42d6304f950e0323424a2902797a024e9e32ee7ffc1": (
        ("scafad", "built", "academic"),
    ),
    # E-018 earlier public orchestrator repo: software-factory architecture.
    "ed4739281f59dc5a9c19a16c9853a07563e6879159327eeb005997932539522c": (
        ("software-factory", "designed", "personal-project"),
    ),
}
_SUPPRESSOR_MARKERS = {
    "Q-001": ("lab assistant",),
    "Q-002": (
        "professional security",
        "production security",
        "soc",
        "incident response",
        "siem",
        "soar",
        "production ml experience",
        "kubernetes experience",
    ),
    "Q-003": ("published research", "peer-reviewed", "research papers"),
    "Q-004": ("efficiency without weakening",),
    "Q-005": ("treasurer", "projects society"),
    "Q-006": ("russian tutoring",),
    "Q-007": ("amethyst trust",),
    "Q-008": ("b2b sales",),
    "Q-009": ("accessibility project", "blind users"),
    "Q-010": ("hand-coded market aligner", "personally hand-coded"),
}
_BENEFIT_HEADINGS = (
    "benefit",
    "compensation",
    "equal opportunity",
    "life at",
    "perks",
    "what we offer",
    "why join",
)
_BENEFIT_TEXT = (
    "annual bonus",
    "competitive compensation",
    "donation matching",
    "employee assistance",
    "flexible schedule",
    "health benefits",
    "referral scheme",
    "travel perks",
    "tuition assistance",
)


def _json_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_file(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"{label} must be an absolute regular file")
    resolved = path.resolve(strict=True)
    if not stat.S_ISREG(resolved.stat().st_mode):
        raise ValueError(f"{label} must be an absolute regular file")
    return resolved


@dataclass(frozen=True)
class CandidateAuthoritySources:
    availability: Path = AVAILABILITY_PATH
    approved_evidence: Path = APPROVED_EVIDENCE_PATH
    operator_answers: Path = OPERATOR_ANSWERS_PATH
    negative_claim_suppressors: Path = NEGATIVE_CLAIMS_PATH
    jobs_database: Path = JOBS_DATABASE_PATH
    schema: Path = SCHEMA_PATH
    policy: Path = POLICY_PATH


@dataclass(frozen=True)
class MaterializedCandidateAuthority:
    document: Mapping[str, object]
    value: bytes
    sha256: str
    object_path: Path
    authority_path: Path


class _VacancyHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._heading_tag: str | None = None
        self._heading_parts: list[str] = []
        self._li_depth = 0
        self._li_parts: list[str] = []
        self._paragraph_depth = 0
        self._paragraph_parts: list[str] = []
        self.heading = ""
        self.items: list[tuple[str, str]] = []
        self.paragraphs: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._heading_tag = tag
            self._heading_parts = []
        if tag == "li":
            if self._li_depth == 0:
                self._li_parts = []
            self._li_depth += 1
        if tag == "p":
            if self._paragraph_depth == 0:
                self._paragraph_parts = []
            self._paragraph_depth += 1
        if tag == "br" and self._paragraph_depth:
            self._paragraph_parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._heading_tag is not None:
            self._heading_parts.append(data)
        if self._li_depth:
            self._li_parts.append(data)
        if self._paragraph_depth:
            self._paragraph_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == self._heading_tag:
            self.heading = " ".join(" ".join(self._heading_parts).split())
            self._heading_tag = None
            self._heading_parts = []
        if tag == "li" and self._li_depth:
            self._li_depth -= 1
            if self._li_depth == 0:
                value = " ".join(" ".join(self._li_parts).split())
                if value:
                    self.items.append((self.heading, value))
                self._li_parts = []
        if tag == "p" and self._paragraph_depth:
            self._paragraph_depth -= 1
            if self._paragraph_depth == 0:
                value = "\n".join(
                    " ".join(part.split())
                    for part in "".join(self._paragraph_parts).splitlines()
                )
                if value.strip():
                    clean = value.strip()
                    if (
                        "\n" not in clean
                        and len(clean) <= 80
                        and re.search(
                            r"(?:about|benefits|culture|ideally|join|looking|"
                            r"qualifications|requirements|role|skills|"
                            r"sponsorship|team|what)",
                            clean,
                            re.IGNORECASE,
                        )
                    ):
                        self.heading = clean
                    else:
                        self.paragraphs.append((self.heading, clean))
                self._paragraph_parts = []


def _normal_token(token: str) -> str:
    token = token.rstrip("./-")
    aliases = {
        "agents": "agent",
        "architect": "architecture",
        "architectures": "architecture",
        "deployed": "deploy",
        "deploying": "deploy",
        "deployment": "deploy",
        "deployments": "deploy",
        "engineering": "engineer",
        "engineers": "engineer",
        "lessons": "tutoring",
        "systems": "system",
        "tested": "test",
        "testing": "test",
        "tests": "test",
        "websites": "website",
    }
    return aliases.get(
        token, token[:-1] if token.endswith("s") and len(token) > 5 else token
    )


def _tokens(value: str) -> frozenset[str]:
    return frozenset(
        _normal_token(token)
        for token in WORD.findall(value.casefold())
        if token not in _STOP_WORDS and len(token) > 1
    )


def _requirements(content: str) -> tuple[dict[str, object], ...]:
    parser = _VacancyHTMLParser()
    parser.feed(html.unescape(content))
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    candidates = list(parser.items)
    requirement_heading = re.compile(
        r"(?:about the role|about you|fit if|ideally|looking for|nice to have|"
        r"preferred|qualifications|required|requirements|skills|"
        r"what you bring|what you.?ll do|who you are)",
        re.IGNORECASE,
    )
    for heading, paragraph in parser.paragraphs:
        if not requirement_heading.search(heading):
            continue
        for fragment in re.split(r"\n|\s*·\s*|(?<=[.!?])\s+", paragraph):
            clean = fragment.strip()
            if clean and "we value transferable skills" not in clean.casefold():
                candidates.append((heading, clean))
    for heading, raw in candidates:
        heading_folded = heading.casefold()
        text = " ".join(raw.split()).strip(" -\u2022")
        folded = text.casefold()
        if (
            not text
            or text.endswith(":")
            or any(marker in heading_folded for marker in _BENEFIT_HEADINGS)
            or any(marker in folded for marker in _BENEFIT_TEXT)
        ):
            continue
        for part in re.split(r"\s*;\s*", text):
            normalized = " ".join(part.split()).strip(" .")
            identity = normalized.casefold()
            if len(normalized) < 8 or identity in seen:
                continue
            seen.add(identity)
            desirable = any(
                marker in heading_folded
                for marker in ("ideally", "nice to have", "preferred", "bonus")
            ) or folded.startswith(("ideally ", "preferred ", "bonus "))
            classification = "desirable" if desirable else "essential"
            digest = hashlib.sha256(normalized.encode()).hexdigest()
            result.append(
                {
                    "requirement_id": (
                        f"{classification}:{len(result) + 1:03d}:{digest[:12]}"
                    ),
                    "classification": classification,
                    "requirement_text": normalized,
                    "requirement_text_sha256": digest,
                }
            )
    if not result:
        raise ValueError("vacancy has no deterministic atomic requirements")
    return tuple(result)


def _prepared_text(value: str) -> str:
    """Casefold and collapse a phrase to its canonical multi-word entity tokens."""

    folded = " ".join(value.casefold().split())
    for phrase, canonical in _ENTITY_PHRASES.items():
        folded = folded.replace(phrase, canonical)
    return folded


def _canonical_entity(token: str) -> str | None:
    token = token.strip(".,;:()[]/-")
    canonical = _ENTITY_CANON.get(token)
    if canonical is not None:
        return canonical
    if token.endswith("s") and len(token) > 2:
        return _ENTITY_CANON.get(token[:-1])
    return None


def _entities_in(text: str) -> tuple[str, ...]:
    seen: list[str] = []
    for token in WORD.findall(text):
        canonical = _canonical_entity(token)
        if canonical is not None and canonical not in seen:
            seen.append(canonical)
    return tuple(seen)


def _detect_action(text: str) -> str:
    for action, markers in _ACTION_KEYWORDS:
        if any(marker in text for marker in markers):
            return action
    return "experience"


def _detect_actions(text: str) -> tuple[str, ...]:
    """Every action a clause asserts (a clause may coordinate several verbs)."""

    found = tuple(
        action
        for action, markers in _ACTION_KEYWORDS
        if any(marker in text for marker in markers)
    )
    return found or ("experience",)


def _detect_modality(text: str) -> str:
    for modality in _MODALITY_RANK:
        if any(marker in text for marker in _MODALITY_MARKERS[modality]):
            return modality
    return "unspecified"


def _required_modality(text: str) -> frozenset[str] | None:
    for modality in _MODALITY_RANK:
        if modality not in _MODALITY_REQUIREMENT:
            continue
        if any(marker in text for marker in _MODALITY_MARKERS[modality]):
            return _MODALITY_REQUIREMENT[modality]
    return None


def _is_negated(clause: str) -> bool:
    return any(marker in clause for marker in _NEGATION_MARKERS)


def _statement_facts(statement: str) -> tuple[tuple[str, str, str], ...]:
    """Deterministically type an arbitrary evidence statement into facts.

    Each clause contributes ``(entity, action, modality)`` triples for the named
    entities it asserts; clauses under negation contribute nothing so an explicit
    ``not …`` can never mint positive support. The approved eighteen statements are
    served from the hash-bound atlas instead of this parser (see
    :func:`typed_evidence_projection`); the parser covers other statements exactly
    and identically.
    """

    facts: list[tuple[str, str, str]] = []
    prepared = _prepared_text(statement)
    for clause in re.split(r"[.;:]", prepared):
        clause = clause.strip()
        if not clause or _is_negated(clause):
            continue
        actions = _detect_actions(clause)
        modality = _detect_modality(clause)
        for entity in _entities_in(clause):
            for action in actions:
                fact = (entity, action, modality)
                if fact not in facts:
                    facts.append(fact)
    return tuple(facts)


def typed_evidence_projection(
    evidence: Sequence[Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    """Typed, hash-bound projection of the approved evidence statements.

    Each entry binds the evidence id and the SHA-256 of its exact statement text
    to a set of typed ``(entity, action, modality)`` facts. For the eighteen
    approved statements the facts come from the explicit, reviewable
    :data:`_APPROVED_EVIDENCE_ATLAS`, keyed by statement hash, so any change to the
    shared candidate source both fails the pinned-hash gate and misses the atlas.
    Statements outside the atlas are typed by the deterministic parser. Matching
    consumes only these typed facts — never generic token overlap — so a
    requirement is supported solely when its material subject, action/relation,
    modality and numeric extent are all entailed by the same evidence item.
    """

    projection: dict[str, dict[str, object]] = {}
    for row in evidence:
        statement = str(row["statement"])
        statement_sha256 = hashlib.sha256(statement.encode()).hexdigest()
        facts = _APPROVED_EVIDENCE_ATLAS.get(statement_sha256)
        if facts is None:
            facts = _statement_facts(statement)
        projection[str(row["id"])] = {
            "schema": TYPED_EVIDENCE_SCHEMA,
            "statement_sha256": statement_sha256,
            "facts": tuple(
                {"entity": entity, "action": action, "modality": modality}
                for entity, action, modality in facts
            ),
        }
    return projection


def typed_evidence_projection_hash(
    evidence: Sequence[Mapping[str, object]],
) -> str:
    """Content hash of the typed evidence projection, bound to its schema."""

    return hashlib.sha256(
        _json_bytes(
            {
                "schema": TYPED_EVIDENCE_SCHEMA,
                "projection": typed_evidence_projection(evidence),
            }
        )
    ).hexdigest()


def _requirement_atom(requirement: str) -> dict[str, object]:
    """Parse a requirement clause into a typed constraint.

    ``conjuncts`` is a list of alternative-entity groups: every group must be
    satisfied (conjunction) and a group is satisfied when any one of its entities
    is (disjunction). Alternatives are recognised only for an ``or`` / ``/`` clause
    with no ``and``; every other shape is treated as a conjunction, which is the
    conservative reading.
    """

    prepared = _prepared_text(requirement)
    entities = _entities_in(prepared)
    disjunctive = (" or " in prepared or "/" in prepared) and " and " not in prepared
    if not entities:
        conjuncts: list[frozenset[str]] = []
    elif disjunctive:
        conjuncts = [frozenset(entities)]
    else:
        conjuncts = [frozenset({entity}) for entity in entities]
    years = _YEARS.search(prepared)
    return {
        "conjuncts": conjuncts,
        "action": _detect_action(prepared),
        "modality": _required_modality(prepared),
        "requires_years": bool(years),
        "requires_scale": any(marker in prepared for marker in _SCALE_MARKERS),
        "negated": _is_negated(prepared),
    }


def _fact_supports(
    fact: Mapping[str, object],
    entity: str,
    action: str,
    modality: frozenset[str] | None,
) -> bool:
    if fact["entity"] != entity:
        return False
    if action not in _ACTION_SATISFIES.get(str(fact["action"]), frozenset()):
        return False
    if modality is not None and fact["modality"] not in modality:
        return False
    return True


def _matched_evidence(
    requirement: str,
    evidence: Sequence[Mapping[str, object]],
    projection: Mapping[str, Mapping[str, object]] | None = None,
) -> tuple[str, ...]:
    atom = _requirement_atom(requirement)
    conjuncts = atom["conjuncts"]
    if not conjuncts:
        # No named material subject to prove: a soft or generic requirement that
        # cannot be deterministically supported. It stays a gap; generic token
        # overlap must never mint a qualification.
        return ()
    if atom["negated"] or atom["requires_years"] or atom["requires_scale"]:
        # A requirement that negates its subject, or demands an explicit numeric
        # duration/scale the approved evidence never attests, cannot be supported.
        return ()
    action = str(atom["action"])
    modality = atom["modality"]
    if projection is None:
        projection = typed_evidence_projection(evidence)
    matches: list[str] = []
    for row in evidence:
        facts = projection[str(row["id"])]["facts"]
        # Every conjunct must be satisfied by some fact of *this same* evidence
        # item; a conjunct with alternatives (disjunction) needs only one branch.
        if all(
            any(
                _fact_supports(fact, entity, action, modality)
                for entity in group
                for fact in facts
            )
            for group in conjuncts
        ):
            matches.append(str(row["id"]))
    return tuple(matches)


def _applied_suppressors(requirement: str) -> tuple[str, ...]:
    folded = requirement.casefold()
    return tuple(
        suppressor_id
        for suppressor_id, markers in _SUPPRESSOR_MARKERS.items()
        if any(marker in folded for marker in markers)
    )


def _evidence_matrix(
    content: str, evidence: Sequence[Mapping[str, object]]
) -> tuple[dict[str, object], ...]:
    rows: list[dict[str, object]] = []
    projection = typed_evidence_projection(evidence)
    for requirement in _requirements(content):
        suppressors = _applied_suppressors(str(requirement["requirement_text"]))
        matches = (
            ()
            if suppressors
            else _matched_evidence(
                str(requirement["requirement_text"]), evidence, projection
            )
        )
        status = "suppressed" if suppressors else "matched" if matches else "gap"
        rows.append(
            {
                **requirement,
                "status": status,
                "evidence_ids": list(matches),
                "suppressor_ids": list(suppressors),
                "weight": "2" if requirement["classification"] == "essential" else "1",
            }
        )
    return tuple(rows)


CANONICAL_REQUIREMENTS_SCHEMA = "market-aligner.requirement-projection.v1"
_CANONICAL_REQUIREMENT_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("required_qualifications", "essential"),
    ("required_skills", "essential"),
    ("responsibilities", "essential"),
    ("preferred_qualifications", "desirable"),
    ("preferred_skills", "desirable"),
)
CANONICAL_REQUIREMENTS_MATRIX_POLICY_SHA256 = hashlib.sha256(
    _json_bytes(
        {
            "category_order": [name for name, _ in _CANONICAL_REQUIREMENT_CATEGORIES],
            "classification": dict(_CANONICAL_REQUIREMENT_CATEGORIES),
            "matcher_schema": TYPED_EVIDENCE_SCHEMA,
            "requirement_schema": CANONICAL_REQUIREMENTS_SCHEMA,
            "schema_version": "jaa.canonical-requirements-matrix-policy.v1",
            "suppressor_mode": "suppress_only",
        }
    )
).hexdigest()


def compile_canonical_requirements_evidence_matrix(
    requirements_bytes: bytes,
    evidence: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Compile JAA evidence selection from an admitted MA requirement projection.

    This is deliberately separate from :func:`_requirements`, which owns the
    legacy HTML extraction path.  The caller supplies the exact, already
    authenticated Market Aligner object bytes.  This function accepts only the
    closed canonical requirement projection shape and applies the existing
    conservative typed matcher; generic overlap therefore cannot promote a
    candidate claim.
    """

    try:
        document = json.loads(requirements_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("canonical requirements object is not JSON") from exc
    expected_keys = {name for name, _ in _CANONICAL_REQUIREMENT_CATEGORIES}
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise ValueError("canonical requirements object has an unsupported shape")
    projection = typed_evidence_projection(evidence)
    rows: list[dict[str, object]] = []
    for category, classification in _CANONICAL_REQUIREMENT_CATEGORIES:
        values = document[category]
        if (
            not isinstance(values, list)
            or any(
                not isinstance(value, str)
                or not value.strip()
                or value != value.strip()
                for value in values
            )
            or len(values) != len(set(values))
        ):
            raise ValueError("canonical requirement category is malformed")
        prefix = category.replace("_", "-")
        for index, requirement_text in enumerate(values, start=1):
            suppressors = _applied_suppressors(requirement_text)
            matches = (
                ()
                if suppressors
                else _matched_evidence(requirement_text, evidence, projection)
            )
            rows.append(
                {
                    "classification": classification,
                    "evidence_ids": list(matches),
                    "requirement_category": category,
                    "requirement_id": f"{prefix}:{index:03d}",
                    "requirement_text": requirement_text,
                    "requirement_text_sha256": hashlib.sha256(
                        requirement_text.encode()
                    ).hexdigest(),
                    "status": (
                        "suppressed"
                        if suppressors
                        else "matched"
                        if matches
                        else "gap"
                    ),
                    "suppressor_ids": list(suppressors),
                    "weight": "2" if classification == "essential" else "1",
                }
            )
    if not rows:
        raise ValueError("canonical requirements object is empty")
    body: dict[str, object] = {
        "evidence_projection_schema": TYPED_EVIDENCE_SCHEMA,
        "evidence_projection_sha256": typed_evidence_projection_hash(evidence),
        "matrix": rows,
        "matrix_policy_sha256": CANONICAL_REQUIREMENTS_MATRIX_POLICY_SHA256,
        "row_matrix_sha256": hashlib.sha256(_json_bytes(rows)).hexdigest(),
        "requirements_sha256": hashlib.sha256(requirements_bytes).hexdigest(),
        "schema_version": "jaa.canonical-requirements-evidence-matrix.v1",
    }
    body["compiler_receipt_sha256"] = hashlib.sha256(_json_bytes(body)).hexdigest()
    return body


def fit_from_evidence_matrix(matrix: Sequence[Mapping[str, object]]) -> str:
    total = Decimal("0")
    matched = Decimal("0")
    for row in matrix:
        weight = (
            Decimal("2") if row.get("classification") == "essential" else Decimal("1")
        )
        total += weight
        if row.get("status") == "matched":
            matched += weight
    if not total:
        raise ValueError("fit evidence matrix has zero total weight")
    return str((matched / total).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP))


def _source_bytes(sources: CandidateAuthoritySources) -> dict[str, bytes]:
    paths = {
        "availability": sources.availability,
        "approved_evidence": sources.approved_evidence,
        "operator_answers": sources.operator_answers,
        "negative_claim_suppressors": sources.negative_claim_suppressors,
        "jobs_database": sources.jobs_database,
    }
    values: dict[str, bytes] = {}
    for name, candidate in paths.items():
        path = _regular_file(candidate, f"candidate source {name}")
        value = path.read_bytes()
        if hashlib.sha256(value).hexdigest() != APPROVED_CANDIDATE_SOURCE_HASHES[name]:
            raise ValueError(f"approved candidate source hash differs: {name}")
        values[name] = value
    return values


def _approved_evidence(value: bytes) -> tuple[dict[str, object], ...]:
    document = json.loads(value)
    statements = document.get("statements")
    if (
        document.get("schema_version") != "jaa05.operator-approved-statements.v1"
        or not isinstance(statements, list)
        or tuple(row.get("id") for row in statements if isinstance(row, Mapping))
        != APPROVED_EVIDENCE_IDS
    ):
        raise ValueError("approved candidate evidence packet is malformed")
    result: list[dict[str, object]] = []
    for row in statements:
        if (
            not isinstance(row, Mapping)
            or not EVIDENCE_ID.fullmatch(str(row.get("id", "")))
            or row.get("kind")
            not in {
                "credential",
                "portfolio_artifact",
                "employment_record",
                "test_result",
            }
            or row.get("proof_class") != row.get("kind")
            or not isinstance(row.get("statement"), str)
            or not str(row["statement"]).strip()
        ):
            raise ValueError("approved candidate evidence statement is malformed")
        result.append(dict(row))
    return tuple(result)


def _claim_suppressors(value: bytes) -> tuple[dict[str, str], ...]:
    result: list[dict[str, str]] = []
    for line in value.decode().splitlines():
        match = SUPPRESSOR_ROW.fullmatch(line.strip())
        if not match:
            continue
        suppressor_id, claim, ruling = match.groups()
        result.append(
            {
                "id": suppressor_id,
                "claim_sha256": hashlib.sha256(claim.encode()).hexdigest(),
                "ruling_sha256": hashlib.sha256(ruling.encode()).hexdigest(),
            }
        )
    if tuple(row["id"] for row in result) != tuple(
        f"Q-{index:03d}" for index in range(1, 11)
    ):
        raise ValueError("negative claim suppressor inventory is incomplete")
    return tuple(result)


def archive_duplicate_snapshot(
    archive_root: Path, repository_root: Path
) -> tuple[str, frozenset[str]]:
    rows: list[dict[str, object]] = []
    quarantined: set[str] = set()
    attempts_root = archive_root / "attempts"
    if attempts_root.is_dir():
        for manifest_path in sorted(attempts_root.glob("*/terminal-manifest.json")):
            attempt_id = manifest_path.parent.name
            verification = verify_complete_attempt(
                attempt_id,
                root=archive_root,
                repository_root=repository_root,
            )
            raw = manifest_path.read_bytes()
            manifest = json.loads(raw)
            roles = {str(row.get("role")) for row in manifest.get("objects", [])}
            job_key = str(manifest["vacancy"]["job_key"])
            click_intent = "submission.click_intent" in roles
            outcome = str(verification["outcome"])
            quarantine = click_intent or outcome in {
                "submitted_success",
                "historical_submitted_success",
                "indeterminate",
            }
            if quarantine:
                quarantined.add(job_key)
            rows.append(
                {
                    "attempt_id": attempt_id,
                    "job_key": job_key,
                    "vacancy_sha256": manifest["vacancy"]["vacancy_sha256"],
                    "outcome": outcome,
                    "click_intent": click_intent,
                    "terminal_manifest_sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
    snapshot = _json_bytes(rows)
    digest = hashlib.sha256(snapshot).hexdigest()
    _atomic_create_or_verify(
        archive_root,
        archive_root / "objects" / digest[:2] / digest,
        snapshot,
    )
    return digest, frozenset(quarantined)


def _projection(
    evidence: Sequence[Mapping[str, object]],
    suppressors: Sequence[Mapping[str, str]],
    *,
    schema_sha256: str,
    policy_sha256: str,
) -> dict[str, object]:
    projection: dict[str, object] = {
        "schema_version": "jaa.candidate-authority-projection.v1",
        "source_hashes": dict(APPROVED_CANDIDATE_SOURCE_HASHES),
        "schema_sha256": schema_sha256,
        "policy_sha256": policy_sha256,
        "availability": AVAILABILITY_AUTHORITY,
        "approved_evidence": [
            {
                "id": row["id"],
                "statement_sha256": hashlib.sha256(
                    str(row["statement"]).encode()
                ).hexdigest(),
                "kind": row["kind"],
                "proof_class": row["proof_class"],
            }
            for row in evidence
        ],
        "claim_suppressors": {
            "source_sha256": APPROVED_CANDIDATE_SOURCE_HASHES[
                "negative_claim_suppressors"
            ],
            "mode": "suppress_only",
            "items": list(suppressors),
        },
    }
    projection["projection_sha256"] = hashlib.sha256(
        _json_bytes(projection)
    ).hexdigest()
    return projection


def _eligibility_checks(
    job_key: str,
    *,
    description_sha256: str,
    duplicate_snapshot_sha256: str,
    quarantined: bool,
) -> tuple[dict[str, object], str, list[str], list[str]]:
    evidence = [f"vacancy:{description_sha256}", "policy:hard-outcomes"]
    checks = {
        name: {"status": "pass", "evidence_ids": list(evidence)}
        for name in (
            "live_deadline",
            "uk_work_right",
            "sponsorship",
            "location_attendance",
            "mandatory_credentials",
            "duplicate_replay",
        )
    }
    checks["uk_work_right"]["evidence_ids"] = ["candidate:availability"]
    checks["sponsorship"]["evidence_ids"] = ["candidate:availability"]
    checks["location_attendance"]["evidence_ids"] = ["candidate:availability"]
    checks["duplicate_replay"]["evidence_ids"] = [
        f"archive:{duplicate_snapshot_sha256}"
    ]
    reasons: list[str] = []
    missing_facts: list[str] = []
    if quarantined:
        checks["duplicate_replay"]["status"] = "fail"
        reasons.append("prior_submission_or_click_intent_quarantine")
        return checks, "ineligible", reasons, missing_facts
    if job_key in HARD_INELIGIBLE:
        reasons.extend(sorted(HARD_INELIGIBLE[job_key]))
        target = (
            "live_deadline"
            if "application_deadline_passed" in HARD_INELIGIBLE[job_key]
            else "mandatory_credentials"
        )
        checks[target]["status"] = "fail"
        return checks, "ineligible", reasons, missing_facts
    if job_key in HARD_UNRESOLVED:
        missing_facts.extend(sorted(HARD_UNRESOLVED[job_key]))
        reasons.append("mandatory_candidate_fact_unresolved")
        checks["location_attendance"]["status"] = "unresolved"
        return checks, "unresolved", reasons, missing_facts
    if job_key not in HARD_ELIGIBLE:
        raise ValueError("vacancy is outside the approved candidate-authority cohort")
    return checks, "eligible", ["all deterministic eligibility checks passed"], []


def _read_postings(
    database: Path, job_keys: set[str]
) -> dict[str, Mapping[str, object]]:
    connection = sqlite3.connect(f"file:{database}?mode=ro&immutable=1", uri=True)
    try:
        placeholders = ",".join("?" for _ in job_keys)
        rows = connection.execute(
            f"SELECT key, raw_json FROM postings WHERE key IN ({placeholders})",
            tuple(sorted(job_keys)),
        ).fetchall()
    finally:
        connection.close()
    result = {str(key): json.loads(raw) for key, raw in rows}
    if set(result) != job_keys:
        raise ValueError("jobs database does not exactly cover candidate decisions")
    return result


def _atomic_create_or_verify(root: Path, path: Path, value: bytes) -> None:
    relative = path.relative_to(root)
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise ValueError("candidate authority archive parent cannot be a symlink")
        current.mkdir(mode=0o700, exist_ok=True)
    resolved_parent = path.parent.resolve(strict=True)
    if resolved_parent != root and root not in resolved_parent.parents:
        raise ValueError("candidate authority archive parent cannot be a symlink")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != value:
            raise ValueError("candidate authority archive object is not create-only")
        return
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    if (
        hashlib.sha256(path.read_bytes()).hexdigest()
        != hashlib.sha256(value).hexdigest()
    ):
        raise ValueError("candidate authority archive write verification failed")


def _validated_pending_cohort(
    discovery: Mapping[str, object], pending: list[object]
) -> dict[str, Mapping[str, object]]:
    pending_by_key = {
        str(row["job_key"]): row for row in pending if isinstance(row, Mapping)
    }
    if len(pending_by_key) != len(pending):
        raise ValueError("Greenhouse discovery contains duplicate candidate vacancies")
    if not set(pending_by_key).issubset(APPROVED_COHORT):
        raise ValueError("Greenhouse discovery cohort differs from approved policy")

    observations = discovery.get("observations")
    if not isinstance(observations, list):
        raise ValueError("Greenhouse discovery observations are missing")
    approved_observations: dict[str, Mapping[str, object]] = {}
    for row in observations:
        if not isinstance(row, Mapping):
            raise ValueError("Greenhouse discovery observation is malformed")
        job_key = str(row.get("job_key", ""))
        if job_key not in APPROVED_COHORT:
            continue
        if job_key in approved_observations:
            raise ValueError("Greenhouse discovery contains duplicate observations")
        approved_observations[job_key] = row
    if set(approved_observations) != APPROVED_COHORT:
        raise ValueError("Greenhouse discovery silently omits approved vacancies")

    for job_key in sorted(APPROVED_COHORT):
        observation = approved_observations[job_key]
        verdict = observation.get("verdict")
        if not isinstance(verdict, Mapping):
            raise ValueError("Greenhouse discovery observation verdict is malformed")
        if job_key in pending_by_key:
            vacancy = pending_by_key[job_key]
            if (
                verdict.get("live") is not True
                or verdict.get("reason") != "live_application_form_observed"
                or verdict.get("requisition_bound") is not True
                or verdict.get("title_bound") is not True
                or observation.get("body_sha256") != vacancy.get("vacancy_sha256")
                or observation.get("requested_url") != vacancy.get("source_url")
                or str(observation.get("role_title", "")).strip()
                != str(vacancy.get("role_title", "")).strip()
                or str(observation.get("company_name", "")).strip().casefold()
                != str(vacancy.get("company_name", "")).strip().casefold()
            ):
                raise ValueError(
                    "Greenhouse live vacancy differs from its network observation"
                )
            continue
        closed_markers = verdict.get("closed_markers")
        terminal_identity_failure = (
            verdict.get("requisition_bound") is False
            or verdict.get("title_bound") is False
        )
        if (
            verdict.get("live") is not False
            or verdict.get("reason") not in TERMINAL_DISCOVERY_REASONS
            or not isinstance(closed_markers, list)
            or not (closed_markers or terminal_identity_failure)
        ):
            raise ValueError(
                "Greenhouse discovery removed a vacancy without terminal evidence"
            )
    return pending_by_key


def build_candidate_authority_document(
    *,
    discovery_path: Path,
    archive_root: Path,
    repository_root: Path,
    sources: CandidateAuthoritySources = CandidateAuthoritySources(),
) -> dict[str, object]:
    discovery_path = _regular_file(discovery_path, "Greenhouse discovery")
    archive_root = archive_root.resolve(strict=True)
    repository_root = repository_root.resolve(strict=True)
    discovery_bytes = discovery_path.read_bytes()
    discovery = json.loads(discovery_bytes)
    if discovery_bytes != _json_bytes(discovery):
        raise ValueError("Greenhouse discovery is not canonical JSON")
    pending = discovery.get("live_pending_eligibility")
    if (
        discovery.get("schema_version") != "jaa.greenhouse-live-discovery.v2"
        or discovery.get("eligibility_authority") is not False
        or discovery.get("ranking_candidate_profile") != "empty"
        or not isinstance(pending, list)
        or not pending
    ):
        raise ValueError("Greenhouse discovery is not the unranked production cohort")
    pending_by_key = _validated_pending_cohort(discovery, pending)

    values = _source_bytes(sources)
    schema = _regular_file(sources.schema, "candidate authority schema")
    policy = _regular_file(sources.policy, "candidate authority policy")
    schema_sha256 = _file_sha256(schema)
    policy_sha256 = _file_sha256(policy)
    evidence = _approved_evidence(values["approved_evidence"])
    suppressors = _claim_suppressors(values["negative_claim_suppressors"])
    projection = _projection(
        evidence,
        suppressors,
        schema_sha256=schema_sha256,
        policy_sha256=policy_sha256,
    )
    evidence_projection_sha256 = typed_evidence_projection_hash(evidence)
    database = _regular_file(sources.jobs_database, "jobs database")
    postings = _read_postings(database, set(pending_by_key))
    if _file_sha256(database) != APPROVED_CANDIDATE_SOURCE_HASHES["jobs_database"]:
        raise ValueError("approved jobs database changed while being read")
    duplicate_snapshot_sha256, quarantined = archive_duplicate_snapshot(
        archive_root, repository_root
    )
    discovery_sha256 = hashlib.sha256(discovery_bytes).hexdigest()
    decisions: list[dict[str, object]] = []
    for job_key in sorted(pending_by_key):
        vacancy = pending_by_key[job_key]
        posting = postings[job_key]
        description = posting.get("content_text")
        content = posting.get("content")
        if (
            not isinstance(description, str)
            or not description.strip()
            or not isinstance(content, str)
            or not content.strip()
            or posting.get("absolute_url") != vacancy.get("source_url")
            or str(posting.get("title", "")).strip()
            != str(vacancy.get("role_title", "")).strip()
            or str(posting.get("company_name", "")).strip().casefold()
            != str(vacancy.get("company_name", "")).strip().casefold()
        ):
            raise ValueError("jobs database vacancy identity differs from discovery")
        description_sha256 = hashlib.sha256(description.encode()).hexdigest()
        matrix = _evidence_matrix(content, evidence)
        checks, decision, reasons, missing_facts = _eligibility_checks(
            job_key,
            description_sha256=description_sha256,
            duplicate_snapshot_sha256=duplicate_snapshot_sha256,
            quarantined=job_key in quarantined,
        )
        receipt = {
            "schema_version": "jaa.candidate-vacancy-decision-receipt.v1",
            "job_key": job_key,
            "role_title": str(vacancy["role_title"]).strip(),
            "company_name": str(vacancy["company_name"]).strip(),
            "source_url": vacancy["source_url"],
            "observed_at": vacancy["live_verified_at"],
            "vacancy_sha256": vacancy["vacancy_sha256"],
            "discovery_body_sha256": vacancy["vacancy_sha256"],
            "vacancy_description_sha256": description_sha256,
            "database_sha256": APPROVED_CANDIDATE_SOURCE_HASHES["jobs_database"],
            "discovery_sha256": discovery_sha256,
            "duplicate_snapshot_sha256": duplicate_snapshot_sha256,
            "candidate_projection_sha256": projection["projection_sha256"],
            "evidence_projection_schema": TYPED_EVIDENCE_SCHEMA,
            "evidence_projection_sha256": evidence_projection_sha256,
            "schema_sha256": schema_sha256,
            "policy_sha256": policy_sha256,
            "source_hashes": dict(APPROVED_CANDIDATE_SOURCE_HASHES),
            "eligibility_checks": checks,
            "decision": decision,
            "fit": fit_from_evidence_matrix(matrix) if decision == "eligible" else None,
            "reasons": reasons,
            "missing_facts": missing_facts,
            "evidence_matrix": list(matrix),
        }
        decisions.append(
            {
                "job_key": job_key,
                "receipt": receipt,
                "receipt_sha256": hashlib.sha256(_json_bytes(receipt)).hexdigest(),
            }
        )
    document = {
        "schema_version": "jaa.production-candidate-authority.v2",
        "snapshot_sha256": discovery["snapshot_sha256"],
        "discovery_sha256": discovery_sha256,
        "duplicate_snapshot_sha256": duplicate_snapshot_sha256,
        "candidate_projection": projection,
        "decisions": decisions,
    }
    return document


def materialize_candidate_authority(
    *,
    discovery_path: Path,
    archive_root: Path,
    repository_root: Path,
    sources: CandidateAuthoritySources = CandidateAuthoritySources(),
) -> MaterializedCandidateAuthority:
    archive_root = archive_root.resolve(strict=True)
    document = build_candidate_authority_document(
        discovery_path=discovery_path,
        archive_root=archive_root,
        repository_root=repository_root,
        sources=sources,
    )
    output = _json_bytes(document)
    digest = hashlib.sha256(output).hexdigest()
    object_path = archive_root / "objects" / digest[:2] / digest
    authority_path = archive_root / "candidate-authorities" / f"{digest}.json"
    _atomic_create_or_verify(archive_root, object_path, output)
    _atomic_create_or_verify(archive_root, authority_path, output)
    return MaterializedCandidateAuthority(
        document=document,
        value=output,
        sha256=digest,
        object_path=object_path,
        authority_path=authority_path,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discovery", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    result = materialize_candidate_authority(
        discovery_path=arguments.discovery,
        archive_root=arguments.archive_root,
        repository_root=arguments.repository_root,
    )
    eligible = sum(
        row["receipt"]["decision"] == "eligible" for row in result.document["decisions"]
    )
    print(
        canonical_json(
            {
                "authority_path": str(result.authority_path),
                "sha256": result.sha256,
                "decision_count": len(result.document["decisions"]),
                "eligible_count": eligible,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "APPROVED_CANDIDATE_SOURCE_HASHES",
    "APPROVED_EVIDENCE_IDS",
    "AVAILABILITY_AUTHORITY",
    "CandidateAuthoritySources",
    "CANONICAL_REQUIREMENTS_MATRIX_POLICY_SHA256",
    "HARD_ELIGIBLE",
    "HARD_INELIGIBLE",
    "HARD_UNRESOLVED",
    "MaterializedCandidateAuthority",
    "archive_duplicate_snapshot",
    "build_candidate_authority_document",
    "compile_canonical_requirements_evidence_matrix",
    "fit_from_evidence_matrix",
    "materialize_candidate_authority",
]
