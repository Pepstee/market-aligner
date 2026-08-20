"""Narrow, read-only Gmail API reconciliation for post-intent submissions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .production_ats_executor import GmailConfirmationEvidence
from .evidence_matching import canonical_json
from .provider_observation_capture import exact_clean_head


COLLECTOR_IDENTITY = "jaa.gmail-api-metadata-reconciler.v1"
COLLECTOR_SOURCE_PATH = "career_automation/gmail_confirmation.py"
ACCESS_TOKEN_ENV = "JAA_GMAIL_OAUTH_ACCESS_TOKEN"
_API_ROOT = "https://gmail.googleapis.com/gmail/v1/users/me"
_PROVIDER_DOMAINS = frozenset({"greenhouse.io", "greenhouse-mail.io"})
_IGNORED_WORDS = frozenset(
    {
        "and",
        "at",
        "engineer",
        "engineering",
        "for",
        "in",
        "of",
        "role",
        "senior",
        "software",
        "the",
    }
)
_POSITIVE_CONFIRMATION = re.compile(
    r"\b(?:thank you for (?:applying|your application)|"
    r"we (?:have )?received your .{0,100}application|"
    r"application (?:has been )?(?:received|submitted)|"
    r"application confirmation)\b",
    re.IGNORECASE,
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _default_http_get(url: str, headers: Mapping[str, str]) -> Mapping[str, object]:
    request = Request(url, headers=dict(headers), method="GET")
    with urlopen(request, timeout=20) as response:  # noqa: S310 - fixed HTTPS API root
        value = response.read(2 * 1024 * 1024 + 1)
    if len(value) > 2 * 1024 * 1024:
        raise ValueError("Gmail metadata response exceeds the safe size limit")
    document = json.loads(value)
    if not isinstance(document, Mapping):
        raise ValueError("Gmail metadata response is malformed")
    return document


_OWNED_HTTP_GET = _default_http_get


def _source_at(repository_root: Path, commit: str, path: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repository_root), "show", f"{commit}:{path}"],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ValueError("Gmail reconciler source is absent from Git")
    return completed.stdout


def _words(value: str) -> set[str]:
    return {
        word
        for word in re.findall(r"[a-z0-9]+", value.casefold())
        if len(word) >= 3 and word not in _IGNORED_WORDS
    }


def _vacancy_matches(
    subject: str, *, application_id: str, company_name: str, role_title: str
) -> bool:
    normalized = " ".join(subject.casefold().split())
    company_words = _words(company_name)
    role_words = _words(role_title)
    subject_words = _words(subject)
    return (
        _POSITIVE_CONFIRMATION.search(subject) is not None
        and
        bool(company_words)
        and company_words.issubset(subject_words)
        and bool(role_words)
        and (
            application_id in normalized
            or role_words.issubset(subject_words)
        )
    )


class GmailAPIConfirmationChecker:
    """Query only provider metadata in a vacancy- and click-scoped time window."""

    def __init__(
        self,
        *,
        repository_root: str | Path,
        access_token_environment: str = ACCESS_TOKEN_ENV,
        http_get: Callable[[str, Mapping[str, str]], Mapping[str, object]]
        | None = None,
    ) -> None:
        self.repository_root = Path(repository_root).resolve(strict=True)
        self.access_token_environment = access_token_environment
        self._http_get = http_get or _OWNED_HTTP_GET
        self._issued_evidence: dict[str, GmailConfirmationEvidence] = {}

    def assert_production_authority(self) -> str:
        """Reject injected transports at the consequential release boundary."""
        if (
            self.access_token_environment != ACCESS_TOKEN_ENV
            or self._http_get is not _OWNED_HTTP_GET
        ):
            raise ValueError(
                "production Gmail reconciliation requires the owned HTTPS transport"
            )
        return self._assert_collector_identity()

    def _assert_collector_identity(self) -> str:
        head = exact_clean_head(self.repository_root)
        committed = _source_at(self.repository_root, head, COLLECTOR_SOURCE_PATH)
        if committed != Path(__file__).read_bytes():
            raise ValueError("running Gmail reconciler differs from exact clean HEAD")
        return hashlib.sha256(committed).hexdigest()

    def _get(
        self,
        path: str,
        parameters: Mapping[str, str],
        *,
        query_events: list[dict[str, object]],
    ) -> Mapping[str, object]:
        token = os.environ.get(self.access_token_environment)
        if not token or token != token.strip() or any(char.isspace() for char in token):
            raise ValueError(
                f"{self.access_token_environment} is required for narrow Gmail reconciliation"
            )
        url = f"{_API_ROOT}/{path}?{urlencode(parameters)}"
        document = self._http_get(
            url,
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
            },
        )
        response_bytes = (canonical_json(dict(document)) + "\n").encode()
        query_events.append(
            {
                "path": (
                    "messages"
                    if path == "messages"
                    else f"messages/{_sha256(path.removeprefix('messages/'))}"
                ),
                "parameters_sha256": hashlib.sha256(
                    (canonical_json(dict(parameters)) + "\n").encode()
                ).hexdigest(),
                "request_url_sha256": hashlib.sha256(url.encode()).hexdigest(),
                "response_sha256": hashlib.sha256(response_bytes).hexdigest(),
                "response_byte_length": len(response_bytes),
            }
        )
        return document

    def check_confirmation(
        self,
        *,
        job_key: str,
        application_id: str,
        company_name: str,
        role_title: str,
        not_before: datetime,
        not_after: datetime,
    ) -> GmailConfirmationEvidence:
        source_sha256 = self._assert_collector_identity()
        if (
            not_before.tzinfo is None
            or not_after.tzinfo is None
            or not_before >= not_after
            or not application_id.isdigit()
            or not job_key.endswith(f":{application_id}")
            or not company_name.strip()
            or not role_title.strip()
        ):
            raise ValueError("Gmail reconciliation scope is invalid")
        lower = int(not_before.astimezone(timezone.utc).timestamp())
        upper = int(not_after.astimezone(timezone.utc).timestamp()) + 1
        quoted_company = company_name.replace('"', "")
        quoted_role = role_title.replace('"', "")
        query = (
            f"after:{lower} before:{upper} "
            "{from:greenhouse.io from:greenhouse-mail.io} "
            f'{{"{quoted_company}" "{quoted_role}" "{application_id}"}}'
        )
        query_events: list[dict[str, object]] = []
        listing = self._get(
            "messages",
            {"maxResults": "50", "q": query},
            query_events=query_events,
        )
        messages = listing.get("messages", [])
        if not isinstance(messages, list):
            raise ValueError("Gmail message listing is malformed")
        matched: list[Mapping[str, str]] = []
        for row in messages:
            if not isinstance(row, Mapping) or not isinstance(row.get("id"), str):
                raise ValueError("Gmail message identity is malformed")
            message_id = str(row["id"])
            if not re.fullmatch(r"[A-Za-z0-9_-]+", message_id):
                raise ValueError("Gmail message identity is malformed")
            metadata = self._get(
                f"messages/{message_id}",
                {
                    "format": "metadata",
                    "metadataHeaders": "From,Subject",
                },
                query_events=query_events,
            )
            internal_date = metadata.get("internalDate")
            payload = metadata.get("payload")
            headers = payload.get("headers") if isinstance(payload, Mapping) else None
            if (
                not isinstance(internal_date, str)
                or not internal_date.isdigit()
                or not isinstance(headers, list)
            ):
                raise ValueError("Gmail message metadata is malformed")
            values = {
                str(item.get("name", "")).casefold(): str(item.get("value", ""))
                for item in headers
                if isinstance(item, Mapping)
            }
            sender = parseaddr(values.get("from", ""))[1]
            sender_domain = sender.rpartition("@")[2].casefold()
            subject = values.get("subject", "")
            received_at = datetime.fromtimestamp(
                int(internal_date) / 1000, timezone.utc
            )
            provider_sender = any(
                sender_domain == domain or sender_domain.endswith(f".{domain}")
                for domain in _PROVIDER_DOMAINS
            )
            if (
                provider_sender
                and not_before.astimezone(timezone.utc)
                <= received_at
                <= not_after.astimezone(timezone.utc)
                and _vacancy_matches(
                    subject,
                    application_id=application_id,
                    company_name=company_name,
                    role_title=role_title,
                )
            ):
                matched.append(
                    {
                        "message_id_sha256": _sha256(message_id),
                        "received_at": received_at.isoformat(),
                        "sender_domain": sender_domain,
                        "subject_sha256": _sha256(subject),
                    }
                )
        matched.sort(key=lambda row: (row["received_at"], row["message_id_sha256"]))
        identity = f"{COLLECTOR_IDENTITY}+source-sha256:{source_sha256}"
        query_receipt = {
            "schema_version": "jaa.gmail-api-query-receipt.v1",
            "collector_source_sha256": source_sha256,
            "job_key_sha256": _sha256(job_key),
            "application_id_sha256": _sha256(application_id),
            "company_name_sha256": _sha256(company_name),
            "role_title_sha256": _sha256(role_title),
            "not_before": not_before.astimezone(timezone.utc).isoformat(),
            "not_after": not_after.astimezone(timezone.utc).isoformat(),
            "events": query_events,
        }
        evidence = GmailConfirmationEvidence(
            collector_identity=identity,
            checked_at=not_after.astimezone(timezone.utc).isoformat(),
            result="match" if matched else "no_match",
            matched_message_metadata=tuple(matched),
            match_reasons=(
                (
                    "positive_confirmation",
                    "provider_sender",
                    "vacancy_identity",
                    "post_intent_time",
                )
                if matched
                else ()
            ),
            query_receipt=query_receipt,
        )
        digest = hashlib.sha256(
            (canonical_json(evidence.document()) + "\n").encode()
        ).hexdigest()
        self._issued_evidence[digest] = evidence
        return evidence

    def verify_evidence(self, evidence: GmailConfirmationEvidence) -> None:
        """Rebind returned evidence to the exact clean collector implementation."""
        expected = (
            f"{COLLECTOR_IDENTITY}+source-sha256:{self.assert_production_authority()}"
        )
        if evidence.collector_identity != expected:
            raise ValueError("Gmail evidence collector identity differs")
        receipt = evidence.query_receipt
        digest = hashlib.sha256(
            (canonical_json(evidence.document()) + "\n").encode()
        ).hexdigest()
        if (
            self._issued_evidence.get(digest) is not evidence
            or not isinstance(receipt, Mapping)
            or receipt.get("schema_version") != "jaa.gmail-api-query-receipt.v1"
            or receipt.get("collector_source_sha256")
            != self.assert_production_authority()
            or not isinstance(receipt.get("events"), list)
            or not receipt["events"]
        ):
            raise ValueError("Gmail evidence lacks an owned query receipt")


__all__ = [
    "ACCESS_TOKEN_ENV",
    "COLLECTOR_IDENTITY",
    "GmailAPIConfirmationChecker",
]
