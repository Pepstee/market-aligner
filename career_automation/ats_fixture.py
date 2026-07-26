"""Cooperative localhost-only ATS fixture for bounded JAA-09 browser tests.

The fixture accepts synthetic application data, keeps uploaded bytes in memory
only long enough to hash them, and emits a deterministic official receipt.
It is not an adapter and cannot address an external ATS.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import threading
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import parse_qs, urlsplit


_APPLICATION_ID = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_UPLOAD_BYTES = 1024 * 1024
_REQUIRED_TEXT = (
    "full_name",
    "email",
    "phone",
    "city",
    "work_authorisation",
    "cover_note",
)
_REQUIRED_UPLOADS = ("cv", "cover_letter")


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _content_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


@dataclass(frozen=True)
class FixtureVacancy:
    application_id: str
    job_key: str
    role_title: str
    company_name: str
    question: str = "Describe one relevant delivery example."

    def __post_init__(self) -> None:
        if not _APPLICATION_ID.fullmatch(self.application_id):
            raise ValueError("fixture application ID is invalid")
        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                self.job_key,
                self.role_title,
                self.company_name,
                self.question,
            )
        ):
            raise ValueError("fixture vacancy fields must be non-empty")


@dataclass(frozen=True)
class FixtureReceipt:
    receipt_id: str
    application_id: str
    job_key: str
    payload_sha256: str
    schema_version: str = "jaa09.fixture-receipt.v1"
    certifies_slice: bool = False

    def document(self, *, include_identity: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "application_id": self.application_id,
            "job_key": self.job_key,
            "payload_sha256": self.payload_sha256,
            "certifies_slice": False,
        }
        if include_identity:
            result["receipt_id"] = self.receipt_id
        return result

    def verify(self) -> None:
        if self.certifies_slice is not False:
            raise ValueError("fixture receipt cannot certify JAA-09")
        expected = _content_hash(self.document(include_identity=False))
        if self.receipt_id != expected:
            raise ValueError("fixture receipt differs from its exact content")


@dataclass(frozen=True)
class _PendingReview:
    nonce: str
    payload_sha256: str
    summary: Mapping[str, str]


class _FixtureState:
    def __init__(
        self,
        vacancy: FixtureVacancy,
        *,
        nonce: Callable[[], str],
        form_token: str,
    ) -> None:
        self.vacancy = vacancy
        self.nonce = nonce
        self.form_token = form_token
        self.lock = threading.Lock()
        self.pending: dict[str, _PendingReview] = {}
        self.receipt: FixtureReceipt | None = None

    def review(
        self,
        text: Mapping[str, str],
        uploads: Mapping[str, tuple[str, str, bytes]],
    ) -> _PendingReview:
        if text.get("fixture_token") != self.form_token:
            raise PermissionError("fixture form authorization is invalid")
        missing = [
            key for key in _REQUIRED_TEXT if not text.get(key, "").strip()
        ]
        if text.get("work_authorisation") == "needs_sponsorship":
            if not text.get("sponsorship_details", "").strip():
                missing.append("sponsorship_details")
        missing.extend(
            key for key in _REQUIRED_UPLOADS if key not in uploads
        )
        if missing:
            raise ValueError(
                "missing required application fields: "
                + ",".join(sorted(missing))
            )
        if "@" not in text["email"] or "\n" in text["email"]:
            raise ValueError("email address is invalid")
        upload_document: dict[str, object] = {}
        for key in _REQUIRED_UPLOADS:
            filename, content_type, content = uploads[key]
            if (
                content_type != "application/pdf"
                or not filename.casefold().endswith(".pdf")
                or not content.startswith(b"%PDF-")
                or len(content) > _MAX_UPLOAD_BYTES
            ):
                raise ValueError(f"{key} must be a bounded PDF")
            upload_document[key] = {
                "filename": Path(filename.replace("\\", "/")).name,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
            }
        body = {
            "contract": "jaa09.fixture-application.v1",
            "application_id": self.vacancy.application_id,
            "job_key": self.vacancy.job_key,
            "fields": {key: text[key].strip() for key in _REQUIRED_TEXT},
            "sponsorship_details": text.get(
                "sponsorship_details",
                "",
            ).strip(),
            "uploads": upload_document,
        }
        payload_sha256 = _content_hash(body)
        summary = {
            "full_name": text["full_name"].strip(),
            "email": text["email"].strip(),
            "work_authorisation": text["work_authorisation"].strip(),
            "cv_sha256": str(upload_document["cv"]["sha256"]),  # type: ignore[index]
            "cover_letter_sha256": str(
                upload_document["cover_letter"]["sha256"]  # type: ignore[index]
            ),
        }
        with self.lock:
            if self.receipt is not None:
                raise FileExistsError("fixture application already submitted")
            value = self.nonce()
            if (
                not isinstance(value, str)
                or len(value) < 24
                or value in self.pending
            ):
                raise ValueError("fixture review nonce is invalid")
            review = _PendingReview(value, payload_sha256, summary)
            self.pending[value] = review
            return review

    def submit(self, nonce: str, form_token: str) -> FixtureReceipt:
        with self.lock:
            if form_token != self.form_token:
                raise PermissionError("fixture form authorization is invalid")
            if self.receipt is not None:
                raise FileExistsError("fixture application already submitted")
            review = self.pending.pop(nonce, None)
            if review is None:
                raise PermissionError("fixture review authorization is invalid")
            provisional = FixtureReceipt(
                "0" * 64,
                self.vacancy.application_id,
                self.vacancy.job_key,
                review.payload_sha256,
            )
            receipt = FixtureReceipt(
                _content_hash(provisional.document(include_identity=False)),
                provisional.application_id,
                provisional.job_key,
                provisional.payload_sha256,
            )
            receipt.verify()
            self.pending.clear()
            self.receipt = receipt
            return receipt


def _host_is_loopback(value: str) -> bool:
    hostname = value.rsplit(":", 1)[0].strip("[]").casefold()
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _page(title: str, body: str) -> bytes:
    return f"""<!doctype html>
<html lang="en-GB">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>{escape(title)}</title>
  <style>
    :root {{
      --bg: oklch(1 0 0);
      --surface: oklch(0.965 0.006 200);
      --ink: oklch(0.205 0.018 205);
      --muted: oklch(0.455 0.024 205);
      --line: oklch(0.86 0.014 200);
      --primary: oklch(0.45 0.074 200);
      --primary-hover: oklch(0.39 0.078 200);
      --danger: oklch(0.48 0.16 28);
      --focus: oklch(0.72 0.14 200);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 1rem/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    header {{
      border-bottom: 1px solid var(--line);
      background: var(--surface);
    }}
    header div, main {{ width: min(100% - 2rem, 760px); margin-inline: auto; }}
    header div {{ padding: 1rem 0; display: flex; justify-content: space-between; gap: 1rem; }}
    .product {{ font-weight: 720; }}
    .environment {{ color: var(--muted); }}
    main {{ padding: 2.5rem 0 4rem; }}
    h1 {{ margin: 0 0 .5rem; font-size: 2rem; line-height: 1.18; letter-spacing: -.02em; text-wrap: balance; }}
    h2 {{ margin: 2rem 0 .75rem; font-size: 1.25rem; }}
    p {{ max-width: 68ch; text-wrap: pretty; }}
    .context {{ margin: 0 0 2rem; color: var(--muted); }}
    fieldset {{ margin: 0; padding: 0; border: 0; }}
    .fields {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem 1.25rem; }}
    .field {{ display: flex; flex-direction: column; gap: .4rem; }}
    .wide {{ grid-column: 1 / -1; }}
    label, legend {{ font-weight: 650; }}
    .hint {{ margin: 0; color: var(--muted); font-size: .9rem; }}
    input, select, textarea {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--bg);
      color: var(--ink);
      font: inherit;
      padding: .68rem .75rem;
    }}
    textarea {{ min-height: 9rem; resize: vertical; }}
    input:hover, select:hover, textarea:hover {{ border-color: var(--muted); }}
    input:focus-visible, select:focus-visible, textarea:focus-visible, button:focus-visible {{
      outline: 3px solid var(--focus);
      outline-offset: 2px;
    }}
    button {{
      margin-top: 1.5rem;
      border: 0;
      border-radius: 8px;
      background: var(--primary);
      color: oklch(1 0 0);
      font: inherit;
      font-weight: 700;
      padding: .72rem 1rem;
      cursor: pointer;
    }}
    button:hover {{ background: var(--primary-hover); }}
    button:active {{ transform: translateY(1px); }}
    dl {{ display: grid; grid-template-columns: minmax(9rem, 1fr) 2fr; gap: .7rem 1rem; }}
    dt {{ color: var(--muted); }}
    dd {{ margin: 0; overflow-wrap: anywhere; }}
    .status {{ padding: 1rem; background: var(--surface); border-radius: 10px; }}
    .error {{ color: var(--danger); }}
    code {{ font: .9em ui-monospace, SFMono-Regular, Consolas, monospace; overflow-wrap: anywhere; }}
    [hidden] {{ display: none !important; }}
    @media (max-width: 620px) {{
      .fields {{ grid-template-columns: 1fr; }}
      .wide {{ grid-column: auto; }}
      header div {{ align-items: flex-start; flex-direction: column; }}
      dl {{ grid-template-columns: 1fr; gap: .15rem; }}
      dd {{ margin-bottom: .75rem; }}
    }}
    @media (prefers-reduced-motion: reduce) {{
      *, *::before, *::after {{ scroll-behavior: auto !important; transition: none !important; }}
    }}
  </style>
</head>
<body>
  <header><div><span class="product">Northstar ATS</span><span class="environment">Local test fixture</span></div></header>
  <main>{body}</main>
</body>
</html>
""".encode()


def _application_page(vacancy: FixtureVacancy, form_token: str) -> bytes:
    body = f"""
<h1>{escape(vacancy.role_title)}</h1>
<p class="context">{escape(vacancy.company_name)} · synthetic vacancy · no external submission</p>
<form method="post" action="/applications/{escape(vacancy.application_id)}/review" enctype="multipart/form-data">
  <input type="hidden" name="fixture_token" value="{escape(form_token)}">
  <fieldset>
    <legend>Candidate details</legend>
    <div class="fields">
      <div class="field"><label for="full_name">Full name</label><input id="full_name" name="full_name" autocomplete="name" required></div>
      <div class="field"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required></div>
      <div class="field"><label for="phone">Phone number</label><input id="phone" name="phone" type="tel" autocomplete="tel" required></div>
      <div class="field"><label for="city">Current city</label><input id="city" name="city" autocomplete="address-level2" required></div>
      <div class="field wide">
        <label for="work_authorisation">UK work authorisation</label>
        <select id="work_authorisation" name="work_authorisation" required>
          <option value="">Select one</option>
          <option value="authorised">Authorised without sponsorship</option>
          <option value="needs_sponsorship">Sponsorship required</option>
        </select>
      </div>
      <div class="field wide" id="sponsorship_field" hidden>
        <label for="sponsorship_details">Sponsorship details</label>
        <textarea id="sponsorship_details" name="sponsorship_details"></textarea>
      </div>
      <div class="field wide"><label for="cover_note">{escape(vacancy.question)}</label><textarea id="cover_note" name="cover_note" required></textarea></div>
      <div class="field"><label for="cv">CV (PDF)</label><input id="cv" name="cv" type="file" accept="application/pdf,.pdf" required></div>
      <div class="field"><label for="cover_letter">Cover letter (PDF)</label><input id="cover_letter" name="cover_letter" type="file" accept="application/pdf,.pdf" required></div>
    </div>
  </fieldset>
  <button type="submit">Review application</button>
</form>
<script>
  const authorisation = document.querySelector("#work_authorisation");
  const sponsorship = document.querySelector("#sponsorship_field");
  const details = document.querySelector("#sponsorship_details");
  function syncSponsorship() {{
    const needed = authorisation.value === "needs_sponsorship";
    sponsorship.hidden = !needed;
    details.required = needed;
  }}
  authorisation.addEventListener("change", syncSponsorship);
  syncSponsorship();
</script>
"""
    return _page(f"{vacancy.role_title} application", body)


def _review_page(
    vacancy: FixtureVacancy,
    review: _PendingReview,
    form_token: str,
) -> bytes:
    rows = "".join(
        f"<dt>{escape(key.replace('_', ' ').title())}</dt><dd>{escape(value)}</dd>"
        for key, value in review.summary.items()
    )
    return _page(
        "Review application",
        f"""
<h1>Review application</h1>
<p class="context">Check the synthetic values below. This button submits only to the local fixture.</p>
<div class="status"><dl>{rows}</dl></div>
<form method="post" action="/applications/{escape(vacancy.application_id)}/submit">
  <input type="hidden" name="review_nonce" value="{escape(review.nonce)}">
  <input type="hidden" name="fixture_token" value="{escape(form_token)}">
  <button type="submit" data-testid="final-submit">Submit test application</button>
</form>
""",
    )


def _receipt_page(receipt: FixtureReceipt) -> bytes:
    return _page(
        "Application receipt",
        f"""
<h1>Application received</h1>
<p class="context">The local ATS fixture produced this content-addressed receipt.</p>
<div class="status" role="status">
  <dl>
    <dt>Receipt ID</dt><dd><code data-testid="receipt-id">{receipt.receipt_id}</code></dd>
    <dt>Application</dt><dd>{escape(receipt.application_id)}</dd>
    <dt>Payload hash</dt><dd><code data-testid="payload-hash">{receipt.payload_sha256}</code></dd>
  </dl>
</div>
""",
    )


class LocalATSFixture:
    """Threaded loopback HTTP fixture with bounded, in-memory submission state."""

    def __init__(
        self,
        vacancy: FixtureVacancy,
        *,
        nonce: Callable[[], str] | None = None,
        form_token: str | None = None,
        host: str = "127.0.0.1",
    ) -> None:
        if not _host_is_loopback(host):
            raise ValueError("ATS fixture may bind only to a loopback host")
        self.state = _FixtureState(
            vacancy,
            nonce=nonce or (lambda: secrets.token_urlsafe(24)),
            form_token=form_token or secrets.token_urlsafe(24),
        )
        self.host = host
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("ATS fixture is not running")
        return f"http://{self.host}:{self._server.server_port}"

    @property
    def application_url(self) -> str:
        return (
            f"{self.base_url}/applications/"
            f"{self.state.vacancy.application_id}"
        )

    @property
    def receipt_url(self) -> str:
        return self.application_url + "/receipt"

    @property
    def receipt(self) -> FixtureReceipt | None:
        return self.state.receipt

    def start(self) -> "LocalATSFixture":
        if self._server is not None:
            return self
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            server_version = "JAA-Local-ATS/1"

            def log_message(self, _format: str, *args: object) -> None:
                return

            def _headers(
                self,
                status: HTTPStatus,
                *,
                content_type: str = "text/html; charset=utf-8",
                length: int,
            ) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(length))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'none'; style-src 'unsafe-inline'; "
                    "script-src 'unsafe-inline'; form-action 'self'; "
                    "base-uri 'none'; frame-ancestors 'none'",
                )
                self.end_headers()

            def _send(
                self,
                status: HTTPStatus,
                body: bytes,
                *,
                content_type: str = "text/html; charset=utf-8",
            ) -> None:
                self._headers(
                    status,
                    content_type=content_type,
                    length=len(body),
                )
                self.wfile.write(body)

            def _allowed_request(self) -> bool:
                host = self.headers.get("Host", "")
                origin = self.headers.get("Origin")
                return _host_is_loopback(host) and (
                    origin is None
                    or origin == "null"
                    or _host_is_loopback(urlsplit(origin).netloc)
                )

            def _path(self, suffix: str) -> str:
                return (
                    f"/applications/{state.vacancy.application_id}/{suffix}"
                )

            def do_GET(self) -> None:  # noqa: N802
                if not self._allowed_request():
                    self._send(HTTPStatus.FORBIDDEN, b"loopback only")
                    return
                path = urlsplit(self.path).path
                if path == f"/applications/{state.vacancy.application_id}":
                    self._send(
                        HTTPStatus.OK,
                        _application_page(
                            state.vacancy,
                            state.form_token,
                        ),
                    )
                    return
                if path == self._path("receipt"):
                    if state.receipt is None:
                        self._send(
                            HTTPStatus.NOT_FOUND,
                            b"receipt not found",
                        )
                    else:
                        self._send(
                            HTTPStatus.OK,
                            _receipt_page(state.receipt),
                        )
                    return
                if path == "/health":
                    self._send(
                        HTTPStatus.OK,
                        b'{"status":"ready"}',
                        content_type="application/json",
                    )
                    return
                self._send(HTTPStatus.NOT_FOUND, b"not found")

            def _body(self) -> bytes:
                try:
                    size = int(self.headers.get("Content-Length", ""))
                except ValueError as exc:
                    raise ValueError("invalid content length") from exc
                if size < 1 or size > _MAX_REQUEST_BYTES:
                    raise ValueError("request body size is invalid")
                body = self.rfile.read(size)
                if len(body) != size:
                    raise ValueError("request body is incomplete")
                return body

            def _multipart(
                self,
                body: bytes,
            ) -> tuple[dict[str, str], dict[str, tuple[str, str, bytes]]]:
                content_type = self.headers.get("Content-Type", "")
                if not content_type.startswith("multipart/form-data;"):
                    raise ValueError("review requires multipart form data")
                message = BytesParser(policy=default).parsebytes(
                    (
                        f"Content-Type: {content_type}\r\n"
                        "MIME-Version: 1.0\r\n\r\n"
                    ).encode()
                    + body
                )
                if not message.is_multipart():
                    raise ValueError("review multipart body is invalid")
                text: dict[str, str] = {}
                uploads: dict[str, tuple[str, str, bytes]] = {}
                for part in message.iter_parts():
                    name = part.get_param(
                        "name",
                        header="content-disposition",
                    )
                    if not name:
                        continue
                    payload = part.get_payload(decode=True) or b""
                    filename = part.get_filename()
                    if filename is None:
                        text[name] = payload.decode("utf-8")
                    else:
                        uploads[name] = (
                            filename,
                            part.get_content_type(),
                            payload,
                        )
                return text, uploads

            def do_POST(self) -> None:  # noqa: N802
                if not self._allowed_request():
                    self._send(HTTPStatus.FORBIDDEN, b"loopback only")
                    return
                try:
                    body = self._body()
                    if urlsplit(self.path).path == self._path("review"):
                        text, uploads = self._multipart(body)
                        review = state.review(text, uploads)
                        self._send(
                            HTTPStatus.OK,
                            _review_page(
                                state.vacancy,
                                review,
                                state.form_token,
                            ),
                        )
                        return
                    if urlsplit(self.path).path == self._path("submit"):
                        values = parse_qs(
                            body.decode("utf-8"),
                            strict_parsing=True,
                        )
                        nonce_values = values.get("review_nonce", [])
                        token_values = values.get("fixture_token", [])
                        if (
                            len(nonce_values) != 1
                            or len(token_values) != 1
                        ):
                            raise PermissionError(
                                "fixture review authorization is invalid"
                            )
                        receipt = state.submit(
                            nonce_values[0],
                            token_values[0],
                        )
                        self._send(
                            HTTPStatus.CREATED,
                            _receipt_page(receipt),
                        )
                        return
                    self._send(HTTPStatus.NOT_FOUND, b"not found")
                except FileExistsError:
                    self._send(
                        HTTPStatus.CONFLICT,
                        _page(
                            "Duplicate application blocked",
                            "<h1>Already submitted</h1>"
                            "<p class=\"error\">The fixture accepts one "
                            "application for this vacancy.</p>",
                        ),
                    )
                except (PermissionError, UnicodeError, ValueError) as error:
                    self._send(
                        HTTPStatus.BAD_REQUEST,
                        _page(
                            "Application blocked",
                            "<h1>Application blocked</h1>"
                            f"<p class=\"error\">{escape(str(error))}</p>",
                        ),
                    )

        self._server = ThreadingHTTPServer((self.host, 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="jaa-local-ats-fixture",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    def __enter__(self) -> "LocalATSFixture":
        return self.start()

    def __exit__(self, *_args: object) -> None:
        self.stop()
