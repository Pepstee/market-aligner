#!/usr/bin/env python3
"""Run one separately authorised JAA-05 liveness canary.

This command is deliberately unusable without a hash-bound Fable activation
ruling that names the exact source revision, contract, amendment and argv.
Package 023 prepares and tests it offline; Package 023 does not authorise a
network request.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from career_automation.employer_research import RawResponseCache  # noqa: E402
from career_automation.holdout_firewall import load_quarantine_bundle  # noqa: E402
from career_automation.public_access import (  # noqa: E402
    PublicAccessController,
    PublicAccessDenied,
    PublicAccessPolicy,
    USER_AGENT,
)
from scraper.scrapling_client import ScraplingClient  # noqa: E402
from tracked_source_revision import source_git_revision  # noqa: E402


CONTRACT_SHA256 = (
    "c43fd61eee5b950f9a9e80fcfe60fa9008f582c31b265685e440485b06f34323"
)
QUARANTINE_SHA256 = (
    "ad380445efd62019fe970ee1d775e48a5e5f58639bd385823e31780547f1a6c4"
)
POLICY_SHA256 = (
    "95e09b38821efa3f2e82df3b7587d74381d4ae5548dc7adb00416883dad9068e"
)
MAX_CONTENT_REQUESTS = 9
MAX_ROBOTS_REQUESTS = 2
MAX_TOTAL_REQUESTS = 11
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
TIMEOUT_SECONDS = 45
ALLOWED_HOSTS = frozenset({"boards-api.greenhouse.io", "api.lever.co"})


class LivenessCanaryFailure(RuntimeError):
    """The authorised canary failed closed."""


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
        + b"\n"
    )


def _read_bound(path: Path, expected_sha256: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise LivenessCanaryFailure(f"bound input is not a regular file: {path}")
    payload = path.read_bytes()
    actual = _digest(payload)
    if actual != expected_sha256:
        raise LivenessCanaryFailure(
            f"bound input hash mismatch for {path}: "
            f"expected {expected_sha256}, got {actual}"
        )
    return payload


def _json_bound(path: Path, expected_sha256: str) -> dict[str, Any]:
    try:
        value = json.loads(_read_bound(path, expected_sha256))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LivenessCanaryFailure(f"invalid JSON input: {path}") from exc
    if not isinstance(value, dict):
        raise LivenessCanaryFailure(f"JSON input is not an object: {path}")
    return value


def _extract_ruling(wrapper: Mapping[str, Any]) -> dict[str, Any]:
    result = wrapper.get("result")
    if not isinstance(result, str):
        raise LivenessCanaryFailure("activation wrapper has no result text")
    marker = "```json"
    start = result.find(marker)
    if start < 0:
        raise LivenessCanaryFailure("activation wrapper has no JSON ruling")
    start = result.find("\n", start + len(marker))
    end = result.find("```", start + 1)
    if start < 0 or end < 0:
        raise LivenessCanaryFailure("activation ruling JSON fence is incomplete")
    try:
        ruling = json.loads(result[start + 1:end])
    except json.JSONDecodeError as exc:
        raise LivenessCanaryFailure("activation ruling JSON is invalid") from exc
    if not isinstance(ruling, dict):
        raise LivenessCanaryFailure("activation ruling is not an object")
    return ruling


def _validate_contract(contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    if (
        contract.get("schema_version")
        != "jaa05.package022-nonexecutable-liveness-canary-contract.v1"
        or contract.get("execution_authorized") is not False
        or contract.get("canary_executed") is not False
        or contract.get("requests_specified_not_performed") is not True
    ):
        raise LivenessCanaryFailure("Package 022 contract markers differ")
    routes = contract.get("routes")
    if not isinstance(routes, list) or len(routes) != MAX_CONTENT_REQUESTS:
        raise LivenessCanaryFailure("Package 022 exact route count differs")
    for row in routes:
        if (
            not isinstance(row, dict)
            or row.get("host") not in ALLOWED_HOSTS
            or row.get("method") != "GET"
            or row.get("timeout_seconds") != TIMEOUT_SECONDS
            or row.get("retry_count") != 0
            or row.get("follow_redirects") is not False
            or row.get("fallback_engines") != []
            or row.get("maximum_response_bytes") != MAX_RESPONSE_BYTES
            or not isinstance(row.get("url"), str)
            or not row["url"].startswith(f"https://{row['host']}/")
            or _digest(row["url"].encode()) != row.get("canonical_url_sha256")
        ):
            raise LivenessCanaryFailure("Package 022 route bounds differ")
    return [dict(row) for row in routes]


def _validate_amendment(
    amendment: Mapping[str, Any],
    *,
    executor_sha256: str,
) -> None:
    if (
        amendment.get("schema_version")
        != "jaa05.package023-canary-execution-amendment.v1"
        or amendment.get("contract_sha256") != CONTRACT_SHA256
        or amendment.get("execution_authorized") is not False
        or amendment.get("canary_executed") is not False
        or amendment.get("requests_specified_not_performed") is not True
    ):
        raise LivenessCanaryFailure("Package 023 amendment markers differ")
    budget = amendment.get("request_budget")
    if budget != {
        "content_get_maximum": MAX_CONTENT_REQUESTS,
        "robots_get_maximum": MAX_ROBOTS_REQUESTS,
        "total_network_send_maximum": MAX_TOTAL_REQUESTS,
        "retry_count": 0,
        "redirects_permitted": False,
        "resume_permitted": False,
        "frozen_input_permitted": False,
    }:
        raise LivenessCanaryFailure("Package 023 request budget differs")
    executor = amendment.get("future_executor")
    if (
        not isinstance(executor, dict)
        or executor.get("path") != str(Path(__file__).resolve())
        or executor.get("sha256") != executor_sha256
    ):
        raise LivenessCanaryFailure("Package 023 executor binding differs")


def _command_identity(argv: list[str]) -> str:
    normalized = list(argv)
    try:
        activation_index = normalized.index("--activation-sha256") + 1
    except (ValueError, IndexError) as exc:
        raise LivenessCanaryFailure(
            "command lacks activation hash argument"
        ) from exc
    normalized[activation_index] = "{FABLE_ACTIVATION_RULING_SHA256}"
    return _digest(_canonical(normalized))


def _validate_activation(
    wrapper: Mapping[str, Any],
    *,
    wrapper_sha256: str,
    amendment_sha256: str,
    source_commit: str,
    command_sha256: str,
) -> dict[str, Any]:
    ruling = _extract_ruling(wrapper)
    expected = {
        "verdict": "AUTHORISE_LIVE_CANARY_ONCE",
        "source_commit": source_commit,
        "contract_sha256": CONTRACT_SHA256,
        "amendment_sha256": amendment_sha256,
        "policy_sha256": POLICY_SHA256,
        "quarantine_sha256": QUARANTINE_SHA256,
        "command_sha256": command_sha256,
        "maximum_content_gets": MAX_CONTENT_REQUESTS,
        "maximum_robots_gets": MAX_ROBOTS_REQUESTS,
        "maximum_total_network_sends": MAX_TOTAL_REQUESTS,
        "retry_count": 0,
        "resume_permitted": False,
        "frozen_input_permitted": False,
    }
    for key, value in expected.items():
        if ruling.get(key) != value:
            raise LivenessCanaryFailure(
                f"activation ruling field {key} differs"
            )
    if ruling.get("activation_wrapper_sha256") not in {None, wrapper_sha256}:
        raise LivenessCanaryFailure("activation wrapper self-binding differs")
    return ruling


def _validate_external_new_path(path: Path, *, label: str) -> Path:
    resolved = path.resolve()
    if path.exists() or path.is_symlink() or resolved.exists():
        raise LivenessCanaryFailure(f"{label} must be absent: {resolved}")
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise LivenessCanaryFailure(f"{label} must be outside the repository")
    return resolved


class BudgetedClient:
    """Count and hard-bound every transport call before the send."""

    def __init__(
        self,
        delegate: ScraplingClient,
        cache: RawResponseCache,
    ) -> None:
        self.delegate = delegate
        self.cache = cache
        self.total = 0
        self.robots = 0
        self.content = 0
        self.events: list[dict[str, Any]] = []

    def fetch(self, engine: str, url: str, **kwargs: Any) -> dict[str, Any]:
        is_robots = url.endswith("/robots.txt")
        next_robots = self.robots + int(is_robots)
        next_content = self.content + int(not is_robots)
        next_total = self.total + 1
        if (
            next_robots > MAX_ROBOTS_REQUESTS
            or next_content > MAX_CONTENT_REQUESTS
            or next_total > MAX_TOTAL_REQUESTS
        ):
            raise LivenessCanaryFailure("network request budget exhausted")
        timeout = kwargs.get("timeout")
        if (
            engine != "static"
            or type(timeout) not in {int, float}
            or not 0 < float(timeout) <= TIMEOUT_SECONDS
            or kwargs.get("method", "get").casefold() != "get"
        ):
            raise LivenessCanaryFailure("transport engine or timeout differs")
        self.robots = next_robots
        self.content = next_content
        self.total = next_total
        self.events.append(
            {
                "sequence": self.total,
                "kind": "robots" if is_robots else "content",
                "url": url,
                "method": "GET",
                "timeout_seconds": float(timeout),
            }
        )
        response = self.delegate.fetch(engine, url, **kwargs)
        try:
            raw = base64.b64decode(
                str(response["body_base64"]),
                validate=True,
            )
            declared = int(response["body_bytes"])
        except (KeyError, TypeError, ValueError) as exc:
            raise LivenessCanaryFailure(
                "transport response byte envelope is invalid"
            ) from exc
        if len(raw) != declared:
            raise LivenessCanaryFailure("transport response byte count differs")
        if response.get("history", ()) or response.get("url") != url:
            digest, reference = self.cache.store(raw[:MAX_RESPONSE_BYTES])
            self.events[-1].update(
                {
                    "outcome": "redirect_prohibited",
                    "bytes_received": declared,
                    "bytes_preserved": min(declared, MAX_RESPONSE_BYTES),
                    "raw_response_ref": reference,
                    "content_sha256": digest,
                }
            )
            raise LivenessCanaryFailure("redirected response is prohibited")
        if declared > MAX_RESPONSE_BYTES:
            prefix = raw[:MAX_RESPONSE_BYTES]
            digest, reference = self.cache.store(prefix)
            self.events[-1].update(
                {
                    "outcome": "response_too_large",
                    "bytes_received": declared,
                    "bytes_preserved": len(prefix),
                    "raw_response_ref": reference,
                    "content_sha256": digest,
                    "truncated": True,
                }
            )
            raise LivenessCanaryFailure(
                "response exceeded 8 MiB; capped prefix preserved and run failed"
            )
        self.events[-1].update(
            {
                "outcome": "response_received",
                "bytes_received": declared,
            }
        )
        return response


def _decode_response(
    response: Mapping[str, Any],
    *,
    expected_url: str,
) -> tuple[bytes, bool, int]:
    try:
        raw = base64.b64decode(str(response["body_base64"]), validate=True)
        declared = int(response["body_bytes"])
    except (KeyError, TypeError, ValueError) as exc:
        raise LivenessCanaryFailure("response byte envelope is invalid") from exc
    if len(raw) != declared:
        raise LivenessCanaryFailure("response byte count differs")
    history = response.get("history", ()) or ()
    if history or response.get("url") != expected_url:
        raise LivenessCanaryFailure("redirected response is prohibited")
    if declared > MAX_RESPONSE_BYTES:
        return raw[:MAX_RESPONSE_BYTES], True, declared
    return raw, False, declared


def _validate_schema(route: Mapping[str, Any], raw: bytes) -> None:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LivenessCanaryFailure("canary response is not valid JSON") from exc
    schema = route["expected_response_schema"]
    if schema["root_type"] == "object":
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("jobs"), list)
        ):
            raise LivenessCanaryFailure("Greenhouse response schema differs")
    elif schema["root_type"] == "array":
        if not isinstance(value, list) or any(
            not isinstance(item, dict) for item in value
        ):
            raise LivenessCanaryFailure("Lever response schema differs")
    else:
        raise LivenessCanaryFailure("unknown expected response schema")


def _inventory(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(root).as_posix(),
    ):
        body = path.read_bytes()
        rows.append(
            {
                "path": path.relative_to(root).as_posix(),
                "byte_count": len(body),
                "sha256": _digest(body),
            }
        )
    return rows


def _write_manifest(root: Path, document: Mapping[str, Any]) -> None:
    path = root / "canary-run-receipt.json"
    path.write_bytes(_canonical(document))
    path.chmod(0o600)
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def execute(args: argparse.Namespace, *, argv: list[str]) -> dict[str, Any]:
    workspace = _validate_external_new_path(args.workspace, label="workspace")
    output = _validate_external_new_path(args.output, label="success output")
    failure_output = _validate_external_new_path(
        args.failure_output,
        label="failure output",
    )
    if len({workspace, output, failure_output}) != 3:
        raise LivenessCanaryFailure("workspace and outputs must be distinct")
    if output.parent != failure_output.parent or workspace.parent != output.parent:
        raise LivenessCanaryFailure(
            "workspace and outputs must be absent siblings on one filesystem"
        )
    output.parent.mkdir(parents=True, exist_ok=True)

    source_commit = source_git_revision(ROOT)
    executor_sha256 = _digest(Path(__file__).read_bytes())
    contract = _json_bound(args.contract, CONTRACT_SHA256)
    routes = _validate_contract(contract)
    amendment_payload = _read_bound(args.amendment, args.amendment_sha256)
    try:
        amendment = json.loads(amendment_payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LivenessCanaryFailure("amendment JSON is invalid") from exc
    if not isinstance(amendment, dict):
        raise LivenessCanaryFailure("amendment is not an object")
    _validate_amendment(amendment, executor_sha256=executor_sha256)
    _read_bound(args.policy, POLICY_SHA256)
    quarantine = load_quarantine_bundle(args.quarantine, QUARANTINE_SHA256)
    for route in routes:
        if route["canonical_url_sha256"] in quarantine.canonical_url_hashes:
            raise LivenessCanaryFailure("canary route overlaps quarantine")
    activation_payload = _read_bound(args.activation_ruling, args.activation_sha256)
    try:
        activation_wrapper = json.loads(activation_payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LivenessCanaryFailure("activation wrapper JSON is invalid") from exc
    if not isinstance(activation_wrapper, dict):
        raise LivenessCanaryFailure("activation wrapper is not an object")
    command_sha256 = _command_identity(argv)
    activation = _validate_activation(
        activation_wrapper,
        wrapper_sha256=args.activation_sha256,
        amendment_sha256=args.amendment_sha256,
        source_commit=source_commit,
        command_sha256=command_sha256,
    )

    workspace.mkdir(mode=0o700)
    receipt: dict[str, Any] = {
        "schema_version": "jaa05.liveness-canary-run-receipt.v1",
        "status": "running",
        "source_commit": source_commit,
        "executor_sha256": executor_sha256,
        "contract_sha256": CONTRACT_SHA256,
        "amendment_sha256": args.amendment_sha256,
        "policy_sha256": POLICY_SHA256,
        "quarantine_sha256": QUARANTINE_SHA256,
        "activation_wrapper_sha256": args.activation_sha256,
        "activation_ruling_id": activation.get("ruling_id"),
        "command": argv,
        "command_sha256": command_sha256,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "request_budget": {
            "maximum_content_gets": MAX_CONTENT_REQUESTS,
            "maximum_robots_gets": MAX_ROBOTS_REQUESTS,
            "maximum_total_network_sends": MAX_TOTAL_REQUESTS,
        },
        "route_outcomes": [],
        "requests": [],
    }
    cache = RawResponseCache(workspace / "raw")
    client = BudgetedClient(ScraplingClient(ROOT), cache)
    controller = PublicAccessController(
        PublicAccessPolicy.load(args.policy),
        client,
        cache,
        default_delay_seconds=10,
        rate_ledger_path=workspace / "rate-ledger.json",
    )
    try:
        for route in routes:
            outcome: dict[str, Any] = {
                "provider": route["provider"],
                "tenant": route["tenant"],
                "url": route["url"],
                "canonical_url_sha256": route["canonical_url_sha256"],
                "status": "started",
                "http_status": None,
                "bytes_received": None,
                "bytes_preserved": None,
                "content_sha256": None,
                "raw_response_ref": None,
                "truncated": False,
                "robots_receipt": None,
            }
            receipt["route_outcomes"].append(outcome)
            try:
                access = controller.before_request(route["url"])
                response = client.fetch(
                    "static",
                    route["url"],
                    timeout=TIMEOUT_SECONDS,
                    headers={"User-Agent": USER_AGENT},
                )
                raw, truncated, received = _decode_response(
                    response,
                    expected_url=route["url"],
                )
                digest, reference = cache.store(raw)
                outcome.update(
                    {
                        "http_status": int(response.get("status", 0)),
                        "bytes_received": received,
                        "bytes_preserved": len(raw),
                        "content_sha256": digest,
                        "raw_response_ref": reference,
                        "truncated": truncated,
                        "robots_receipt": asdict(access),
                    }
                )
                if truncated:
                    outcome["status"] = "failed_response_too_large"
                    raise LivenessCanaryFailure(
                        "response exceeded 8 MiB; capped prefix preserved and run failed"
                    )
                if not 200 <= outcome["http_status"] < 300:
                    outcome["status"] = "failed_http_status"
                    raise LivenessCanaryFailure("canary content status is not 2xx")
                _validate_schema(route, raw)
                outcome["status"] = "live_schema_valid"
            except PublicAccessDenied as exc:
                outcome["status"] = "robots_or_policy_denied"
                raise LivenessCanaryFailure(str(exc)) from exc
            except LivenessCanaryFailure:
                event = client.events[-1] if client.events else {}
                if event.get("url") == route["url"]:
                    for key in (
                        "bytes_received",
                        "bytes_preserved",
                        "content_sha256",
                        "raw_response_ref",
                        "truncated",
                    ):
                        if key in event:
                            outcome[key] = event[key]
                    if event.get("outcome") == "response_too_large":
                        outcome["status"] = "failed_response_too_large"
                    elif event.get("outcome") == "redirect_prohibited":
                        outcome["status"] = "failed_redirect"
                raise
        receipt["status"] = "success"
        receipt["completed_at"] = datetime.now(timezone.utc).isoformat()
        receipt["requests"] = client.events
        receipt["request_counts"] = {
            "content": client.content,
            "robots": client.robots,
            "total": client.total,
        }
        receipt["raw_inventory"] = _inventory(workspace)
        _write_manifest(workspace, receipt)
        os.rename(workspace, output)
        return receipt
    except BaseException as exc:
        receipt["status"] = "failure"
        receipt["completed_at"] = datetime.now(timezone.utc).isoformat()
        receipt["requests"] = client.events
        receipt["request_counts"] = {
            "content": client.content,
            "robots": client.robots,
            "total": client.total,
        }
        receipt["failure"] = {
            "type": type(exc).__name__,
            "message": str(exc),
        }
        try:
            receipt["raw_inventory"] = _inventory(workspace)
            _write_manifest(workspace, receipt)
            os.rename(workspace, failure_output)
        except BaseException as preserve_error:
            exc.add_note(
                "failure preservation also failed: "
                f"{type(preserve_error).__name__}: {preserve_error}; "
                f"workspace retained at {workspace}"
            )
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--amendment", type=Path, required=True)
    parser.add_argument("--amendment-sha256", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--quarantine", type=Path, required=True)
    parser.add_argument("--activation-ruling", type=Path, required=True)
    parser.add_argument("--activation-sha256", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--failure-output", type=Path, required=True)
    return parser


def main() -> int:
    argv = [str(Path(sys.executable).resolve()), str(Path(__file__).resolve()), *sys.argv[1:]]
    try:
        execute(_parser().parse_args(), argv=argv)
    except Exception as exc:
        print(f"JAA-05 liveness canary: ERROR: {exc}", file=sys.stderr)
        return 2
    print("JAA-05 liveness canary: SUCCESS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
