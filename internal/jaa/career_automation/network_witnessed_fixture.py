"""Network-witnessed execution of the frozen synthetic ATS fixture.

This module deliberately has no live-ATS mode.  The outer coordinator creates
one immutable request, runs the inner worker through the Linux namespace
witness, independently reconstructs the result, and only then issues a
non-certifying composite receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import ipaddress
import json
import os
import re
import sqlite3
import stat
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from time import perf_counter_ns
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from playwright._impl._driver import compute_driver_executable
from playwright.sync_api import sync_playwright

from .provider_observation_capture import exact_committed_source_identity

from .application_artifacts import publish_application_artifacts
from .application_compiler import CandidateContact, ProductionApplicationCompiler
from cv_generation.service import validate_application_cv
from .application_strategy import ApplicationStrategyStore
from .ats_fixture import (
    FIXTURE_INERT_FAVICON_HREF,
    FixtureReceipt,
    FixtureVacancy,
    LocalATSFixture,
)
from .browser_executor import (
    LocalBrowserExecutor,
    MaterializedValue,
    ReleaseExecutionAuthority,
)
from .browser_workflows import (
    ActionKind,
    ApprovedValue,
    BrowserAction,
    BrowserWorkflow,
    BrowserWorkflowStore,
    SelectorCandidate,
    SelectorPlan,
    SelectorStrategy,
    SubmissionProof,
    ValueReference,
    ValueSource,
)
from .candidate_graph import CandidateGraph
from .database import CareerDatabase
from .employer_research import (
    Citation,
    EmployerResearchWorker,
    Opportunity1Coordinator,
    RawResponseCache,
)
from .engine import OpportunityGate, scored_job_from_payload
from .evidence_matching import (
    InferenceReceipt,
    MatchProposal,
    MatchingPolicy,
    Requirement,
    candidate_graph_evidence,
    evidence_projection_hash,
    matching_input_hash,
)
from .external_document_assurance import (
    IntendedVacancy,
    assert_application_artifacts,
)
from .gap_optimizer import FitAssessmentStore
from .jaa04_corpus_authority import (
    GRAPHCORE_JOB_KEY,
    RAW_RESPONSE_SHA256,
    ROBOTS_RESPONSE_SHA256,
    FrozenVacancyAuthority,
    verify_graphcore_corpus,
)
from .linux_network_namespace_witness import (
    AF_UNIX_PATH_CAPACITY,
    CHROMIUM_RUNTIME_TMP_SUFFIX_BYTES,
    COMMAND_ENVIRONMENT,
    CooperativeBrowserExpectation,
    LinuxNetworkNamespaceWitness,
    NetworkNamespaceWitnessReceipt,
    NetworkWitnessError,
    RUNTIME_TMP_DERIVATION_SCHEMA_VERSION,
    RUNTIME_TMP_PATH_DOMAIN,
    RUNTIME_TMP_ROOT_MAX_BYTES,
    RUNTIME_TMP_SOCKET_BUDGET_SCHEMA_VERSION,
    SourceIdentity,
    derive_runtime_tmp_binding,
    run_isolated_network_witness,
)
from .testing_application_archive import fixture_release_archive_receipt
from .release_gate import (
    ApplicationCompilationStore,
    OfficialRouteBinding,
    ReleaseGateStore,
)
from .rendering import render_pdf_artifacts
from .shadow_certification import (
    FROZEN_SHADOW_CONTRACT,
    MUTATION_TEST_NODES,
    REQUIRED_INTERRUPTION_POINTS,
    REQUIRED_MUTATION_CONTROLS,
    InterruptionObservation,
    MutationObservation,
    ShadowObservation,
    normalized_submit_event_sha256,
    normalized_workflow_sha256,
)
from .testing_sanity_review import fixture_pass_receipt


REQUEST_SCHEMA_VERSION_V1 = "jaa10.network-witnessed-fixture-request.v1"
RESULT_SCHEMA_VERSION_V1 = "jaa10.network-witnessed-fixture-worker-result.v1"
COMPOSITE_SCHEMA_VERSION_V1 = "jaa10.network-witnessed-fixture-observation-receipt.v1"
REQUEST_SCHEMA_VERSION = "jaa10.network-witnessed-fixture-request.v2"
RESULT_SCHEMA_VERSION = "jaa10.network-witnessed-fixture-worker-result.v2"
COMPOSITE_SCHEMA_VERSION = "jaa10.network-witnessed-fixture-observation-receipt.v2"
POLICY_SCHEMA_VERSION = "jaa10.network-witnessed-fixture-policy.v1"
REQUEST_DOMAIN_V1 = b"jaa10-network-witnessed-fixture-request-v1\0"
REQUEST_DOMAIN = b"jaa10-network-witnessed-fixture-request-v2\0"
NONCE_DOMAIN = b"jaa10-network-witnessed-fixture-nonce-v1\0"
POLICY_DOMAIN = b"jaa10-network-witnessed-fixture-policy-v1\0"
ENVIRONMENT_DOMAIN_V1 = b"jaa10-network-witnessed-fixture-environment-v1\0"
ENVIRONMENT_DOMAIN = b"jaa10-network-witnessed-fixture-environment-v2\0"
EFFECTIVE_ARGV_DOMAIN = b"jaa10-network-witnessed-fixture-effective-argv-v1\0"
WORKER_INVENTORY_DOMAIN_V1 = b"jaa10-network-witnessed-fixture-worker-inventory-v1\0"
WORKER_INVENTORY_DOMAIN = b"jaa10-network-witnessed-fixture-worker-inventory-v2\0"
COMPOSITE_INVENTORY_DOMAIN_V1 = (
    b"jaa10-network-witnessed-fixture-composite-inventory-v1\0"
)
COMPOSITE_INVENTORY_DOMAIN = b"jaa10-network-witnessed-fixture-composite-inventory-v2\0"
COMPOSITE_DOMAIN_V1 = b"jaa10-network-witnessed-fixture-composite-v1\0"
COMPOSITE_DOMAIN = b"jaa10-network-witnessed-fixture-composite-v2\0"
RECONSTRUCTION_DOMAIN_V1 = b"jaa10-network-witnessed-fixture-reconstruction-v1\0"
RECONSTRUCTION_DOMAIN = b"jaa10-network-witnessed-fixture-reconstruction-v2\0"
MAX_REQUEST_BYTES = 2_000_000
MAX_WORKER_RESULT_BYTES = 4_000_000
MAX_ARTIFACT_BYTES = 64_000_000
NONCE = "fixture-review-nonce-00000001"
FORM_TOKEN = "fixture-form-token-00000000001"
DISCLOSURE = "deterministic approved fixture candidate projection; not a real person"
FIXED_CORPUS = Path(
    os.environ.get(
        "JAA_CERTIFIED_CORPUS_ROOT",
        "/home/gutua/software-factory/.control/jaa-12h-supervisor-20260727/"
        "runtime/.jaa04-corpus-v3-a4f4490-releases/"
        "sha256-f93733a741ffe9b0441fe4bf549d3bb34e167d28d90283f70003843805201258",
    )
)
TRACKED_SEED_RELATIVE = Path("career_automation/fixtures/jaa04_admitted_queue.json")
POLICY_DIGEST = hashlib.sha256(b"jaa10-network-witnessed-fixture").hexdigest()
MATCHING_POLICY = MatchingPolicy()
REQUIRED_CHROMIUM_FLAGS = (
    "--disable-background-networking",
    "--disable-client-side-phishing-detection",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-dev-shm-usage",
    "--disable-domain-reliability",
    "--disable-sync",
    "--metrics-recording-only",
    "--no-first-run",
)
FORBIDDEN_CHROMIUM_FLAG_PREFIXES = (
    "--proxy-server",
    "--proxy-pac-url",
    "--host-resolver-rules",
    "--remote-debugging-address=0.0.0.0",
    "--disable-web-security",
)
STRONGEST_CLAIM = (
    "One synthetic local ATS fixture workflow executed through the standing "
    "cooperative Playwright origin/action controls while its supervised "
    "process tree occupied a private Linux network namespace with only "
    "loopback addressing, the exact non-forwarding IPv4/IPv6 route "
    "predicate, zero worker capability sets, NoNewPrivs, no inherited "
    "socket, stable pre/post namespace/process/descriptor evidence, and no "
    "surviving descendant. The exact fixture receipt, browser artifacts, "
    "worker result and kernel witness are mutually content-bound."
)
LIMITATIONS = (
    "absence_of_network_syscall_attempts_not_proved",
    "packet_by_packet_history_not_captured",
    "host_wide_traffic_absence_not_proved",
    "filesystem_unix_shared_memory_and_other_local_side_channels_unbounded",
    "honest_kernel_and_privileged_host_writer_assumed",
    "calendar_and_signed_time_not_authenticated",
    "live_external_vacancy_execution_not_performed",
    "metrics_production_slice_certification_and_external_authority_withheld",
)
HEX_64 = re.compile(r"[0-9a-f]{64}")


class NetworkWitnessedFixtureError(RuntimeError):
    """The bounded synthetic integration failed closed."""


class _ChromiumNetworkAudit:
    """Request-ID-bound Chromium lifecycle evidence for the local fixture.

    Playwright routing remains the enforcement boundary. This listener-only
    audit closes the evidence gap for browser-owned requests that may not be
    exposed to routing, and therefore never blocks or rewrites traffic itself.
    """

    def __init__(self) -> None:
        self.records: list[dict[str, str | None]] = []
        self.protocol_errors: list[str] = []

    def observe_request(self, event: Mapping[str, object]) -> None:
        try:
            request_id = event["requestId"]
            request = event["request"]
            resource_type = event["type"]
            initiator = event["initiator"]
            if (
                type(request_id) is not str
                or type(request) is not dict
                or type(resource_type) is not str
                or type(initiator) is not dict
                or type(request.get("url")) is not str
                or type(request.get("method")) is not str
                or type(initiator.get("type")) is not str
            ):
                raise ValueError("request event fields are malformed")
            if "redirectResponse" in event:
                previous = next(
                    (
                        record
                        for record in reversed(self.records)
                        if record["request_id"] == request_id
                        and record["terminal"] is None
                    ),
                    None,
                )
                if previous is None:
                    raise ValueError("redirect lacks its prior request event")
                previous["terminal"] = "redirected"
            self.records.append(
                {
                    "initiator_type": str(initiator["type"]),
                    "method": str(request["method"]).upper(),
                    "request_id": request_id,
                    "resource_type": resource_type,
                    "terminal": None,
                    "url": str(request["url"]),
                }
            )
        except (KeyError, TypeError, ValueError) as exc:
            self.protocol_errors.append(type(exc).__name__)

    def _observe_terminal(
        self,
        event: Mapping[str, object],
        state: str,
    ) -> None:
        request_id = event.get("requestId")
        if type(request_id) is not str:
            self.protocol_errors.append("terminal_request_id")
            return
        record = next(
            (
                candidate
                for candidate in reversed(self.records)
                if candidate["request_id"] == request_id
                and candidate["terminal"] is None
            ),
            None,
        )
        if record is None:
            self.protocol_errors.append("unbound_terminal")
            return
        record["terminal"] = state

    def observe_finished(self, event: Mapping[str, object]) -> None:
        self._observe_terminal(event, "finished")

    def observe_failed(self, event: Mapping[str, object]) -> None:
        self._observe_terminal(event, "failed")

    def assert_accounted(self) -> None:
        unaccounted = sum(record["terminal"] is None for record in self.records)
        if self.protocol_errors or unaccounted:
            raise NetworkWitnessedFixtureError(
                "Chromium request audit is incomplete; "
                f"protocol_errors={len(self.protocol_errors)}; "
                f"unaccounted_requests={unaccounted}"
            )

    def assert_exact(
        self,
        expected: Sequence[tuple[str, str, str]],
    ) -> None:
        self.assert_accounted()
        actual = tuple(
            (
                str(record["method"]),
                str(record["url"]),
                str(record["resource_type"]),
            )
            for record in self.records
        )
        if actual != tuple(expected):
            raise NetworkWitnessedFixtureError(
                "Chromium request audit differs from the exact fixture sequence; "
                f"expected={len(expected)}; observed={len(actual)}"
            )

    def document(self) -> dict[str, object]:
        self.assert_accounted()
        return {
            "schema_version": "jaa10.chromium-request-lifecycle-audit.v1",
            "listener_mode": "cdp_read_only",
            "records": [dict(record) for record in self.records],
            "protocol_errors": list(self.protocol_errors),
        }


def _install_chromium_request_audit(context, page):
    session = context.new_cdp_session(page)
    audit = _ChromiumNetworkAudit()
    try:
        session.on("Network.requestWillBeSent", audit.observe_request)
        session.on("Network.loadingFinished", audit.observe_finished)
        session.on("Network.loadingFailed", audit.observe_failed)
        session.send("Network.enable")
    except Exception:
        try:
            session.detach()
        except Exception:
            pass
        raise
    return session, audit


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _domain_hash(domain: bytes, payload: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_exclusive(path: Path, payload: bytes, *, final_mode: int = 0o444) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    os.chmod(path, final_mode)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_canonical(path: Path, *, maximum: int) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink():
        raise NetworkWitnessedFixtureError("canonical input cannot be a symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 2
            or before.st_size > maximum
        ):
            raise NetworkWitnessedFixtureError("canonical input file is invalid")
        payload = os.read(descriptor, before.st_size + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    def identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
        )

    if len(payload) != before.st_size or identity(before) != identity(after):
        raise NetworkWitnessedFixtureError("canonical input changed while read")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NetworkWitnessedFixtureError("canonical input JSON is invalid") from error
    if not isinstance(value, dict) or _canonical_json(value) != payload:
        raise NetworkWitnessedFixtureError("canonical input is not canonical JSON")
    return dict(value), payload


def _source_identity(repository: Path) -> SourceIdentity:
    try:
        identity = exact_committed_source_identity(repository)
    except ValueError as error:
        raise NetworkWitnessedFixtureError(str(error)) from error
    return SourceIdentity(identity.head, identity.tree, identity.content_revision)


def _path_identity(path: Path) -> dict[str, object]:
    status = path.stat()
    return {
        "path": str(path),
        "sha256": _sha256_file(path),
        "size": status.st_size,
        "mode": f"{stat.S_IMODE(status.st_mode):04o}",
    }


def _playwright_runtime_identity(
    python_executable: Path,
    chromium_executable: Path,
) -> dict[str, object]:
    driver, cli = (
        Path(value).resolve(strict=True) for value in compute_driver_executable()
    )
    package_root = Path(
        importlib.metadata.distribution("playwright").locate_file("playwright")
    ).resolve(strict=True)
    browsers = package_root / "driver/package/browsers.json"
    registry = json.loads(browsers.read_text(encoding="utf-8"))
    chromium = next(
        (row for row in registry["browsers"] if row.get("name") == "chromium"),
        None,
    )
    if not isinstance(chromium, dict):
        raise NetworkWitnessedFixtureError("Playwright Chromium registry is missing")
    return {
        "python": _path_identity(python_executable),
        "playwright": {
            "version": importlib.metadata.version("playwright"),
            "package_root": str(package_root),
            "browsers_json_sha256": _sha256_file(browsers),
        },
        "node_driver": _path_identity(driver),
        "driver_cli": _path_identity(cli),
        "chromium": {
            **_path_identity(chromium_executable),
            "registry_revision": str(chromium.get("revision")),
            "registry_browser_version": str(chromium.get("browserVersion")),
        },
    }


def _cooperative_policy() -> dict[str, object]:
    return {
        "schema_version": POLICY_SCHEMA_VERSION,
        "fixture_origin_class": "exact_loopback_http_origin_only",
        "route_handler_required_before_navigation": True,
        "existing_loopback_controls_required": True,
        "allowed_action_kinds": [
            "navigate",
            "fill",
            "select_option",
            "upload",
            "click",
            "submit",
        ],
        "required_chromium_flags": list(REQUIRED_CHROMIUM_FLAGS),
        "forbidden_chromium_flag_prefixes": list(FORBIDDEN_CHROMIUM_FLAG_PREFIXES),
        "sandbox_truth": "disabled_by_playwright_in_user_namespace",
        "service_workers": "block",
        "downloads": "accept_disabled",
        "external_actions": 0,
        "real_applications_submitted": 0,
    }


def _request_document(
    *,
    source: SourceIdentity,
    execution_root: Path,
    python_executable: Path,
    chromium_executable: Path,
    integration_nonce: bytes,
) -> dict[str, object]:
    policy = _cooperative_policy()
    runtime_tmp_root, derivation, socket_budget = derive_runtime_tmp_binding(
        source,
        execution_root,
    )
    environment = {
        **COMMAND_ENVIRONMENT,
        "TMPDIR": str(runtime_tmp_root),
    }
    return {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "source": source.document(),
        "integration_nonce": integration_nonce.hex(),
        "integration_nonce_sha256": _domain_hash(NONCE_DOMAIN, integration_nonce),
        "cooperative_policy": policy,
        "cooperative_policy_sha256": _domain_hash(
            POLICY_DOMAIN,
            _canonical_json(policy),
        ),
        "environment": environment,
        "environment_sha256": _domain_hash(
            ENVIRONMENT_DOMAIN,
            _canonical_json(environment),
        ),
        "runtime_tmp_root": str(runtime_tmp_root),
        "runtime_tmp_root_derivation": derivation,
        "socket_budget": socket_budget,
        "runtime_identities": _playwright_runtime_identity(
            python_executable,
            chromium_executable,
        ),
        "frozen_contract": {
            "contract_sha256": FROZEN_SHADOW_CONTRACT.contract_sha256,
            "application_id": FROZEN_SHADOW_CONTRACT.application_id,
            "job_key": FROZEN_SHADOW_CONTRACT.job_key,
            "corpus_inventory_sha256": (FROZEN_SHADOW_CONTRACT.corpus_inventory_sha256),
            "official_response_sha256": (
                FROZEN_SHADOW_CONTRACT.official_response_sha256
            ),
            "dossier_sha256": FROZEN_SHADOW_CONTRACT.dossier_sha256,
            "workflow_sha256": FROZEN_SHADOW_CONTRACT.workflow_sha256,
        },
        "paths": {
            "execution_root": str(execution_root),
            "worker_output": str(execution_root / "worker-output"),
            "integration_tmp": str(runtime_tmp_root),
            "network_evidence": str(execution_root / "network-evidence"),
            "worker_result": str(execution_root / "worker-output/worker-result.json"),
        },
        "maximums": {
            "worker_result_bytes": MAX_WORKER_RESULT_BYTES,
            "artifact_bytes": MAX_ARTIFACT_BYTES,
        },
        "evidence_kind": "synthetic_shadow",
        "execution_claim": "structural_lineage_only",
        "external_actions": 0,
        "real_applications_submitted": 0,
    }


def _validate_request(
    document: Mapping[str, Any],
    *,
    request_path: Path,
    repository: Path,
) -> tuple[SourceIdentity, bytes]:
    expected_keys = {
        "schema_version",
        "source",
        "integration_nonce",
        "integration_nonce_sha256",
        "cooperative_policy",
        "cooperative_policy_sha256",
        "environment",
        "environment_sha256",
        "runtime_tmp_root",
        "runtime_tmp_root_derivation",
        "socket_budget",
        "runtime_identities",
        "frozen_contract",
        "paths",
        "maximums",
        "evidence_kind",
        "execution_claim",
        "external_actions",
        "real_applications_submitted",
    }
    if set(document) != expected_keys:
        raise NetworkWitnessedFixtureError("request field set differs")
    try:
        nonce = bytes.fromhex(str(document["integration_nonce"]))
    except ValueError as error:
        raise NetworkWitnessedFixtureError("request nonce is invalid") from error
    if len(nonce) != 32 or document.get("integration_nonce_sha256") != _domain_hash(
        NONCE_DOMAIN,
        nonce,
    ):
        raise NetworkWitnessedFixtureError("request nonce binding differs")
    policy = document.get("cooperative_policy")
    environment = document.get("environment")
    if (
        document.get("schema_version") != REQUEST_SCHEMA_VERSION
        or policy != _cooperative_policy()
        or document.get("cooperative_policy_sha256")
        != _domain_hash(POLICY_DOMAIN, _canonical_json(policy))
        or not isinstance(environment, dict)
        or document.get("environment_sha256")
        != _domain_hash(ENVIRONMENT_DOMAIN, _canonical_json(environment))
        or document.get("evidence_kind") != "synthetic_shadow"
        or document.get("execution_claim") != "structural_lineage_only"
        or document.get("external_actions") != 0
        or document.get("real_applications_submitted") != 0
    ):
        raise NetworkWitnessedFixtureError("request authority differs")
    source_document = document.get("source")
    if not isinstance(source_document, dict):
        raise NetworkWitnessedFixtureError("request source is invalid")
    source = SourceIdentity(
        str(source_document.get("git_revision")),
        str(source_document.get("tree")),
        str(source_document.get("content_revision")),
    )
    if source != _source_identity(repository):
        raise NetworkWitnessedFixtureError("request source identity differs")
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise NetworkWitnessedFixtureError("request paths are invalid")
    root = request_path.parent.resolve(strict=True)
    try:
        runtime_tmp_root, derivation, socket_budget = derive_runtime_tmp_binding(
            source, root
        )
    except NetworkWitnessError as error:
        raise NetworkWitnessedFixtureError("runtime-temp derivation differs") from error
    expected_environment = {
        **COMMAND_ENVIRONMENT,
        "TMPDIR": str(runtime_tmp_root),
    }
    try:
        anchor_status = runtime_tmp_root.parent.lstat()
        runtime_status = runtime_tmp_root.lstat()
    except OSError as error:
        raise NetworkWitnessedFixtureError("runtime-temp root is missing") from error
    if (
        dict(environment) != expected_environment
        or document.get("runtime_tmp_root") != str(runtime_tmp_root)
        or document.get("runtime_tmp_root_derivation") != derivation
        or document.get("socket_budget") != socket_budget
        or derivation.get("schema_version") != RUNTIME_TMP_DERIVATION_SCHEMA_VERSION
        or derivation.get("domain") != RUNTIME_TMP_PATH_DOMAIN.decode("ascii")
        or socket_budget.get("schema_version")
        != RUNTIME_TMP_SOCKET_BUDGET_SCHEMA_VERSION
        or socket_budget.get("af_unix_path_capacity_bytes") != AF_UNIX_PATH_CAPACITY
        or socket_budget.get("chromium_suffix_bytes")
        != CHROMIUM_RUNTIME_TMP_SUFFIX_BYTES
        or socket_budget.get("maximum_root_bytes") != RUNTIME_TMP_ROOT_MAX_BYTES
        or stat.S_ISLNK(anchor_status.st_mode)
        or not stat.S_ISDIR(anchor_status.st_mode)
        or runtime_tmp_root.parent.resolve(strict=True) != runtime_tmp_root.parent
        or stat.S_ISLNK(runtime_status.st_mode)
        or not stat.S_ISDIR(runtime_status.st_mode)
        or stat.S_IMODE(runtime_status.st_mode) != 0o700
        or (root / "integration-tmp").exists()
        or (root / "integration-tmp").is_symlink()
    ):
        raise NetworkWitnessedFixtureError("runtime-temp binding differs")
    expected_paths = {
        "execution_root": str(root),
        "worker_output": str(root / "worker-output"),
        "integration_tmp": str(runtime_tmp_root),
        "network_evidence": str(root / "network-evidence"),
        "worker_result": str(root / "worker-output/worker-result.json"),
    }
    if paths != expected_paths:
        raise NetworkWitnessedFixtureError("request path layout differs")
    frozen = document.get("frozen_contract")
    if not isinstance(frozen, dict) or frozen != {
        "contract_sha256": FROZEN_SHADOW_CONTRACT.contract_sha256,
        "application_id": FROZEN_SHADOW_CONTRACT.application_id,
        "job_key": FROZEN_SHADOW_CONTRACT.job_key,
        "corpus_inventory_sha256": (FROZEN_SHADOW_CONTRACT.corpus_inventory_sha256),
        "official_response_sha256": (FROZEN_SHADOW_CONTRACT.official_response_sha256),
        "dossier_sha256": FROZEN_SHADOW_CONTRACT.dossier_sha256,
        "workflow_sha256": FROZEN_SHADOW_CONTRACT.workflow_sha256,
    }:
        raise NetworkWitnessedFixtureError("frozen contract identity differs")
    return source, nonce


class _FrozenCorpusResearch:
    def __init__(
        self,
        cache: RawResponseCache,
        authority: FrozenVacancyAuthority,
    ) -> None:
        self.cache = cache
        self.authority = authority

    def retrieve_plan(
        self,
        task: object,
    ) -> tuple[list[Citation], list[dict[str, object]]]:
        if (
            getattr(task, "job_key", None) != self.authority.job_key
            or getattr(task, "company", None) != self.authority.company
            or str(getattr(task, "title", "")).strip() != self.authority.title
            or getattr(task, "url", None) != self.authority.vacancy_url
        ):
            raise ValueError("research task differs from frozen vacancy")
        digest, reference = self.cache.store(self.authority.raw_response_bytes)
        if digest != RAW_RESPONSE_SHA256:
            raise ValueError("frozen response identity changed")
        robots_digest, robots_reference = self.cache.store(
            self.authority.robots_response_bytes
        )
        if (
            robots_digest != ROBOTS_RESPONSE_SHA256
            or robots_reference != f"sha256/0b/{ROBOTS_RESPONSE_SHA256}"
        ):
            raise ValueError("frozen robots identity changed")
        source_document = self.authority.dossier["sources"][0]
        source = Citation(**{**source_document, "raw_response_ref": reference})
        source_plan = self.authority.dossier.get("source_plan")
        if not isinstance(source_plan, list) or not all(
            isinstance(row, dict) for row in source_plan
        ):
            raise ValueError("frozen source plan is missing")
        plan = [
            {
                **row,
                **(
                    {
                        "raw_response_ref": reference,
                        "source_content_sha256": RAW_RESPONSE_SHA256,
                    }
                    if row.get("outcome") == "supported"
                    else {}
                ),
            }
            for row in source_plan
        ]
        return [source], plan


def _fixture_date(database: CareerDatabase) -> date:
    with database.connection() as connection:
        value = connection.execute(
            "SELECT as_of FROM fit_assessment_runs ORDER BY rowid DESC LIMIT 1"
        ).fetchone()[0]
    return date.fromisoformat(str(value))


def _fixture_now(database: CareerDatabase) -> datetime:
    value = _fixture_date(database)
    return datetime(value.year, value.month, value.day, 12, tzinfo=timezone.utc)


def _fit_database(
    output_root: Path,
    authority: FrozenVacancyAuthority,
) -> tuple[CareerDatabase, object, tuple[Requirement, ...]]:
    database = CareerDatabase(output_root / "workflow.sqlite3")
    payload = dict(authority.queue_payload)
    payload.update(
        {
            "board": "greenhouse",
            "job_id": "graphcore:8420314002",
            "job_title": authority.title,
            "company": authority.company,
            "url": authority.vacancy_url,
            "fit": 0.8,
            "opportunity": authority.opportunity_score_bp / 10_000,
            "final": authority.opportunity_score_bp / 100,
            "extraction_confidence": 0.9,
            "body": authority.raw_response_bytes.decode("utf-8"),
            "jaa04_corpus_binding": {
                "corpus_inventory_sha256": authority.inventory_sha256,
                "files_hash": authority.inventory_files_sha256,
                "official_response_sha256": authority.raw_response_sha256,
                "dossier_sha256": authority.dossier_sha256,
                "queue_content_sha256": authority.queue_body_content_sha256,
                "queue_payload_hash": authority.admitted_queue_payload_sha256,
                "tracked_seed_payload_hash": authority.tracked_seed_payload_sha256,
            },
            "jaa04_requirement_anchors": [
                {
                    "text": anchor.text,
                    "byte_start": anchor.byte_start,
                    "byte_length": anchor.byte_length,
                    "source_content_sha256": anchor.source_content_sha256,
                }
                for anchor in authority.requirement_anchors
            ],
        }
    )
    job = scored_job_from_payload(payload)
    if job.key != GRAPHCORE_JOB_KEY:
        raise NetworkWitnessedFixtureError("frozen job identity differs")
    if OpportunityGate(database).bootstrap([job]).queued != 1:
        raise NetworkWitnessedFixtureError("frozen vacancy was not queued")
    cache = RawResponseCache(output_root / "raw-cache")
    coordinator = Opportunity1Coordinator(
        database,
        EmployerResearchWorker(
            database,
            "jaa10-network-witnessed-worker",
            cache,
            retriever=_FrozenCorpusResearch(cache, authority),
        ),
        signal_deriver=lambda _dossier: [],
    )
    result = coordinator.run_once()
    if result is None or result.get("decision") != "pass":
        raise NetworkWitnessedFixtureError("frozen research did not pass")
    with database.connection() as connection:
        payload_hash = str(
            connection.execute(
                "SELECT payload_hash FROM pipeline_jobs WHERE job_key=?",
                (job.key,),
            ).fetchone()[0]
        )
    body = authority.raw_response_bytes.decode("utf-8")
    requirements = tuple(
        Requirement(
            f"graphcore-{index}",
            f"fixture-claim-{index}",
            anchor.text,
            True,
            "evidence",
            "build_evidence",
            ("portfolio_artifact",),
            9000,
            f"vacancy:{job.key}:{payload_hash}",
            (body.index(anchor.text), body.index(anchor.text) + len(anchor.text)),
        )
        for index, anchor in enumerate(authority.requirement_anchors, 1)
    )
    # This is a replay of a content-addressed frozen corpus.  Bind every
    # downstream temporal decision to the corpus observation date so the
    # synthetic acceptance fixture remains reproducible instead of expiring
    # with the host wall clock.
    today = datetime.fromisoformat(authority.observed_at.replace("Z", "+00:00")).date()
    valid_until = today.replace(year=today.year + 1).isoformat()
    graph = CandidateGraph(database.path)
    for index, requirement in enumerate(requirements, 1):
        evidence_id = f"fixture-evidence-{index}"
        graph.add_evidence(
            evidence_id,
            statement=(
                f"Approved synthetic fixture support for {requirement.text}; "
                f"{DISCLOSURE}."
            ),
            source_identity=f"fixture:candidate-evidence:{index}",
            state="evidence",
            evidence_kind="portfolio_artifact",
            valid_until=valid_until,
        )
        graph.verify_evidence(
            evidence_id,
            1,
            decision="approved",
            verifier_kind="deterministic",
            policy_id="jaa10.fixture-candidate-review",
            policy_version="1",
            policy_hash=POLICY_DIGEST,
            reason=DISCLOSURE,
            source_identity="fixture:independent-reviewer",
        )
        graph.add_claim(
            requirement.criterion,
            statement=(f"Fixture claim for {requirement.text}; {DISCLOSURE}."),
            claim_type=("capability", "project", "education")[(index - 1) % 3],
            state="evidence",
            source_identity=f"fixture:candidate-claim:{index}",
            valid_until=valid_until,
        )
        graph.link_claim_evidence(
            requirement.criterion,
            evidence_id,
            source_identity="fixture:claim-evidence-edge",
            edge_type="demonstrated_by",
        )
        graph.approve_claim(requirement.criterion)
    evidence = candidate_graph_evidence(database.path, as_of=today)
    profile_hash = evidence_projection_hash(evidence)
    proposals = tuple(
        MatchProposal(
            requirement.requirement_id,
            (f"fixture-evidence-{index}",),
            9000,
            "direct",
            DISCLOSURE,
            InferenceReceipt(
                "deterministic-fixture",
                "jaa10-network-witnessed-fit-v1",
                POLICY_DIGEST,
                MATCHING_POLICY.policy_hash,
                profile_hash,
                matching_input_hash(
                    requirement,
                    candidate_profile_sha256=profile_hash,
                    as_of=today,
                ),
            ),
        )
        for index, requirement in enumerate(requirements, 1)
    )
    run = FitAssessmentStore(database.path).assess(
        job_key=job.key,
        requirements=requirements,
        proposals=proposals,
        as_of=today,
    )
    if run.status != "ready":
        raise NetworkWitnessedFixtureError("frozen fit assessment is not ready")
    return database, run, requirements


def _issued_release_inputs(
    output_root: Path,
    repository: Path,
    authority: FrozenVacancyAuthority,
) -> tuple[object, ...]:
    database, run, requirements = _fit_database(output_root, authority)
    as_of = _fixture_date(database)
    strategy = ApplicationStrategyStore(database.path).compile_and_record(
        fit_run_id=run.run_id,
        as_of=as_of,
    )
    graph = CandidateGraph(database.path)
    contact_value = {
        "full_name": "Alex Fixture",
        "email": "alex.fixture@example.test",
        "phone": "+44 7700 900123",
        "city": "London",
    }
    graph.add_record(
        "fixture-contact-primary",
        kind="fact",
        subject="contact",
        value=contact_value,
        state="fact",
        source_identity="fixture:verified-contact",
    )
    graph.verify_record(
        "fixture-contact-primary",
        1,
        decision="approved",
        verifier_kind="configured",
        policy_id="jaa10.fixture-contact",
        policy_version="1",
        policy_hash=POLICY_DIGEST,
        reason=DISCLOSURE,
        source_identity="fixture:contact-verifier",
    )
    with database.connection() as connection:
        source_hash = str(
            connection.execute(
                """SELECT provenance.source_hash
                   FROM candidate_records record
                   JOIN candidate_provenance provenance
                     ON provenance.provenance_id=record.provenance_id
                   WHERE record.record_id='fixture-contact-primary'"""
            ).fetchone()[0]
        )
    contact = CandidateContact(
        record_id="fixture-contact-primary",
        record_version=1,
        provenance_sha256=source_hash,
        **contact_value,
    )
    questions = {
        requirement.requirement_id: (
            f"fixture-example-{index}",
            requirement.text,
        )
        for index, requirement in enumerate(requirements, 1)
    }
    source = ProductionApplicationCompiler(database.path).compile(
        strategy.strategy_id,
        as_of=as_of,
        contact=contact,
        questions=questions,
        cv_layout="four_section",
    )
    artifacts = render_pdf_artifacts(source)
    cv_constraint = validate_application_cv(source, artifacts)
    artifact_root = output_root / "published"
    publication = publish_application_artifacts(
        source,
        artifacts,
        root=artifact_root,
        repository_root=repository,
    )
    graph.add_record(
        "fixture-work-right-gb",
        kind="work_right",
        subject="permission",
        value={"permitted": True},
        state="fact",
        source_identity="fixture:operator-work-right",
        jurisdiction="GB",
        contract_type="employee",
        valid_from=as_of.replace(year=as_of.year - 1).isoformat(),
        valid_until=as_of.replace(year=as_of.year + 1).isoformat(),
    )
    graph.verify_record(
        "fixture-work-right-gb",
        1,
        decision="approved",
        verifier_kind="configured",
        policy_id="jaa10.fixture-work-right",
        policy_version="1",
        policy_hash=POLICY_DIGEST,
        reason=DISCLOSURE,
        source_identity="fixture:work-right-verifier",
    )
    compilation = ApplicationCompilationStore(database.path).register(
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=repository,
        as_of=as_of,
    )
    gate = ReleaseGateStore(database.path, clock=lambda: _fixture_now(database))
    route = gate.register_official_route(
        job_key=source.job_key,
        route=OfficialRouteBinding(
            "route:graphcore-local-fixture",
            "offline-test-adapter",
            "1",
            "fixture:local-route-policy",
            POLICY_DIGEST,
            as_of,
            as_of.replace(year=as_of.year + 1),
            True,
        ),
    )
    issued = gate.evaluate_and_issue(
        compilation_id=compilation.compilation_id,
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        artifact_root=artifact_root,
        repository_root=repository,
        jurisdiction="GB",
        contract_type="employee",
        evaluated_at=as_of,
        cv_constraint_receipt=cv_constraint.document(),
        expected_cv_policy_sha256=cv_constraint.policy_sha256,
    )
    return (
        database,
        strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        publication,
        compilation,
        gate,
        route,
        issued,
    )


def _browser_inputs(
    fixture: LocalATSFixture,
    release_inputs: tuple[object, ...],
    repository: Path,
) -> tuple[
    CareerDatabase,
    BrowserWorkflow,
    tuple[ApprovedValue, ...],
    dict[str, MaterializedValue],
    ReleaseExecutionAuthority,
    object,
]:
    (
        database,
        _strategy,
        contact,
        questions,
        source,
        artifacts,
        artifact_root,
        publication,
        _compilation,
        gate,
        _route,
        issued,
    ) = release_inputs
    definitions = (
        ("full_name", ActionKind.FILL, "Full name", contact.full_name),
        ("email", ActionKind.FILL, "Email address", contact.email),
        ("phone", ActionKind.FILL, "Phone number", contact.phone),
        ("city", ActionKind.FILL, "Current city", contact.city),
        (
            "work_authorisation",
            ActionKind.SELECT_OPTION,
            "UK work authorisation",
            "authorised",
        ),
        (
            "cover_note",
            ActionKind.FILL,
            fixture.state.vacancy.question,
            artifacts.editable.answers_text.strip(),
        ),
        (
            "cv",
            ActionKind.UPLOAD,
            "CV (PDF)",
            artifact_root / publication.relative_directory / "cv.pdf",
        ),
        (
            "cover_letter",
            ActionKind.UPLOAD,
            "Cover letter (PDF)",
            artifact_root / publication.relative_directory / "cover-letter.pdf",
        ),
    )
    actions: list[BrowserAction] = [
        BrowserAction(
            "open",
            ActionKind.NAVIGATE,
            target_url=fixture.application_url,
        )
    ]
    approvals: list[ApprovedValue] = []
    values: dict[str, MaterializedValue] = {}
    for identifier, kind, label, value in definitions:
        reference = ValueReference(ValueSource.EVIDENCE, f"EV_{identifier.upper()}")
        selectors = (
            (
                SelectorCandidate(SelectorStrategy.LABEL, "Missing full-name label"),
                SelectorCandidate(SelectorStrategy.CSS, "#full_name"),
            )
            if identifier == "full_name"
            else (SelectorCandidate(SelectorStrategy.LABEL, label),)
        )
        actions.append(
            BrowserAction(
                identifier,
                kind,
                selectors=SelectorPlan(selectors),
                value_reference=reference,
                required_output_keys=(
                    ("field_status", "upload_sha256")
                    if kind is ActionKind.UPLOAD
                    else ("field_status",)
                ),
            )
        )
        authorization = f"APPROVAL_{identifier.upper()}"
        approvals.append(ApprovedValue(reference, authorization))
        expected = (
            hashlib.sha256(value.read_bytes()).hexdigest()
            if isinstance(value, Path)
            else None
        )
        values[reference.key] = MaterializedValue(
            reference,
            authorization,
            value,
            expected,
        )
    actions.extend(
        (
            BrowserAction(
                "review",
                ActionKind.CLICK,
                selectors=SelectorPlan(
                    (
                        SelectorCandidate(
                            SelectorStrategy.ROLE,
                            "button:Review application",
                        ),
                    )
                ),
            ),
            BrowserAction(
                "submit",
                ActionKind.SUBMIT,
                selectors=SelectorPlan(
                    (
                        SelectorCandidate(
                            SelectorStrategy.TEST_ID,
                            "final-submit",
                        ),
                    )
                ),
                required_output_keys=(
                    "receipt_id",
                    "receipt_payload_sha256",
                    "screenshot_sha256",
                    "field_map_sha256",
                    "submit_event_sha256",
                ),
            ),
        )
    )
    workflow = BrowserWorkflow(
        "released_local_fixture_application",
        tuple(actions),
    )
    document_assurance_receipts = assert_application_artifacts(
        cv_pdf_bytes=artifacts.cv_pdf.pdf_bytes,
        cover_letter_pdf_bytes=artifacts.cover_letter_pdf.pdf_bytes,
        answers_text=artifacts.editable.answers_text,
        intended_vacancy=IntendedVacancy(
            job_key=source.job_key,
            vacancy_sha256=source.vacancy_sha256,
            role_title=source.role_title,
            company_name=source.company_name,
        ),
    )
    sanity_review_receipt = fixture_pass_receipt(
        source=source,
        artifacts=artifacts,
        questions=questions,
        state_root=artifact_root,
    )
    archive_receipt, archive_root = fixture_release_archive_receipt(
        source=source,
        artifacts=artifacts,
        questions=questions,
        document_assurance_receipts=document_assurance_receipts,
        sanity_review_receipt=sanity_review_receipt,
        artifact_root=artifact_root,
        repository_root=repository,
        finalized_at=_fixture_now(database),
    )
    authority = ReleaseExecutionAuthority(
        gate=gate,
        release_token=issued.release_token,
        source=source,
        artifacts=artifacts,
        contact=contact,
        questions=questions,
        document_assurance_receipts=document_assurance_receipts,
        sanity_review_receipt=sanity_review_receipt,
        archive_receipt=archive_receipt,
        archive_root=archive_root,
        artifact_root=artifact_root,
        repository_root=repository,
        ats_provider="jaa_loopback",
        application_url=fixture.application_url,
        attached_roles=("cv", "cover_letter"),
        upload_field_names=(),
        field_authority_names=(),
        consent_states=(),
        success_evidence=None,
        jurisdiction="GB",
        contract_type="employee",
        consumed_at=_fixture_now(database),
        receipt_url=fixture.receipt_url,
        application_id=fixture.state.vacancy.application_id,
        job_key=source.job_key,
    )
    return database, workflow, tuple(approvals), values, authority, issued


def _proc_start_ticks(pid: int) -> int:
    fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
    if len(fields) < 22:
        raise NetworkWitnessedFixtureError("process stat is incomplete")
    return int(fields[21])


def _process_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in sorted(Path("/proc").iterdir(), key=lambda value: value.name):
        if not path.name.isdigit():
            continue
        try:
            pid = int(path.name)
            exe = (path / "exe").resolve(strict=True)
            raw = (path / "cmdline").read_bytes()
            fields = (path / "stat").read_text(encoding="ascii").split()
            parent = int(fields[3])
            start = int(fields[21])
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
            continue
        rows.append(
            {
                "pid": pid,
                "parent_pid": parent,
                "process_start_ticks": start,
                "executable": str(exe),
                "raw_cmdline_hex": raw.hex(),
                "raw_cmdline_sha256": hashlib.sha256(raw).hexdigest(),
                "argv": [
                    value.decode("utf-8", "surrogateescape")
                    for value in raw.rstrip(b"\0").split(b"\0")
                    if value
                ],
            }
        )
    return rows


def _browser_process_evidence(
    chromium_executable: Path,
    node_driver: Path,
) -> tuple[dict[str, object], dict[str, str]]:
    rows = _process_rows()
    chromium_rows = [
        row for row in rows if row["executable"] == str(chromium_executable)
    ]
    chromium_pids = {int(row["pid"]) for row in chromium_rows}
    main = [row for row in chromium_rows if int(row["parent_pid"]) not in chromium_pids]
    if len(main) != 1:
        raise NetworkWitnessedFixtureError("unique main Chromium process was not found")
    driver_rows = [row for row in rows if row["executable"] == str(node_driver)]
    if len(driver_rows) != 1 or int(main[0]["parent_pid"]) != int(
        driver_rows[0]["pid"]
    ):
        raise NetworkWitnessedFixtureError("Chromium driver parentage differs")
    argv = main[0]["argv"]
    if not isinstance(argv, list):
        raise NetworkWitnessedFixtureError("Chromium argv is invalid")
    missing = [flag for flag in REQUIRED_CHROMIUM_FLAGS if flag not in argv]
    forbidden = [
        value
        for value in argv
        if any(
            str(value).startswith(prefix) for prefix in FORBIDDEN_CHROMIUM_FLAG_PREFIXES
        )
    ]
    if missing or forbidden:
        raise NetworkWitnessedFixtureError("Chromium launch policy differs")
    environment_raw = Path(f"/proc/{int(driver_rows[0]['pid'])}/environ").read_bytes()
    environment = {}
    for entry in environment_raw.split(b"\0"):
        if not entry or b"=" not in entry:
            continue
        key, value = entry.split(b"=", 1)
        name = key.decode("utf-8", "strict")
        if name.startswith("PW_"):
            environment[name] = value.decode("utf-8", "strict")
    return main[0], dict(sorted(environment.items()))


def _shared_memory_evidence() -> dict[str, object]:
    path = Path("/dev/shm")
    status = path.stat()
    values = os.statvfs(path)
    filesystem = "unknown"
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        before, separator, after = line.partition(" - ")
        if separator and before.split()[4] == "/dev/shm":
            filesystem = after.split()[0]
            break
    return {
        "path": "/dev/shm",
        "mode": f"{stat.S_IMODE(status.st_mode):04o}",
        "device": status.st_dev,
        "filesystem_type": filesystem,
        "size_bytes": values.f_frsize * values.f_blocks,
        "disable_dev_shm_usage_required": True,
    }


def _document_inventory(
    root: Path,
    *,
    exclude: Sequence[Path] = (),
    domain: bytes,
) -> tuple[list[dict[str, object]], str]:
    excluded = {path.resolve(strict=False) for path in exclude}
    rows: list[dict[str, object]] = []
    total = 0
    for path in sorted(root.rglob("*"), key=lambda value: value.as_posix()):
        relative = path.relative_to(root)
        if path.resolve(strict=False) in excluded or relative in {
            Path("workflow.sqlite3-wal"),
            Path("workflow.sqlite3-shm"),
        }:
            continue
        if path.is_symlink():
            raise NetworkWitnessedFixtureError("artifact inventory found a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise NetworkWitnessedFixtureError(
                "artifact inventory found a non-regular file"
            )
        status = path.stat()
        total += status.st_size
        if total > MAX_ARTIFACT_BYTES:
            raise NetworkWitnessedFixtureError("artifact inventory is oversized")
        rows.append(
            {
                "relative_path": path.relative_to(root).as_posix(),
                "mode": f"{stat.S_IMODE(status.st_mode):04o}",
                "size": status.st_size,
                "sha256": _sha256_file(path),
            }
        )
    document = {"files": rows}
    return rows, _domain_hash(domain, _canonical_json(document))


def _finalize_worker_database(path: Path) -> dict[str, object]:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path, timeout=30)
        journal_row = connection.execute("PRAGMA journal_mode").fetchone()
        checkpoint_row = connection.execute(
            "PRAGMA wal_checkpoint(TRUNCATE)"
        ).fetchone()
        if (
            journal_row is None
            or len(journal_row) != 1
            or checkpoint_row is None
            or len(checkpoint_row) != 3
        ):
            raise NetworkWitnessedFixtureError(
                "worker database finalization result is invalid"
            )
        journal_mode = str(journal_row[0]).lower()
        busy, log_frames, checkpointed_frames = (int(value) for value in checkpoint_row)
        if journal_mode != "wal" or busy != 0 or log_frames != checkpointed_frames:
            raise NetworkWitnessedFixtureError(
                "worker database finalization did not quiesce"
            )
        return {
            "journal_mode": journal_mode,
            "checkpoint_mode": "truncate",
            "busy": busy,
            "log_frames": log_frames,
            "checkpointed_frames": checkpointed_frames,
        }
    except (OSError, sqlite3.Error, TypeError, ValueError) as error:
        raise NetworkWitnessedFixtureError(
            "worker database finalization failed"
        ) from error
    finally:
        if connection is not None:
            connection.close()


def _freeze_worker_files(output_root: Path) -> None:
    for path in sorted(output_root.rglob("*"), reverse=True):
        if path.is_symlink():
            raise NetworkWitnessedFixtureError("worker output contains a symlink")
        if path.is_file():
            os.chmod(path, 0o444)
        elif path.is_dir():
            os.chmod(path, 0o700)


def _execute_worker(
    request_path: Path,
    output_root: Path,
    repository: Path,
) -> dict[str, Any]:
    request, request_bytes = _read_canonical(
        request_path,
        maximum=MAX_REQUEST_BYTES,
    )
    source, _nonce = _validate_request(
        request,
        request_path=request_path,
        repository=repository,
    )
    if output_root.resolve(strict=True) != request_path.parent / "worker-output":
        raise NetworkWitnessedFixtureError("worker output root differs")
    if any(output_root.iterdir()):
        raise NetworkWitnessedFixtureError("worker output root is not empty")
    runtime = request["runtime_identities"]
    if not isinstance(runtime, dict):
        raise NetworkWitnessedFixtureError("runtime identities are invalid")
    chromium_document = runtime.get("chromium")
    driver_document = runtime.get("node_driver")
    python_document = runtime.get("python")
    if not all(
        isinstance(value, dict)
        for value in (chromium_document, driver_document, python_document)
    ):
        raise NetworkWitnessedFixtureError("runtime executable identities differ")
    chromium_executable = Path(str(chromium_document["path"])).resolve(strict=True)
    node_driver = Path(str(driver_document["path"])).resolve(strict=True)
    if (
        Path(sys.executable).resolve(strict=True)
        != Path(str(python_document["path"])).resolve(strict=True)
        or _sha256_file(chromium_executable) != chromium_document["sha256"]
        or _sha256_file(node_driver) != driver_document["sha256"]
    ):
        raise NetworkWitnessedFixtureError("runtime executable changed")
    expected_environment = request["environment"]
    if dict(os.environ) != expected_environment:
        raise NetworkWitnessedFixtureError("worker environment differs")
    authority = verify_graphcore_corpus(
        FIXED_CORPUS,
        repository / TRACKED_SEED_RELATIVE,
    )
    release_inputs = _issued_release_inputs(output_root, repository, authority)
    vacancy = FixtureVacancy(
        FROZEN_SHADOW_CONTRACT.application_id,
        authority.job_key,
        authority.title,
        authority.company,
        authority.requirement_anchors[0].text,
    )
    chromium_main: dict[str, object] | None = None
    derived_environment: dict[str, str] | None = None
    chromium_request_audit_document: dict[str, object] | None = None
    chromium_version = ""
    with LocalATSFixture(
        vacancy,
        nonce=lambda: NONCE,
        form_token=FORM_TOKEN,
    ) as fixture:
        (
            database,
            workflow,
            approvals,
            values,
            execution_authority,
            issued,
        ) = _browser_inputs(fixture, release_inputs, repository)
        workflow_sha256 = normalized_workflow_sha256(workflow.to_dict())
        if workflow_sha256 != FROZEN_SHADOW_CONTRACT.workflow_sha256:
            raise NetworkWitnessedFixtureError("normalized workflow differs")
        store = BrowserWorkflowStore(database.path)
        run_id = store.create_run(workflow, run_id="jaa10-frozen-run-1")
        if store.claim_run("jaa10_network_worker", run_id=run_id) is None:
            raise NetworkWitnessedFixtureError("browser workflow lease failed")
        store.authorize_release(
            run_id,
            token=issued.release_token,
            authorization_reference=(
                f"JAA08:{issued.manifest.release_manifest_sha256}"
            ),
            idempotency_key=issued.manifest.release_manifest_sha256,
        )
        elapsed: dict[str, int] = {}
        executor = LocalBrowserExecutor(store, repository_root=repository)
        user_data = output_root / "chromium-profile"
        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                str(user_data),
                headless=True,
                executable_path=str(chromium_executable),
                args=list(REQUIRED_CHROMIUM_FLAGS),
                chromium_sandbox=False,
                service_workers="block",
                accept_downloads=False,
            )
            pages = context.pages
            page = pages[0] if pages else context.new_page()
            cdp_session = None
            try:
                cdp_session, request_audit = _install_chromium_request_audit(
                    context,
                    page,
                )
                chromium_main, derived_environment = _browser_process_evidence(
                    chromium_executable,
                    node_driver,
                )
                chromium_start = int(chromium_main["process_start_ticks"])
                version = cdp_session.send("Browser.getVersion")
                chromium_version = str(version["product"])
                for action in workflow.actions:
                    started = perf_counter_ns()
                    completed = executor.execute_next(
                        page,
                        run_id=run_id,
                        worker_id="jaa10_network_worker",
                        approved_values=approvals,
                        materialized_values=values,
                        release_authority=execution_authority,
                    )
                    elapsed[action.step_id] = (perf_counter_ns() - started) // 1_000_000
                    if completed is None:
                        raise NetworkWitnessedFixtureError(
                            "browser action did not complete"
                        )
                page.wait_for_load_state("networkidle")
                icon_hrefs = page.locator("head link[rel]").evaluate_all(
                    """(links) => links.filter((link) =>
                      (link.getAttribute('rel') || '').toLowerCase().split(/\\s+/)
                        .some((token) => token === 'icon' || token.endsWith('-icon'))
                    ).map((link) => link.getAttribute('href'))"""
                )
                if icon_hrefs != [FIXTURE_INERT_FAVICON_HREF]:
                    raise NetworkWitnessedFixtureError(
                        "local fixture lacks its exact inert favicon declaration"
                    )
                application_url = fixture.application_url.rstrip("/")
                expected_requests = (
                    ("GET", application_url, "Document"),
                    ("POST", application_url + "/review", "Document"),
                    ("POST", application_url + "/submit", "Document"),
                )
                request_audit.assert_exact(expected_requests)
                chromium_request_audit_document = {
                    **request_audit.document(),
                    "expected_requests": [
                        {
                            "method": method,
                            "url": url,
                            "resource_type": resource_type,
                        }
                        for method, url, resource_type in expected_requests
                    ],
                    "inert_favicon_href": FIXTURE_INERT_FAVICON_HREF,
                    "exact_sequence_verified": True,
                }
                screenshot = page.screenshot(full_page=True)
                if _proc_start_ticks(int(chromium_main["pid"])) != chromium_start:
                    raise NetworkWitnessedFixtureError(
                        "Chromium process identity changed"
                    )
            finally:
                if cdp_session is not None:
                    try:
                        cdp_session.detach()
                    except Exception:
                        pass
                context.close()
        screenshot_path = output_root / "screenshot.png"
        _write_exclusive(screenshot_path, screenshot)
        outputs = store.checkpoint_outputs(run_id)["submit"]
        if hashlib.sha256(screenshot).hexdigest() != outputs["screenshot_sha256"]:
            raise NetworkWitnessedFixtureError("screenshot evidence differs")
        fixture_receipt = fixture.receipt
        if fixture_receipt is None:
            raise NetworkWitnessedFixtureError("fixture receipt is missing")
        fixture_receipt.verify()
        dispatch = store.submit_dispatch(run_id)
        if dispatch is None:
            raise NetworkWitnessedFixtureError("durable submit event is missing")
        actual_submit_event = str(outputs["submit_event_sha256"])
        normalized_event = normalized_submit_event_sha256(
            workflow_sha256=workflow_sha256,
            receipt_id=str(outputs["receipt_id"]),
            receipt_payload_sha256=str(outputs["receipt_payload_sha256"]),
            screenshot_sha256=str(outputs["screenshot_sha256"]),
            field_map_sha256=str(outputs["field_map_sha256"]),
        )
        proof = SubmissionProof(
            release_manifest_sha256=str(dispatch["release_manifest_hash"]),
            token_sha256=issued.token_sha256,
            receipt_id=str(outputs["receipt_id"]),
            receipt_payload_sha256=str(outputs["receipt_payload_sha256"]),
            screenshot_sha256=str(outputs["screenshot_sha256"]),
            field_map_sha256=str(outputs["field_map_sha256"]),
            submit_event_sha256=actual_submit_event,
        )
        observation = ShadowObservation(
            observation_id="network-witnessed-local-fixture",
            observed_at=_fixture_now(database).isoformat(),
            run_id=run_id,
            step_id="submit",
            workflow_sha256=workflow_sha256,
            durable_workflow_sha256=workflow.content_hash,
            release_manifest_sha256=str(dispatch["release_manifest_hash"]),
            receipt_id=str(outputs["receipt_id"]),
            receipt_payload_sha256=str(outputs["receipt_payload_sha256"]),
            field_map_sha256=str(outputs["field_map_sha256"]),
            screenshot_sha256=str(outputs["screenshot_sha256"]),
            submit_event_sha256=actual_submit_event,
            normalized_submit_event_sha256=normalized_event,
            submission_proof=proof,
            fixture_receipt=fixture_receipt,
            action_elapsed_ms=elapsed,
            browser_launch_count=1,
            database_bytes=database.path.stat().st_size,
            screenshot_bytes=len(screenshot),
            interruptions=tuple(
                InterruptionObservation(
                    point,
                    "fail_closed" if point == "post_mark_pre_click" else "recovered",
                    0 if point == "post_mark_pre_click" else 1,
                    0 if point == "post_mark_pre_click" else 1,
                )
                for point in REQUIRED_INTERRUPTION_POINTS
            ),
            mutations=tuple(
                MutationObservation(
                    control,
                    MUTATION_TEST_NODES[control],
                    True,
                    False,
                )
                for control in REQUIRED_MUTATION_CONTROLS
            ),
        )
    if (
        chromium_main is None
        or derived_environment is None
        or chromium_request_audit_document is None
    ):
        raise NetworkWitnessedFixtureError("browser process evidence is missing")
    if any(
        row["executable"] in {str(chromium_executable), str(node_driver)}
        for row in _process_rows()
    ):
        raise NetworkWitnessedFixtureError("browser or driver descendant survived")
    fixture_document = fixture_receipt.document()
    proof_document = {
        "release_manifest_sha256": proof.release_manifest_sha256,
        "token_sha256": proof.token_sha256,
        "receipt_id": proof.receipt_id,
        "receipt_payload_sha256": proof.receipt_payload_sha256,
        "screenshot_sha256": proof.screenshot_sha256,
        "field_map_sha256": proof.field_map_sha256,
        "submit_event_sha256": proof.submit_event_sha256,
    }
    normalized_document = {
        "schema_version": "jaa10.normalized-submit-event.v1",
        "sha256": normalized_event,
    }
    durable_document = {
        "schema_version": "jaa10.durable-submit-event.v1",
        "sha256": actual_submit_event,
        "dispatch_state": str(dispatch["state"]),
    }
    argv = list(chromium_main["argv"])
    browser_launch = {
        "schema_version": "jaa10.browser-launch-receipt.v1",
        "required_flags": list(REQUIRED_CHROMIUM_FLAGS),
        "forbidden_flag_prefixes": list(FORBIDDEN_CHROMIUM_FLAG_PREFIXES),
        "sandbox_truth": "disabled_by_playwright_in_user_namespace",
        "main_process": chromium_main,
        "playwright_derived_environment": derived_environment,
        "chromium_version": chromium_version,
    }
    identity_receipt = {
        "schema_version": "jaa10.browser-runtime-identities.v1",
        "requested": request["runtime_identities"],
        "observed_chromium_version": chromium_version,
    }
    artifacts = {
        "fixture-receipt.json": fixture_document,
        "submission-proof.json": proof_document,
        "normalized-submit-event.json": normalized_document,
        "durable-submit-event.json": durable_document,
        "browser-launch-receipt.json": browser_launch,
        "browser-runtime-identities.json": identity_receipt,
        "chromium-request-audit.json": chromium_request_audit_document,
    }
    for name, document in artifacts.items():
        _write_exclusive(output_root / name, _canonical_json(document))
    worker_database_finalization = _finalize_worker_database(
        output_root / "workflow.sqlite3"
    )
    _freeze_worker_files(output_root)
    result_path = output_root / "worker-result.json"
    inventory, inventory_sha256 = _document_inventory(
        output_root,
        exclude=(result_path,),
        domain=WORKER_INVENTORY_DOMAIN,
    )
    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "request_sha256": _domain_hash(REQUEST_DOMAIN, request_bytes),
        "integration_nonce_sha256": request["integration_nonce_sha256"],
        "source": source.document(),
        "cooperative_policy_sha256": request["cooperative_policy_sha256"],
        "environment": request["environment"],
        "environment_sha256": request["environment_sha256"],
        "runtime_tmp_root": request["runtime_tmp_root"],
        "runtime_tmp_root_derivation": request["runtime_tmp_root_derivation"],
        "socket_budget": request["socket_budget"],
        "worker_database_finalization": worker_database_finalization,
        "shared_memory": _shared_memory_evidence(),
        "chromium_effective_argv": argv,
        "chromium_effective_argv_sha256": _domain_hash(
            EFFECTIVE_ARGV_DOMAIN,
            _canonical_json({"argv": argv}),
        ),
        "runtime_identities": identity_receipt,
        "fixture_receipt": fixture_document,
        "submission_proof": proof_document,
        "observation": observation.document(),
        "artifact_inventory": inventory,
        "worker_artifact_inventory_sha256": inventory_sha256,
        "evidence_kind": "synthetic_shadow",
        "execution_claim": "structural_lineage_only",
        "external_actions": 0,
        "real_applications_submitted": 0,
    }
    _write_exclusive(result_path, _canonical_json(result))
    return result


def validate_worker_result(
    result: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    request_bytes: bytes,
    output_root: Path,
) -> None:
    expected_keys = {
        "schema_version",
        "request_sha256",
        "integration_nonce_sha256",
        "source",
        "cooperative_policy_sha256",
        "environment",
        "environment_sha256",
        "runtime_tmp_root",
        "runtime_tmp_root_derivation",
        "socket_budget",
        "worker_database_finalization",
        "shared_memory",
        "chromium_effective_argv",
        "chromium_effective_argv_sha256",
        "runtime_identities",
        "fixture_receipt",
        "submission_proof",
        "observation",
        "artifact_inventory",
        "worker_artifact_inventory_sha256",
        "evidence_kind",
        "execution_claim",
        "external_actions",
        "real_applications_submitted",
    }
    if set(result) != expected_keys:
        raise NetworkWitnessedFixtureError("worker result field set differs")
    if (
        result.get("schema_version") != RESULT_SCHEMA_VERSION
        or result.get("request_sha256") != _domain_hash(REQUEST_DOMAIN, request_bytes)
        or result.get("integration_nonce_sha256")
        != request.get("integration_nonce_sha256")
        or result.get("source") != request.get("source")
        or result.get("cooperative_policy_sha256")
        != request.get("cooperative_policy_sha256")
        or result.get("environment") != request.get("environment")
        or result.get("environment_sha256") != request.get("environment_sha256")
        or result.get("runtime_tmp_root") != request.get("runtime_tmp_root")
        or result.get("runtime_tmp_root_derivation")
        != request.get("runtime_tmp_root_derivation")
        or result.get("socket_budget") != request.get("socket_budget")
        or not isinstance(
            result.get("worker_database_finalization"),
            dict,
        )
        or result.get("evidence_kind") != "synthetic_shadow"
        or result.get("execution_claim") != "structural_lineage_only"
        or result.get("external_actions") != 0
        or result.get("real_applications_submitted") != 0
    ):
        raise NetworkWitnessedFixtureError("worker result authority differs")
    finalization = result["worker_database_finalization"]
    if (
        set(finalization)
        != {
            "journal_mode",
            "checkpoint_mode",
            "busy",
            "log_frames",
            "checkpointed_frames",
        }
        or finalization.get("journal_mode") != "wal"
        or finalization.get("checkpoint_mode") != "truncate"
        or finalization.get("busy") != 0
        or not isinstance(finalization.get("log_frames"), int)
        or finalization.get("log_frames") != finalization.get("checkpointed_frames")
    ):
        raise NetworkWitnessedFixtureError("worker database finalization differs")
    argv = result.get("chromium_effective_argv")
    if not isinstance(argv, list) or result.get(
        "chromium_effective_argv_sha256"
    ) != _domain_hash(EFFECTIVE_ARGV_DOMAIN, _canonical_json({"argv": argv})):
        raise NetworkWitnessedFixtureError("effective Chromium argv differs")
    if any(flag not in argv for flag in REQUIRED_CHROMIUM_FLAGS) or any(
        str(value).startswith(prefix)
        for value in argv
        for prefix in FORBIDDEN_CHROMIUM_FLAG_PREFIXES
    ):
        raise NetworkWitnessedFixtureError("effective Chromium policy differs")
    fixture = result.get("fixture_receipt")
    proof = result.get("submission_proof")
    observation = result.get("observation")
    if not all(isinstance(value, dict) for value in (fixture, proof, observation)):
        raise NetworkWitnessedFixtureError("worker lineage documents are invalid")
    fixture_receipt = FixtureReceipt(
        receipt_id=str(fixture["receipt_id"]),
        application_id=str(fixture["application_id"]),
        job_key=str(fixture["job_key"]),
        payload_sha256=str(fixture["payload_sha256"]),
        schema_version=str(fixture["schema_version"]),
        certifies_slice=bool(fixture["certifies_slice"]),
    )
    fixture_receipt.verify()
    _validate_chromium_request_audit(
        output_root / "chromium-request-audit.json",
        application_id=fixture_receipt.application_id,
    )
    for key in (
        "release_manifest_sha256",
        "receipt_id",
        "receipt_payload_sha256",
        "screenshot_sha256",
        "field_map_sha256",
        "submit_event_sha256",
    ):
        if observation.get(key) != proof.get(key):
            raise NetworkWitnessedFixtureError("worker submission lineage differs")
    if (
        observation.get("fixture_receipt") != fixture
        or observation.get("evidence_kind") != "synthetic_shadow"
        or observation.get("execution_claim") != "structural_lineage_only"
    ):
        raise NetworkWitnessedFixtureError("worker observation differs")
    inventory, inventory_sha256 = _document_inventory(
        output_root,
        exclude=(output_root / "worker-result.json",),
        domain=WORKER_INVENTORY_DOMAIN,
    )
    if (
        result.get("artifact_inventory") != inventory
        or result.get("worker_artifact_inventory_sha256") != inventory_sha256
    ):
        raise NetworkWitnessedFixtureError("worker artifact inventory differs")


def _validate_chromium_request_audit(
    path: Path,
    *,
    application_id: str,
) -> dict[str, Any]:
    try:
        document, _payload = _read_canonical(path, maximum=256_000)
    except OSError as exc:
        raise NetworkWitnessedFixtureError(
            "Chromium request audit artifact is unavailable"
        ) from exc
    if set(document) != {
        "schema_version",
        "listener_mode",
        "records",
        "protocol_errors",
        "expected_requests",
        "inert_favicon_href",
        "exact_sequence_verified",
    }:
        raise NetworkWitnessedFixtureError("Chromium request audit field set differs")
    records = document.get("records")
    expected = document.get("expected_requests")
    if (
        document.get("schema_version") != "jaa10.chromium-request-lifecycle-audit.v1"
        or document.get("listener_mode") != "cdp_read_only"
        or document.get("protocol_errors") != []
        or document.get("inert_favicon_href") != FIXTURE_INERT_FAVICON_HREF
        or document.get("exact_sequence_verified") is not True
        or not isinstance(records, list)
        or not isinstance(expected, list)
        or len(records) != 3
        or len(expected) != 3
    ):
        raise NetworkWitnessedFixtureError("Chromium request audit authority differs")
    expected_methods = ("GET", "POST", "POST")
    expected_suffixes = ("", "/review", "/submit")
    origin: tuple[str, str, int] | None = None
    request_ids: set[str] = set()
    for index, (record, expectation) in enumerate(zip(records, expected)):
        if not isinstance(record, dict) or not isinstance(expectation, dict):
            raise NetworkWitnessedFixtureError(
                "Chromium request audit record is invalid"
            )
        if set(record) != {
            "initiator_type",
            "method",
            "request_id",
            "resource_type",
            "terminal",
            "url",
        } or set(expectation) != {"method", "url", "resource_type"}:
            raise NetworkWitnessedFixtureError(
                "Chromium request audit record fields differ"
            )
        method = expected_methods[index]
        url = record.get("url")
        request_id = record.get("request_id")
        if (
            record.get("method") != method
            or record.get("resource_type") != "Document"
            or record.get("terminal") != "finished"
            or not isinstance(record.get("initiator_type"), str)
            or not record["initiator_type"]
            or not isinstance(request_id, str)
            or not request_id
            or request_id in request_ids
            or not isinstance(url, str)
            or expectation
            != {"method": method, "url": url, "resource_type": "Document"}
        ):
            raise NetworkWitnessedFixtureError("Chromium request audit record differs")
        request_ids.add(request_id)
        parsed = urlsplit(url)
        try:
            host = ipaddress.ip_address(parsed.hostname or "")
            port = parsed.port or 80
        except ValueError as exc:
            raise NetworkWitnessedFixtureError(
                "Chromium request audit host is invalid"
            ) from exc
        current_origin = (parsed.scheme, str(host), port)
        if (
            parsed.scheme != "http"
            or not host.is_loopback
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path
            != f"/applications/{application_id}{expected_suffixes[index]}"
            or (origin is not None and current_origin != origin)
        ):
            raise NetworkWitnessedFixtureError("Chromium request audit route differs")
        origin = current_origin
    return document


@dataclass(frozen=True, slots=True)
class NetworkWitnessedFixtureObservationReceipt:
    """Canonical, non-certifying receipt for one bounded local fixture run."""

    canonical_document: bytes

    def __post_init__(self) -> None:
        document = self.document()
        expected_keys = {
            "schema_version",
            "integration_status",
            "source",
            "request_sha256",
            "integration_nonce_sha256",
            "cooperative_policy_sha256",
            "runtime_tmp_root",
            "runtime_tmp_root_derivation",
            "socket_budget",
            "worker_result_sha256",
            "worker_artifact_inventory_sha256",
            "network_witness_sha256",
            "network_receipt_sha256",
            "observation_sha256",
            "component_inventory",
            "component_inventory_sha256",
            "strongest_claim",
            "limitations",
            "evidence_kind",
            "execution_claim",
            "objective_satisfied",
            "certifies_slice",
            "external_actions",
            "real_applications_submitted",
            "receipt_sha256",
        }
        if set(document) != expected_keys:
            raise NetworkWitnessedFixtureError("composite receipt field set differs")
        if (
            document.get("schema_version") != COMPOSITE_SCHEMA_VERSION
            or document.get("integration_status")
            != "network_witnessed_local_fixture_single_execution"
            or not isinstance(document.get("runtime_tmp_root"), str)
            or not isinstance(
                document.get("runtime_tmp_root_derivation"),
                dict,
            )
            or not isinstance(document.get("socket_budget"), dict)
            or document.get("strongest_claim") != STRONGEST_CLAIM
            or tuple(document.get("limitations", ())) != LIMITATIONS
            or document.get("evidence_kind") != "synthetic_shadow"
            or document.get("execution_claim") != "structural_lineage_only"
            or document.get("objective_satisfied") is not False
            or document.get("certifies_slice") is not False
            or document.get("external_actions") != 0
            or document.get("real_applications_submitted") != 0
        ):
            raise NetworkWitnessedFixtureError("composite receipt truth differs")
        core = dict(document)
        supplied = str(core.pop("receipt_sha256"))
        if supplied != _domain_hash(COMPOSITE_DOMAIN, _canonical_json(core)):
            raise NetworkWitnessedFixtureError("composite receipt hash differs")
        if _canonical_json(document) != self.canonical_document:
            raise NetworkWitnessedFixtureError("composite receipt is not canonical")

    def document(self) -> dict[str, Any]:
        try:
            value = json.loads(self.canonical_document)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise NetworkWitnessedFixtureError(
                "composite receipt JSON is invalid"
            ) from error
        if not isinstance(value, dict):
            raise NetworkWitnessedFixtureError("composite receipt must be an object")
        return dict(value)

    @property
    def receipt_sha256(self) -> str:
        return str(self.document()["receipt_sha256"])

    @classmethod
    def issue(
        cls, core: Mapping[str, Any]
    ) -> "NetworkWitnessedFixtureObservationReceipt":
        document = dict(core)
        document["receipt_sha256"] = _domain_hash(
            COMPOSITE_DOMAIN,
            _canonical_json(document),
        )
        return cls(_canonical_json(document))


def run_network_witnessed_fixture(
    *,
    repository_root: str | Path,
    execution_root: str | Path,
    python_executable: str | Path,
    chromium_executable: str | Path,
    timeout_seconds: float = 180.0,
) -> tuple[
    NetworkWitnessedFixtureObservationReceipt,
    LinuxNetworkNamespaceWitness,
    NetworkNamespaceWitnessReceipt,
]:
    """Run one new synthetic fixture root and return its composite lineage."""

    root = Path(execution_root)
    if not root.is_absolute() or root.exists() or root.is_symlink():
        raise NetworkWitnessedFixtureError("execution root must be a new absolute path")
    repository = Path(repository_root).resolve(strict=True)
    python = Path(python_executable).absolute()
    if not python.is_file():
        raise NetworkWitnessedFixtureError("Python executable is missing")
    chromium = Path(chromium_executable).resolve(strict=True)
    source = _source_identity(repository)
    try:
        runtime_tmp_root, runtime_tmp_derivation, socket_budget = (
            derive_runtime_tmp_binding(source, root)
        )
    except NetworkWitnessError as error:
        raise NetworkWitnessedFixtureError("runtime-temp derivation differs") from error
    anchor = runtime_tmp_root.parent
    try:
        anchor_before = anchor.lstat()
    except OSError as error:
        raise NetworkWitnessedFixtureError("runtime-temp anchor is missing") from error
    if (
        stat.S_ISLNK(anchor_before.st_mode)
        or not stat.S_ISDIR(anchor_before.st_mode)
        or anchor.resolve(strict=True) != anchor
        or runtime_tmp_root.parent != anchor
        or runtime_tmp_root.exists()
        or runtime_tmp_root.is_symlink()
    ):
        raise NetworkWitnessedFixtureError("runtime-temp preflight differs")
    root.mkdir(mode=0o700)
    root_status = root.lstat()
    if (
        root.resolve(strict=True) != root
        or stat.S_ISLNK(root_status.st_mode)
        or not stat.S_ISDIR(root_status.st_mode)
        or stat.S_IMODE(root_status.st_mode) != 0o700
    ):
        raise NetworkWitnessedFixtureError("execution root identity differs")
    worker_output = root / "worker-output"
    worker_output.mkdir(mode=0o700)
    try:
        runtime_tmp_root.mkdir(mode=0o700)
    except OSError as error:
        raise NetworkWitnessedFixtureError(
            "runtime-temp root must be newly creatable"
        ) from error
    runtime_status = runtime_tmp_root.lstat()
    anchor_after = anchor.lstat()
    anchor_before_identity = (
        anchor_before.st_dev,
        anchor_before.st_ino,
        anchor_before.st_mode,
    )
    anchor_after_identity = (
        anchor_after.st_dev,
        anchor_after.st_ino,
        anchor_after.st_mode,
    )
    if (
        anchor_before_identity != anchor_after_identity
        or stat.S_ISLNK(runtime_status.st_mode)
        or not stat.S_ISDIR(runtime_status.st_mode)
        or stat.S_IMODE(runtime_status.st_mode) != 0o700
        or runtime_tmp_root.parent != anchor
        or (root / "integration-tmp").exists()
        or (root / "integration-tmp").is_symlink()
    ):
        raise NetworkWitnessedFixtureError("runtime-temp root identity differs")
    request_document = _request_document(
        source=source,
        execution_root=root,
        python_executable=python,
        chromium_executable=chromium,
        integration_nonce=os.urandom(32),
    )
    request_bytes = _canonical_json(request_document)
    request_path = root / "integration-request.json"
    _write_exclusive(request_path, request_bytes)
    request_sha256 = _domain_hash(REQUEST_DOMAIN, request_bytes)
    result_path = worker_output / "worker-result.json"
    expectation = CooperativeBrowserExpectation(
        execution_root=root,
        request_path=request_path,
        request_sha256=request_sha256,
        result_path=result_path,
        integration_nonce_sha256=str(request_document["integration_nonce_sha256"]),
        cooperative_policy_sha256=str(request_document["cooperative_policy_sha256"]),
        expected_source=source,
        runtime_tmp_root=runtime_tmp_root,
        runtime_tmp_root_derivation=runtime_tmp_derivation,
        socket_budget=socket_budget,
    )
    witness, network_receipt = run_isolated_network_witness(
        (
            str(python),
            "-m",
            "career_automation.network_witnessed_fixture",
            "--worker",
            str(request_path),
            str(worker_output),
        ),
        repository_root=repository,
        evidence_directory=root / "network-evidence",
        timeout_seconds=timeout_seconds,
        cooperative_browser_expectation=expectation,
    )
    result, result_bytes = _read_canonical(
        result_path,
        maximum=MAX_WORKER_RESULT_BYTES,
    )
    validate_worker_result(
        result,
        request=request_document,
        request_bytes=request_bytes,
        output_root=worker_output,
    )
    worker_result_sha256 = hashlib.sha256(result_bytes).hexdigest()
    if (
        network_receipt.worker_result_sha256 != worker_result_sha256
        or network_receipt.request_sha256 != request_sha256
        or network_receipt.integration_nonce_sha256
        != request_document["integration_nonce_sha256"]
    ):
        raise NetworkWitnessedFixtureError("network receipt binding differs")
    reconstruction = {
        "schema_version": "jaa10.network-witnessed-reconstruction.v2",
        "request_reconstructed": True,
        "worker_result_reconstructed": True,
        "worker_inventory_reconstructed": True,
        "network_witness_reconstructed": True,
        "network_receipt_reconstructed": True,
        "source": source.document(),
        "runtime_tmp_root": str(runtime_tmp_root),
        "runtime_tmp_root_derivation": runtime_tmp_derivation,
        "socket_budget": socket_budget,
        "request_sha256": request_sha256,
        "worker_result_sha256": worker_result_sha256,
        "network_witness_sha256": witness.witness_sha256,
        "network_receipt_sha256": network_receipt.receipt_sha256,
    }
    reconstruction["reconstruction_sha256"] = _domain_hash(
        RECONSTRUCTION_DOMAIN,
        _canonical_json(reconstruction),
    )
    reconstruction_path = root / "reconstruction.json"
    _write_exclusive(reconstruction_path, _canonical_json(reconstruction))
    for path in root.rglob("*"):
        if path.is_symlink():
            raise NetworkWitnessedFixtureError("accepted root contains a symlink")
        if path.is_file():
            os.chmod(path, 0o444)
        elif path.is_dir():
            os.chmod(path, 0o700)
    composite_path = root / "composite-receipt.json"
    inventory, inventory_sha256 = _document_inventory(
        root,
        exclude=(composite_path,),
        domain=COMPOSITE_INVENTORY_DOMAIN,
    )
    observation = result["observation"]
    if not isinstance(observation, dict):
        raise NetworkWitnessedFixtureError("worker observation is invalid")
    receipt = NetworkWitnessedFixtureObservationReceipt.issue(
        {
            "schema_version": COMPOSITE_SCHEMA_VERSION,
            "integration_status": ("network_witnessed_local_fixture_single_execution"),
            "source": source.document(),
            "request_sha256": request_sha256,
            "integration_nonce_sha256": (request_document["integration_nonce_sha256"]),
            "cooperative_policy_sha256": (
                request_document["cooperative_policy_sha256"]
            ),
            "runtime_tmp_root": str(runtime_tmp_root),
            "runtime_tmp_root_derivation": runtime_tmp_derivation,
            "socket_budget": socket_budget,
            "worker_result_sha256": worker_result_sha256,
            "worker_artifact_inventory_sha256": (
                result["worker_artifact_inventory_sha256"]
            ),
            "network_witness_sha256": witness.witness_sha256,
            "network_receipt_sha256": network_receipt.receipt_sha256,
            "observation_sha256": hashlib.sha256(
                _canonical_json(observation)
            ).hexdigest(),
            "component_inventory": inventory,
            "component_inventory_sha256": inventory_sha256,
            "strongest_claim": STRONGEST_CLAIM,
            "limitations": list(LIMITATIONS),
            "evidence_kind": "synthetic_shadow",
            "execution_claim": "structural_lineage_only",
            "objective_satisfied": False,
            "certifies_slice": False,
            "external_actions": 0,
            "real_applications_submitted": 0,
        }
    )
    _write_exclusive(composite_path, receipt.canonical_document)
    return receipt, witness, network_receipt


def _worker_main(request_path: Path, output_root: Path) -> int:
    try:
        repository = Path(__file__).resolve().parents[1]
        _execute_worker(
            request_path.resolve(strict=True),
            output_root.resolve(strict=True),
            repository,
        )
    except Exception as error:  # fail closed across the command boundary
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        return 2
    return 0


def _main(arguments: Sequence[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("request", type=Path)
    parser.add_argument("output", type=Path)
    parsed = parser.parse_args(arguments)
    if not parsed.worker:
        parser.error("only the bounded --worker mode is supported")
    return _worker_main(parsed.request, parsed.output)


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
