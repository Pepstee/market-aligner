"""Command-line entry point for the canonical product."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from market_aligner import __version__
from market_aligner import processing as processing_module
from market_aligner.collectors.engine import Collector
from market_aligner.config import ProductPaths
from market_aligner.config_loader import closure_identity, snapshot_config
from market_aligner.applications.producer import write_handoff
from market_aligner.profiler.importers import (
    import_evidence_led,
    import_guided_profile,
    project_canonical_authority,
)
from market_aligner.profiler.schema import CandidateProfile, TrackProfile, new_profile_id
from market_aligner.profiler.store import ProfileStore
from market_aligner.research.store import AssessmentStore
from market_aligner.research.public_provider import (
    CanonicalCollectorVacancyLoader,
    RefreshDerivedResearchProvider,
)
from market_aligner.research.worker import ResearchWorker
from market_aligner.llm.codex_gateway import (
    SYNTHETIC_CANARY_MARKER,
    CodexSemanticGateway,
    synthetic_extraction_canary,
)
from market_aligner.llm.contracts import canonical_hash
from market_aligner.assessment.scoring import AssessmentAxes
from market_aligner.service.api import AssessmentRequest, CollectionService, MarketAlignerService
from market_aligner.service.processing import ProcessingService
from market_aligner.state.operations import (
    INGEST_CYCLE_KIND,
    OperationJournal,
    OperationRefused,
    SealConflict,
    canonical_json,
    content_sha256,
    make_record,
    new_owner_id,
    normalized_error,
    utc_now,
    validate_operation_id,
)


def _add_data_home(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--data-home",
        type=Path,
        default=None,
        help="External private-data root (defaults to MARKET_ALIGNER_DATA_HOME).",
    )


def _synthetic_profile(profile_id: str) -> CandidateProfile:
    return CandidateProfile(
        profile_id=profile_id,
        version="synthetic-v1",
        display_label="Synthetic new user",
        tracks={
            "example_track": TrackProfile(
                interest=0.0,
                demonstrated_skill=0.0,
                confidence=0.0,
                market_readiness=0.0,
                rationale="Synthetic onboarding fixture; no claims have been supplied.",
                gaps=("Complete evidence-led onboarding.",),
            )
        },
        unknowns=("All candidate facts are unknown until evidence-led onboarding.",),
    )


def _profile_command(args: argparse.Namespace) -> int:
    store = ProfileStore(args.data_home)
    if args.profile_action == "list":
        print(json.dumps({"profile_ids": store.list_profile_ids()}, sort_keys=True))
        return 0
    if args.profile_action == "create-synthetic":
        profile = _synthetic_profile(args.profile_id or new_profile_id())
        store.save(profile, [])
        print(json.dumps({"profile_id": profile.profile_id, "version": profile.version}, sort_keys=True))
        return 0
    if args.profile_action == "import":
        if args.format == "evidence-led":
            profile, evidence = import_evidence_led(args.source, args.profile_id)
        else:
            profile, evidence = import_guided_profile(
                args.source,
                args.profile_id,
                profile_key=args.profile_key,
            )
        store.save(profile, evidence)
        print(
            json.dumps(
                {
                    "profile_id": profile.profile_id,
                    "version": profile.version,
                    "evidence_items": len(evidence),
                },
                sort_keys=True,
            )
        )
        return 0
    if args.profile_action == "show":
        profile, evidence = store.load(args.profile_id)
        payload = asdict(profile)
        payload.pop("display_label", None)
        payload["evidence_items"] = len(evidence)
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return 0
    if args.profile_action == "project-canonical":
        profile, _, receipt = project_canonical_authority(
            authority_path=args.authority,
            evidence_packet_path=args.approved_evidence,
            legacy_profile_path=args.legacy_profile,
            legacy_evidence_path=args.legacy_evidence,
            evidence_mapping_path=args.evidence_mapping,
            data_home=args.data_home,
        )
        print(
            json.dumps(
                {
                    "profile_id": profile.profile_id,
                    "track_names": sorted(profile.tracks),
                    "receipt_sha256": receipt.receipt_sha256,
                    "profile_sha256": receipt.profile_sha256,
                    "evidence_ledger_sha256": receipt.evidence_ledger_sha256,
                    "mappings": len(receipt.mappings),
                    "omissions": len(receipt.omissions),
                    "conflicts": len(receipt.conflicts),
                    "release_authority": False,
                },
                sort_keys=True,
            )
        )
        return 0
    raise AssertionError(f"unhandled profile action: {args.profile_action}")


def _assess_command(args: argparse.Namespace) -> int:
    payload = json.loads(args.request.read_text(encoding="utf-8"))
    axes = AssessmentAxes(**payload.pop("axes"))
    request = AssessmentRequest(profile_id=args.profile_id, axes=axes, **payload)
    service = MarketAlignerService(args.data_home)
    result = service.assess(request)
    output = asdict(result)
    if args.apply_opportunity_gate:
        output["opportunity_gate"] = asdict(service.gate(args.profile_id, request.job_key))
    print(json.dumps(output, ensure_ascii=False, sort_keys=True, default=str))
    return 0


def _handoff_command(args: argparse.Namespace) -> int:
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    service = MarketAlignerService(args.data_home)
    handoff = service.handoff(args.profile_id, args.job_key, manifest)
    write_handoff(args.output, handoff)
    print(
        json.dumps(
            {
                "application_id": handoff.application_id,
                "job_key": args.job_key,
                "output": str(args.output),
                "payload_sha256": handoff.payload_sha256,
                "profile_id": args.profile_id,
                "root_sha256": handoff.root_sha256,
                "schema_version": "market-aligner.jaa-handoff.v1",
            },
            sort_keys=True,
        )
    )
    return 0


def _promote_assessment_command(args: argparse.Namespace) -> int:
    service = MarketAlignerService(args.data_home)
    promotion = service.promote_processing(
        profile_id=args.profile_id,
        track=args.track,
        job_key=args.job_key,
        processing_receipt_path=args.processing_receipt,
    )
    print(
        json.dumps(
            {
                "created": promotion.created,
                "job_key": promotion.job_key,
                "policy_sha256": promotion.policy_sha256,
                "profile_id": promotion.profile_id,
                "receipt_path": str(promotion.receipt_path),
                "receipt_sha256": promotion.receipt_sha256,
                "schema_version": "market-aligner.assessment-promotion.v1",
            },
            sort_keys=True,
        )
    )
    return 0


def _collect_command(args: argparse.Namespace) -> int:
    service = CollectionService(args.data_home)
    receipt = service.collect(
        args.config,
        once=bool(args.once),
        hours=float(args.hours or 0),
        poll_minutes=float(args.poll_minutes),
        operation_id=args.operation_id,
        log=lambda message: print(message, file=sys.stderr),
    )
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


def _refresh_vacancy_command(args: argparse.Namespace) -> int:
    receipt = CollectionService(args.data_home).refresh_vacancy(
        args.config,
        job_key=args.job_key,
        expected_content_sha256=args.expected_content_sha256,
        operation_id=args.operation_id,
        log=lambda message: print(message, file=sys.stderr),
    )
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


def _refresh_research_command(args: argparse.Namespace) -> int:
    profiles = ProfileStore(args.data_home)
    assessments = AssessmentStore(profiles.paths.state / "assessments.sqlite3")
    queued = assessments.refresh_completed_research_if_needed(
        args.profile_id,
        args.job_key,
        collection_refresh_receipt_path=args.collection_refresh_receipt,
        collection_config_path=args.collection_config,
    )
    print(
        json.dumps(
            {
                "application_authority": False,
                "authority_scope": "research_requeue_only",
                "job_key": args.job_key,
                "profile_id": args.profile_id,
                "queued": queued,
                "research_completed": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _refresh_research_provider(
    args: argparse.Namespace, *, selector_review_receipt: Path | None = None
) -> tuple[AssessmentStore, RefreshDerivedResearchProvider]:
    profiles = ProfileStore(args.data_home)
    assessments = AssessmentStore(profiles.paths.state / "assessments.sqlite3")
    loader = CanonicalCollectorVacancyLoader(
        data_home=assessments.data_home,
        collection_config_path=args.collection_config,
    )
    provider = RefreshDerivedResearchProvider(
        store=assessments,
        canonical_vacancy_loader=loader,
        repository_root=Path(__file__).resolve().parents[2],
        archive_root=(
            assessments.data_home / "state" / "public-employer-research-v2"
        ),
        selector_review_receipt_path=selector_review_receipt,
    )
    return assessments, provider


def _research_admit_selector_review_command(args: argparse.Namespace) -> int:
    assessments, provider = _refresh_research_provider(args)
    task = assessments.preview_refresh_research(args.profile_id, args.job_key)
    if task is None:
        print(json.dumps({
            "application_authority": False,
            "admitted": False,
            "job_key": args.job_key,
            "profile_id": args.profile_id,
            "release_authority": False,
            "schema_version": "market-aligner.selector-review-admission-run.v1",
            "status": "idle",
        }, sort_keys=True))
        return 1
    result = provider.admit_selector_review(task, args.selector_review_input)
    print(json.dumps({
        "application_authority": False,
        "admitted": True,
        "authority_mode": "selector_occurrence_only",
        "current_canonical_object_sha256": result.current_canonical_object_sha256,
        "job_key": args.job_key,
        "map_path": str(result.map_path),
        "map_sha256": result.map_sha256,
        "prior_dossier_sha256": result.prior_dossier_sha256,
        "profile_id": args.profile_id,
        "receipt_file_sha256": result.receipt_file_sha256,
        "receipt_path": str(result.receipt_path),
        "receipt_sha256": result.semantic_receipt_sha256,
        "release_authority": False,
        "schema_version": "market-aligner.selector-review-admission-run.v1",
        "status": "admitted",
    }, sort_keys=True))
    return 0


def _research_run_one_command(args: argparse.Namespace) -> int:
    assessments, provider = _refresh_research_provider(
        args, selector_review_receipt=args.selector_review_receipt
    )
    preview = assessments.preview_refresh_research(args.profile_id, args.job_key)
    if preview is None:
        run = None
    else:
        provider.preflight(preview)
        run = ResearchWorker(assessments, provider, args.worker_id).run_one(
            profile_id=args.profile_id,
            job_key=args.job_key,
            require_refresh_bridge=True,
        )
    derivation = provider.last_derivation
    output = {
        "application_authority": False,
        "completed": run is not None and run.status == "completed",
        "dossier_sha256": None if run is None else run.dossier_sha256,
        "error": None if run is None else run.error,
        "job_key": args.job_key,
        "profile_id": args.profile_id,
        "release_authority": False,
        "schema_version": "market-aligner.research-run-one.v1",
        "status": "idle" if run is None else run.status,
        "worker_id": args.worker_id,
    }
    if derivation is not None:
        output.update(
            {
                "current_canonical_object_sha256": (
                    derivation.current_canonical_object_sha256
                ),
                "derivation_receipt_file_sha256": (
                    derivation.receipt_file_sha256
                ),
                "derivation_receipt_path": str(derivation.receipt_path),
                "derivation_receipt_sha256": (
                    derivation.semantic_receipt_sha256
                ),
                "plan_path": str(derivation.plan_path),
                "plan_sha256": derivation.plan_sha256,
                "prior_dossier_sha256": derivation.prior_dossier_sha256,
            }
        )
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    return 0 if run is not None and run.status == "completed" else 1


def _codex_gateway(args: argparse.Namespace) -> CodexSemanticGateway:
    return CodexSemanticGateway(
        model=args.model,
        cli_timeout_seconds=args.semantic_timeout,
        codex_binary=str(args.codex_binary) if args.codex_binary else None,
    )


def _process_command(args: argparse.Namespace) -> int:
    worker = _codex_gateway(args)
    receipt = ProcessingService(args.data_home, worker).process(
        args.config,
        profile_id=args.profile_id,
        track=args.track,
        worker_id=args.worker_id,
    )
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


def _process_job_command(args: argparse.Namespace) -> int:
    receipt = ProcessingService(args.data_home, _codex_gateway(args)).process(
        args.config,
        profile_id=args.profile_id,
        track=args.track,
        worker_id=args.worker_id,
        job_key=args.job_key,
    )
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


def _applications_command(args: argparse.Namespace) -> int:
    result = MarketAlignerService.prepare_internal_jaa(
        eligibility_receipt=args.eligibility_receipt.read_bytes(),
        evidence_reference_sha256=args.evidence_reference_sha256,
        contact_reference_sha256=args.contact_reference_sha256,
        forensic_root=args.forensic_root,
        attempt_id=args.attempt_id,
        application_id=args.application_id,
        ats_name=args.ats_name,
    )
    print(json.dumps(result, sort_keys=True))
    return 0

def _write_exact_bytes(sink, payload: bytes) -> None:
    """Write one exact receipt to a binary or ordinary CLI stdout seam."""

    if hasattr(sink, "buffer"):
        sink.buffer.write(payload)
        sink.buffer.flush()
        return
    try:
        sink.write(payload)
    except TypeError:
        sink.write(payload.decode("utf-8"))
    if hasattr(sink, "flush"):
        sink.flush()

def _process_one_command(args: argparse.Namespace, *, out=None, err=None) -> int:
    """Run the provider-free FIT path with byte-identical success output."""

    sink_out = out if out is not None else sys.stdout
    sink_err = err if err is not None else sys.stderr
    try:
        receipt = MarketAlignerService.process_one(
            args.data_home,
            args.processing_envelope,
            supplied_operation_id=args.operation_id,
            supplied_config_path=str(args.config),
            supplied_profile_id=args.profile_id,
            supplied_job_key=args.job_key,
            supplied_track=args.track,
        )
    except processing_module.ProcessingRefused as exc:
        refusal = {
            "command": "process-one",
            "status": "refused",
            "reason": exc.reason,
            "detail": exc.detail,
        }
        if exc.reason != processing_module.REASON_OPERATION_ID:
            refusal["operation_id"] = args.operation_id
        line = processing_module.canonical_json(refusal) + "\n"
        try:
            sink_err.write(line)
        except TypeError:
            sink_err.write(line.encode("utf-8"))
        if hasattr(sink_err, "flush"):
            sink_err.flush()
        return 2
    _write_exact_bytes(sink_out, receipt)
    return 0

def _eligibility_one_command(args: argparse.Namespace, *, out=None, err=None) -> int:
    """Run the provider-free eligibility path with byte-identical output."""

    sink_out = out if out is not None else sys.stdout
    sink_err = err if err is not None else sys.stderr
    try:
        receipt = MarketAlignerService.eligibility_one(
            args.data_home,
            args.eligibility_envelope,
            supplied_operation_id=args.operation_id,
            supplied_fit_operation_id=args.fit_operation_id,
            supplied_config_path=str(args.config),
            supplied_profile_id=args.profile_id,
            supplied_job_key=args.job_key,
            supplied_track=args.track,
        )
    except processing_module.ProcessingRefused as exc:
        refusal = {
            "command": "eligibility-one",
            "status": "refused",
            "reason": exc.reason,
            "detail": exc.detail,
        }
        if exc.reason != processing_module.ELIGIBILITY_REASON_OPERATION_ID:
            refusal["operation_id"] = args.operation_id
        line = processing_module.canonical_json(refusal) + chr(10)
        try:
            sink_err.write(line)
        except TypeError:
            sink_err.write(line.encode("utf-8"))
        if hasattr(sink_err, "flush"):
            sink_err.flush()
        return 2
    _write_exact_bytes(sink_out, receipt)
    return 0

def _emit_refusal(exc: OperationRefused, err=None) -> int:
    payload = {"command": "ingest", "status": "refused", **exc.payload}
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True), file=err or sys.stderr)
    return 2

def _emit_ingest(payload: dict, code: int, out=None) -> int:
    payload.setdefault("command", "ingest")
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True), file=out or sys.stdout)
    return code

def _preflight_refusal(exc: ValueError) -> OperationRefused:
    """Map canonical seam errors onto stable structured refusal reasons."""
    text = str(exc)
    if text.startswith("escape:"):
        return OperationRefused("path_escape", text[len("escape:"):])
    if text.startswith("shape:"):
        return OperationRefused("invalid_config_shape", text[len("shape:"):])
    return OperationRefused("path_escape", text)

def _binding_refusals(existing: dict, *, kind, config_source, config_file_sha256,
                      config_sha256, scope, data_home) -> OperationRefused | None:
    """Same operation id with any changed binding must never reach a provider.

    Precedence is deliberate: the source scope is reported before config
    identity fields so a scope-substituted contender names the scope change
    even when its configuration file differs wholesale.
    """
    checks = (
        ("kind", existing["kind"], kind),
        ("source_scope", existing["source_scope"], scope),
        ("config_source", existing["config_source"], str(config_source)),
        ("config_file_sha256", existing["config_file_sha256"], config_file_sha256),
        ("config_sha256", existing["config_sha256"], config_sha256),
        ("data_home", existing["data_home"], data_home),
    )
    for field, recorded, current in checks:
        if recorded != current:
            return OperationRefused(
                f"binding_{field}",
                f"journal binds a different {field} for this operation id",
                operation_id=existing["operation_id"],
                disposition=existing["disposition"],
            )
    return None

def _replay_payload(existing: dict) -> dict:
    payload = {
        "status": "replayed",
        "replayed": True,
        "disposition": existing["disposition"],
        "operation_id": existing["operation_id"],
        "receipt_id": existing["receipt_id"],
        "result": existing["result"],
        "finished_at": existing["finished_at"],
    }
    if existing["disposition"] == "failed":
        payload.pop("result")
        payload["error"] = existing["error"]
    return payload

def _ingest_command(args: argparse.Namespace, *, out=None, err=None) -> int:
    # Thread-safe capture seam: callers (tests) may inject private streams so
    # concurrent contenders never touch the process-global sys.stdout/stderr.
    sink_out = out if out is not None else sys.stdout
    sink_err = err if err is not None else sys.stderr

    def _refuse(exc: OperationRefused) -> int:
        return _emit_refusal(exc, sink_err)

    def _emit(payload: dict, code: int) -> int:
        return _emit_ingest(payload, code, sink_out)

    try:
        operation_id = validate_operation_id(args.operation_id)
    except OperationRefused as exc:
        return _refuse(exc)

    config_source = args.config.expanduser().resolve()
    try:
        cfg, config_identities = snapshot_config(config_source)
    except Exception as exc:  # parse/IO/coherence failures refuse pre-provider
        return _refuse(
            OperationRefused("config_unreadable", f"configuration could not be loaded: {exc}")
        )
    config_file_sha256 = closure_identity(config_identities)
    config_sha256 = content_sha256(cfg)

    # Resolve without creating: an escaping or malformed configuration must
    # leave a fresh data home absent.
    paths = ProductPaths.resolve(args.data_home)
    try:
        plan = Collector.plan(paths.root, cfg)
    except ValueError as exc:
        return _refuse(_preflight_refusal(exc))
    scope = plan["boards"]
    if not scope:
        return _refuse(OperationRefused("empty_scope", "configuration enables no boards"))

    paths.ensure()
    try:
        journal = OperationJournal(paths.state / "operations")
    except OperationRefused as exc:
        return _refuse(exc)

    bindings = dict(
        kind=INGEST_CYCLE_KIND,
        config_source=config_source,
        config_file_sha256=config_file_sha256,
        config_sha256=config_sha256,
        scope=scope,
        data_home=str(paths.root),
    )

    # Fast journal gate before lock contention: every refusal here performs
    # zero provider calls.
    try:
        existing = journal.load(operation_id)
    except OperationRefused as exc:
        return _refuse(exc)

    if existing is not None:
        mismatch = _binding_refusals(existing, **bindings)
        if mismatch is not None:
            return _refuse(mismatch)
        disposition = existing["disposition"]
        if disposition == "completed":
            return _emit(_replay_payload(existing), 0)
        if disposition == "failed":
            return _emit(_replay_payload(existing), 2)
        if disposition == "indeterminate":
            return _refuse(
                OperationRefused(
                    "indeterminate_state",
                    "this operation was marked indeterminate and stays fail-closed; "
                    "an unresolved external call can never be repeated or resumed here",
                    operation_id=operation_id,
                    disposition=disposition,
                )
            )
        return _refuse(
            OperationRefused(
                "in_progress",
                "another run owns this operation's in-flight claim; refusing without "
                "touching its record or contacting any provider",
                operation_id=operation_id,
                disposition=disposition,
                extra={"owner_id": existing["owner_id"]},
            )
        )

    claim = make_record(
        operation_id=operation_id,
        kind=INGEST_CYCLE_KIND,
        config_source=str(config_source),
        config_file_sha256=config_file_sha256,
        config_sha256=config_sha256,
        source_scope=scope,
        data_home=str(paths.root),
        disposition="in_flight",
        owner_id=new_owner_id(),
    )
    claim_bytes = canonical_json(claim).encode("utf-8")

    # Per-board locks span reload, blocker scan, claim, provider cycle and
    # seal, acquired in canonical order so intersecting scopes serialize on
    # exactly their shared boards.
    try:
        locks = journal.acquire_board_locks(str(paths.root), scope)
    except OperationRefused as exc:
        return _refuse(exc)

    operation_lock_fd = None
    try:
        try:
            blockers = journal.scan_unresolved_scope_blockers(str(paths.root), scope)
        except OperationRefused as exc:
            return _refuse(exc)
        if blockers:
            return _refuse(
                OperationRefused(
                    "scope_blocked",
                    "an unresolved earlier call covers an intersecting board; it remains "
                    "fail-closed and blocks this scope until a separately typed "
                    "authority contract exists",
                    extra={"blocked_by": blockers},
                )
            )

        # The typed operation lock is verified and held before any claim or
        # provider access: substituted (06xx/symlink/hardlink) entries fail
        # closed here with zero provider calls and cannot strand in_flight.
        # It is also the final serializer for same-ID races with disjoint
        # scopes, whose board locks do not intersect.
        try:
            operation_lock_fd = journal.open_operation_lock(operation_id)
        except OperationRefused as exc:
            # No claim exists yet, so there is no in_flight disposition to
            # report: the refusal carries the operation identity only.
            enriched = OperationRefused(
                exc.reason,
                str(exc),
                operation_id=operation_id,
                disposition=None,
            )
            return _refuse(enriched)

        # Re-load strictly under both lock families. A twin that observed
        # absence earlier now sees the winner's record: precise changed-binding
        # refusals for differing configs/scopes, truthful terminal replay when
        # every binding matches — never a second provider fetch.
        try:
            current = journal.load(operation_id, operation_lock_fd=operation_lock_fd)
        except OperationRefused as exc:
            return _refuse(exc)
        if current is not None:
            mismatch = _binding_refusals(current, **bindings)
            if mismatch is not None:
                return _refuse(mismatch)
            disposition = current["disposition"]
            if disposition == "completed":
                return _emit(_replay_payload(current), 0)
            if disposition == "failed":
                return _emit(_replay_payload(current), 2)
            if disposition == "indeterminate":
                return _refuse(
                    OperationRefused(
                        "indeterminate_state",
                        "this operation was marked indeterminate and stays fail-closed",
                        operation_id=operation_id,
                        disposition=disposition,
                    )
                )
            return _refuse(
                OperationRefused(
                    "in_progress",
                    "the winning twin still holds its live in-flight claim",
                    operation_id=operation_id,
                    disposition=disposition,
                    extra={"owner_id": current["owner_id"]},
                )
            )

        try:
            claimed = journal.claim(claim)
        except OSError as exc:
            return _refuse(
                OperationRefused(
                    "claim_publication_failed",
                    f"claim could not be published; no final record exists and zero "
                    f"provider calls were made: {exc}",
                    operation_id=operation_id,
                    disposition="in_flight",
                )
            )
        if not claimed:
            return _refuse(
                OperationRefused(
                    "in_progress",
                    "another run won the exclusive claim between check and create; "
                    "refusing as a contender",
                    operation_id=operation_id,
                    disposition="in_flight",
                )
            )

        def _log(message: str) -> None:
            print(message, file=sink_err)

        try:
            collector = Collector(cfg, paths.root, log=_log)
            collector.migrate_existing()
            result = collector.cycle()
        except Exception as exc:
            failed = make_record(
                operation_id=operation_id,
                kind=INGEST_CYCLE_KIND,
                config_source=str(config_source),
                config_file_sha256=config_file_sha256,
                config_sha256=config_sha256,
                source_scope=scope,
                data_home=str(paths.root),
                disposition="failed",
                owner_id=claim["owner_id"],
                started_at=claim["started_at"],
                finished_at=utc_now(),
                error=normalized_error(exc),
            )
            try:
                journal.cas_replace(
                    failed,
                    expected_prior_bytes=claim_bytes,
                    operation_id=operation_id,
                    operation_lock_fd=operation_lock_fd,
                )
            except SealConflict as conflict:
                return _refuse(conflict)
            except OperationRefused as exc:
                return _refuse(exc)
            return _refuse(
                OperationRefused(
                    "provider_failure",
                    "collection cycle aborted; last good database and raw cache "
                    f"preserved: {normalized_error(exc)}",
                    operation_id=operation_id,
                    disposition="failed",
                )
            )

        completed = make_record(
            operation_id=operation_id,
            kind=INGEST_CYCLE_KIND,
            config_source=str(config_source),
            config_file_sha256=config_file_sha256,
            config_sha256=config_sha256,
            source_scope=scope,
            data_home=str(paths.root),
            disposition="completed",
            owner_id=claim["owner_id"],
            started_at=claim["started_at"],
            finished_at=utc_now(),
            result=dict(result),
        )
        try:
            journal.cas_replace(
                completed,
                expected_prior_bytes=claim_bytes,
                operation_id=operation_id,
                operation_lock_fd=operation_lock_fd,
            )
        except SealConflict as conflict:
            return _refuse(conflict)
        except OperationRefused as exc:
            return _refuse(exc)
    finally:
        # Exactly one release point: the caller-owned operation-lock descriptor
        # (cas_replace never unlocks or closes it) plus every board lock.
        if operation_lock_fd is not None:
            OperationJournal.release_locks([operation_lock_fd])
        OperationJournal.release_locks(locks)

    return _emit(
        {
            "status": "ok",
            "replayed": False,
            "disposition": completed["disposition"],
            "operation_id": operation_id,
            "receipt_id": completed["receipt_id"],
            "config_source": str(config_source),
            "config_file_sha256": config_file_sha256,
            "config_sha256": config_sha256,
            "source_scope": scope,
            "data_home": str(paths.root),
            "result": dict(result),
        },
        0,
    )


def _semantic_canary_command(args: argparse.Namespace) -> int:
    extraction, receipt = synthetic_extraction_canary(_codex_gateway(args))
    payload = {
        "extraction_sha256": canonical_hash(asdict(extraction)),
        "marker": SYNTHETIC_CANARY_MARKER,
        "receipt": asdict(receipt),
        "schema_version": "market-aligner.synthetic-semantic-canary.v1",
        "synthetic_non_candidate_canary": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({**payload, "output": str(args.output)}, ensure_ascii=False, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="market-aligner")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    profiles = commands.add_parser("profiles", help="Manage external private profiles.")
    profile_commands = profiles.add_subparsers(dest="profile_action", required=True)

    list_parser = profile_commands.add_parser("list")
    _add_data_home(list_parser)
    list_parser.set_defaults(handler=_profile_command)

    synthetic = profile_commands.add_parser("create-synthetic")
    synthetic.add_argument("--profile-id")
    _add_data_home(synthetic)
    synthetic.set_defaults(handler=_profile_command)

    importer = profile_commands.add_parser("import")
    importer.add_argument("--format", choices=("evidence-led", "guided"), required=True)
    importer.add_argument("--source", type=Path, required=True)
    importer.add_argument("--profile-id")
    importer.add_argument(
        "--profile-key",
        default="profile",
        help="Top-level mapping containing guided track scores.",
    )
    _add_data_home(importer)
    importer.set_defaults(handler=_profile_command)

    show = profile_commands.add_parser("show")
    show.add_argument("profile_id")
    _add_data_home(show)
    show.set_defaults(handler=_profile_command)

    projector = profile_commands.add_parser(
        "project-canonical",
        help="Create or exactly replay a hash-bound canonical profile projection.",
    )
    projector.add_argument("--authority", type=Path, required=True)
    projector.add_argument("--approved-evidence", type=Path, required=True)
    projector.add_argument("--legacy-profile", type=Path, required=True)
    projector.add_argument("--legacy-evidence", type=Path, required=True)
    projector.add_argument("--evidence-mapping", type=Path, required=True)
    _add_data_home(projector)
    projector.set_defaults(handler=_profile_command)

    assess = commands.add_parser("assess", help="Assess one vacancy for an opaque profile ID.")
    assess.add_argument("--profile-id", required=True)
    assess.add_argument("--request", type=Path, required=True)
    assess.add_argument("--apply-opportunity-gate", action="store_true")
    _add_data_home(assess)
    assess.set_defaults(handler=_assess_command)

    ingest = commands.add_parser(
        "ingest",
        help="Run one bounded official collection cycle from an exact external config.",
    )
    ingest.add_argument(
        "--operation-id",
        required=True,
        help=(
            "Stable opaque operation identity "
            "([A-Za-z0-9][A-Za-z0-9._-]{7,63}); each id runs at most one "
            "provider-reaching cycle and replays its terminal receipt."
        ),
    )
    ingest.add_argument("--config", type=Path, required=True)
    _add_data_home(ingest)
    ingest.set_defaults(handler=_ingest_command)

    handoff = commands.add_parser(
        "handoff", help="Emit one opportunity-gated assessment for internal JAA."
    )
    handoff.add_argument("--profile-id", required=True)
    handoff.add_argument("--job-key", required=True)
    handoff.add_argument("--manifest", type=Path, required=True)
    handoff.add_argument("--output", type=Path, required=True)
    _add_data_home(handoff)
    handoff.set_defaults(handler=_handoff_command)

    promote = commands.add_parser(
        "promote-assessment",
        help="Promote one current processing result into handoff-gated assessment state.",
    )
    promote.add_argument("--profile-id", required=True)
    promote.add_argument("--track", required=True)
    promote.add_argument("--job-key", required=True)
    promote.add_argument("--processing-receipt", type=Path, required=True)
    _add_data_home(promote)
    promote.set_defaults(handler=_promote_assessment_command)

    collect = commands.add_parser(
        "collect", help="Run the resumable raw-vacancy collector without application authority."
    )
    collect.add_argument("--config", type=Path, required=True)
    duration = collect.add_mutually_exclusive_group(required=True)
    duration.add_argument("--once", action="store_true")
    duration.add_argument("--hours", type=float)
    collect.add_argument("--poll-minutes", type=float, default=15.0)
    collect.add_argument(
        "--operation-id",
        required=True,
        help="Stable opaque ID reused only to recover/replay this exact collection.",
    )
    _add_data_home(collect)
    collect.set_defaults(handler=_collect_command)

    refresh = commands.add_parser(
        "refresh-vacancy",
        help="CAS-refresh one exact existing fetched vacancy without broad discovery.",
    )
    refresh.add_argument("--config", type=Path, required=True)
    refresh.add_argument("--job-key", required=True)
    refresh.add_argument("--expected-content-sha256", required=True)
    refresh.add_argument(
        "--operation-id",
        required=True,
        help="Stable opaque ID reused only to recover/replay this exact refresh.",
    )
    _add_data_home(refresh)
    refresh.set_defaults(handler=_refresh_vacancy_command)

    refresh_research = commands.add_parser(
        "refresh-research",
        help="Admit one exact unchanged collection receipt and requeue stale research.",
    )
    refresh_research.add_argument("--profile-id", required=True)
    refresh_research.add_argument("--job-key", required=True)
    refresh_research.add_argument(
        "--collection-refresh-receipt", type=Path, required=True
    )
    refresh_research.add_argument("--collection-config", type=Path, required=True)
    _add_data_home(refresh_research)
    refresh_research.set_defaults(handler=_refresh_research_command)

    selector_review = commands.add_parser(
        "research-admit-selector-review",
        help="Admit an exact selector-occurrence map for one refresh-linked task.",
    )
    selector_review.add_argument("--profile-id", required=True)
    selector_review.add_argument("--job-key", required=True)
    selector_review.add_argument(
        "--selector-review-input", type=Path, required=True
    )
    selector_review.add_argument("--collection-config", type=Path, required=True)
    _add_data_home(selector_review)
    selector_review.set_defaults(handler=_research_admit_selector_review_command)

    research_run_one = commands.add_parser(
        "research-run-one",
        help="Rebuild one exact refresh-linked dossier without new public claims.",
    )
    research_run_one.add_argument("--profile-id", required=True)
    research_run_one.add_argument("--job-key", required=True)
    research_run_one.add_argument("--worker-id", required=True)
    research_run_one.add_argument("--collection-config", type=Path, required=True)
    research_run_one.add_argument("--selector-review-receipt", type=Path)
    _add_data_home(research_run_one)
    research_run_one.set_defaults(handler=_research_run_one_command)

    process = commands.add_parser(
        "process",
        help="Process one resumable shard of fetched vacancies into current ranked reports.",
    )
    process.add_argument("--config", type=Path, required=True)
    process.add_argument("--profile-id", required=True)
    process.add_argument("--track", required=True)
    process.add_argument("--worker-id", required=True)
    process.add_argument("--model", required=True, help="Explicit Codex model identity.")
    process.add_argument("--semantic-timeout", type=float, default=120.0)
    process.add_argument("--codex-binary", type=Path)
    _add_data_home(process)
    process.set_defaults(handler=_process_command)

    process_job = commands.add_parser(
        "process-job",
        help="Process one exact fetched vacancy through the existing processing service.",
    )
    process_job.add_argument("--config", type=Path, required=True)
    process_job.add_argument("--profile-id", required=True)
    process_job.add_argument("--track", required=True)
    process_job.add_argument("--worker-id", required=True)
    process_job.add_argument("--job-key", required=True)
    process_job.add_argument("--model", required=True, help="Explicit Codex model identity.")
    process_job.add_argument("--semantic-timeout", type=float, default=120.0)
    process_job.add_argument("--codex-binary", type=Path)
    _add_data_home(process_job)
    process_job.set_defaults(handler=_process_job_command)

    process_one = commands.add_parser(
        "process-one",
        help=(
            "Admit one sealed evidence-bound FIT envelope and atomically "
            "materialize its deterministic assessment receipt."
        ),
    )
    process_one.add_argument("--operation-id", required=True)
    process_one.add_argument("--config", type=Path, required=True)
    process_one.add_argument("--profile-id", required=True)
    process_one.add_argument("--job-key", required=True)
    process_one.add_argument("--track", required=True)
    process_one.add_argument("--processing-envelope", required=True)
    process_one.add_argument("--data-home", type=Path, required=True)
    process_one.set_defaults(handler=_process_one_command)

    eligibility = commands.add_parser(
        "eligibility-one",
        help="Admit one sealed evidence-bound eligibility envelope atomically.",
    )
    eligibility.add_argument("--operation-id", required=True)
    eligibility.add_argument("--fit-operation-id", required=True)
    eligibility.add_argument("--config", type=Path, required=True)
    eligibility.add_argument("--profile-id", required=True)
    eligibility.add_argument("--job-key", required=True)
    eligibility.add_argument("--track", required=True)
    eligibility.add_argument("--eligibility-envelope", required=True)
    eligibility.add_argument("--data-home", type=Path, required=True)
    eligibility.set_defaults(handler=_eligibility_one_command)

    applications = commands.add_parser(
        "applications", help="Run the faceless internal JAA diagnostic corridor."
    )
    applications.add_argument("--eligibility-receipt", type=Path, required=True)
    applications.add_argument("--evidence-reference-sha256", required=True)
    applications.add_argument("--contact-reference-sha256", required=True)
    applications.add_argument("--forensic-root", type=Path, required=True)
    applications.add_argument("--attempt-id", required=True)
    applications.add_argument("--application-id", required=True)
    applications.add_argument("--ats-name", default="fixture")
    applications.set_defaults(handler=_applications_command)

    canary = commands.add_parser(
        "semantic-canary",
        help="Explicitly run one synthetic non-candidate Codex transport canary.",
    )
    canary.add_argument("--model", required=True, help="Explicit Codex model identity.")
    canary.add_argument("--semantic-timeout", type=float, default=120.0)
    canary.add_argument("--codex-binary", type=Path)
    canary.add_argument("--output", type=Path, required=True)
    canary.set_defaults(handler=_semantic_canary_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
