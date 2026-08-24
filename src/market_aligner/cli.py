"""Command-line entry point for the canonical product."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from market_aligner import __version__
from market_aligner.collectors.engine import Collector
from market_aligner.config import ProductPaths
from market_aligner.config_loader import closure_identity, snapshot_config
from market_aligner.profiler.importers import import_evidence_led, import_guided_profile
from market_aligner.profiler.schema import CandidateProfile, TrackProfile, new_profile_id
from market_aligner.profiler.store import ProfileStore
from market_aligner.assessment.scoring import AssessmentAxes
from market_aligner.service.api import AssessmentRequest, MarketAlignerService
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
    """Same operation id with any changed binding must never reach a provider."""
    checks = (
        ("kind", existing["kind"], kind),
        ("config_source", existing["config_source"], str(config_source)),
        ("config_file_sha256", existing["config_file_sha256"], config_file_sha256),
        ("config_sha256", existing["config_sha256"], config_sha256),
        ("source_scope", existing["source_scope"], scope),
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
            enriched = OperationRefused(
                exc.reason,
                str(exc),
                operation_id=operation_id,
                disposition='in_flight',
            )
            return _refuse(enriched)

        # Re-load strictly under both lock families. A twin that observed
        # absence earlier now sees the winner's record: precise changed-binding
        # refusals for differing configs/scopes, truthful terminal replay when
        # every binding matches — never a second provider fetch.
        try:
            current = journal.load(operation_id)
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
    ingest.add_argument(
        "--config",
        type=Path,
        required=True,
        help="External collection configuration file (recursive extends supported).",
    )
    _add_data_home(ingest)
    ingest.set_defaults(handler=_ingest_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
