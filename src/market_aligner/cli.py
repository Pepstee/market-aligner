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
from market_aligner.config_loader import load_config
from market_aligner.profiler.importers import import_evidence_led, import_guided_profile
from market_aligner.profiler.schema import CandidateProfile, TrackProfile, new_profile_id
from market_aligner.profiler.store import ProfileStore
from market_aligner.assessment.scoring import AssessmentAxes
from market_aligner.service.api import AssessmentRequest, MarketAlignerService
from market_aligner.state.operations import (
    INGEST_CYCLE_KIND,
    OperationJournal,
    OperationRefused,
    content_sha256,
    derive_operation_id,
    make_record,
    utc_now,
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


def _emit_refusal(exc: OperationRefused) -> int:
    payload = {"command": "ingest", "status": "refused", **exc.payload}
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True), file=sys.stderr)
    return 2


def _ingest_command(args: argparse.Namespace) -> int:
    config_source = args.config.expanduser().resolve()
    try:
        cfg = load_config(config_source)
    except Exception as exc:  # any parse/IO failure refuses before provider access
        return _emit_refusal(
            OperationRefused("config_unreadable", f"configuration could not be loaded: {exc}")
        )
    config_sha256 = content_sha256(cfg)
    scope = sorted(
        str(board) for board in ((cfg.get("boards") or {}).get("enabled") or [])
    )
    if not scope:
        return _emit_refusal(OperationRefused("empty_scope", "configuration enables no boards"))
    operation_id = derive_operation_id(INGEST_CYCLE_KIND, config_sha256, scope)

    paths = ProductPaths.resolve(args.data_home).ensure()
    journal = OperationJournal(paths.state / "operations")

    # Journal gate: runs before Collector construction, so a refused operation
    # performs no provider access whatsoever.
    try:
        existing = journal.load(operation_id)
    except OperationRefused as exc:
        return _emit_refusal(exc)
    if existing is not None:
        if existing["kind"] != INGEST_CYCLE_KIND:
            return _emit_refusal(
                OperationRefused(
                    "operation_substitution",
                    "journal binds a different operation kind",
                    operation_id=operation_id,
                    disposition=existing["disposition"],
                )
            )
        if existing["config_sha256"] != config_sha256:
            return _emit_refusal(
                OperationRefused(
                    "config_substitution",
                    "journal binds a different configuration identity",
                    operation_id=operation_id,
                    disposition=existing["disposition"],
                )
            )
        if existing["source_scope"] != scope:
            return _emit_refusal(
                OperationRefused(
                    "scope_substitution",
                    "journal binds a different source scope",
                    operation_id=operation_id,
                    disposition=existing["disposition"],
                )
            )
        disposition = existing["disposition"]
        if disposition in ("completed", "failed"):
            return _emit_refusal(
                OperationRefused(
                    "replay_terminal",
                    f"operation already reached terminal disposition {disposition!r}; "
                    "a second identical run would perform a second provider fetch",
                    operation_id=operation_id,
                    disposition=disposition,
                )
            )
        if disposition == "indeterminate":
            return _emit_refusal(
                OperationRefused(
                    "indeterminate_state",
                    "an earlier run never reported a terminal disposition; whether providers "
                    "were contacted is unknowable, so the operation fails closed",
                    operation_id=operation_id,
                    disposition=disposition,
                )
            )
        # in_flight: a killed or concurrent run holds the claim.
        marked = make_record(
            operation_id=operation_id,
            kind=INGEST_CYCLE_KIND,
            config_sha256=config_sha256,
            config_source=str(config_source),
            data_home=str(paths.root),
            source_scope=scope,
            disposition="indeterminate",
            started_at=existing["started_at"],
            resolved_at=utc_now(),
            note="prior run reported no terminal disposition; whether providers were "
            "contacted is unknowable, so the operation is marked indeterminate",
        )
        journal.update(marked)
        return _emit_refusal(
            OperationRefused(
                "indeterminate_state",
                "found an in-flight claim from an earlier run; marked indeterminate and "
                "refusing to repeat an unknowable provider interaction",
                operation_id=operation_id,
                disposition="indeterminate",
            )
        )

    claim = make_record(
        operation_id=operation_id,
        kind=INGEST_CYCLE_KIND,
        config_sha256=config_sha256,
        config_source=str(config_source),
        data_home=str(paths.root),
        source_scope=scope,
        disposition="in_flight",
    )
    if not journal.claim(claim):
        return _emit_refusal(
            OperationRefused(
                "concurrent_run",
                "another run holds the in-flight claim for this operation",
                operation_id=operation_id,
                disposition="in_flight",
            )
        )

    def _log(message: str) -> None:
        print(message, file=sys.stderr)

    try:
        collector = Collector(cfg, paths.root, log=_log)
        collector.migrate_existing()
        result = collector.cycle()
    except Exception as exc:
        failed = make_record(
            operation_id=operation_id,
            kind=INGEST_CYCLE_KIND,
            config_sha256=config_sha256,
            config_source=str(config_source),
            data_home=str(paths.root),
            source_scope=scope,
            disposition="failed",
            started_at=claim["started_at"],
            finished_at=utc_now(),
            error=f"{type(exc).__name__}: {exc}",
        )
        journal.update(failed)
        return _emit_refusal(
            OperationRefused(
                "provider_failure",
                f"collection cycle aborted; last good database and raw cache preserved: {exc}",
                operation_id=operation_id,
                disposition="failed",
            )
        )

    completed = make_record(
        operation_id=operation_id,
        kind=INGEST_CYCLE_KIND,
        config_sha256=config_sha256,
        config_source=str(config_source),
        data_home=str(paths.root),
        source_scope=scope,
        disposition="completed",
        started_at=claim["started_at"],
        finished_at=utc_now(),
        result=dict(result),
    )
    journal.update(completed)
    output = {
        "command": "ingest",
        "status": "ok",
        "disposition": completed["disposition"],
        "operation_id": operation_id,
        "receipt_id": completed["receipt_id"],
        "config_source": str(config_source),
        "config_sha256": config_sha256,
        "source_scope": scope,
        "data_home": str(paths.root),
        "result": dict(result),
    }
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
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
