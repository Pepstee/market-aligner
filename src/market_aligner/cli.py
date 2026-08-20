"""Command-line entry point for the canonical product."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from market_aligner import __version__
from market_aligner.applications.producer import write_handoff
from market_aligner.profiler.importers import import_evidence_led, import_guided_profile
from market_aligner.profiler.schema import CandidateProfile, TrackProfile, new_profile_id
from market_aligner.profiler.store import ProfileStore
from market_aligner.assessment.scoring import AssessmentAxes
from market_aligner.service.api import AssessmentRequest, MarketAlignerService


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

    handoff = commands.add_parser(
        "handoff", help="Emit one opportunity-gated assessment for internal JAA."
    )
    handoff.add_argument("--profile-id", required=True)
    handoff.add_argument("--job-key", required=True)
    handoff.add_argument("--manifest", type=Path, required=True)
    handoff.add_argument("--output", type=Path, required=True)
    _add_data_home(handoff)
    handoff.set_defaults(handler=_handoff_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
