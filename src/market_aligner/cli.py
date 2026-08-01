"""Command-line entry point for the canonical product."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from market_aligner import __version__
from market_aligner.profiler.importers import import_evidence_led, import_guided_profile
from market_aligner.profiler.schema import CandidateProfile, TrackProfile, new_profile_id
from market_aligner.profiler.store import ProfileStore


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
