"""Command-line access to the canonical career lifecycle runtime."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Sequence

from .database import CareerDatabase
from .lifecycle import LifecycleReducer, ModelIdentity, PolicyIdentity
from .models import PipelineState


def _json_value(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"invalid JSON: {exc.msg}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jaa-lifecycle")
    parser.add_argument("--database", required=True, type=Path, help="career SQLite database")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("migrate", help="initialize or migrate the career database")

    transition = commands.add_parser("transition", help="commit one lifecycle transition")
    transition.add_argument("--job-key", required=True)
    transition.add_argument("--to-state", required=True, choices=[state.value for state in PipelineState])
    transition.add_argument("--policy-id", required=True)
    transition.add_argument("--policy-version", required=True)
    transition.add_argument("--policy-hash", required=True)
    transition.add_argument("--inputs", required=True, type=_json_value, metavar="JSON")
    transition.add_argument("--outputs", required=True, type=_json_value, metavar="JSON")
    transition.add_argument("--idempotency-key", required=True)
    transition.add_argument("--model-provider")
    transition.add_argument("--model-id")
    transition.add_argument("--model-version")

    commands.add_parser("replay", help="reconstruct and print lifecycle state")
    commands.add_parser("verify", help="verify migrations, receipts, events and materialised state")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "migrate":
        CareerDatabase(args.database)
        print(json.dumps({"database": str(args.database), "status": "ready"}, sort_keys=True))
        return 0

    reducer = LifecycleReducer(args.database)
    if args.command == "transition":
        model_values = (args.model_provider, args.model_id, args.model_version)
        if any(model_values) and not all(model_values):
            _parser().error("model provider, id and version must be supplied together")
        model = ModelIdentity(*model_values) if all(model_values) else None
        receipt = reducer.commit(
            job_key=args.job_key,
            to_state=PipelineState(args.to_state),
            policy=PolicyIdentity(args.policy_id, args.policy_version, args.policy_hash),
            inputs=args.inputs,
            outputs=args.outputs,
            idempotency_key=args.idempotency_key,
            model=model,
        )
        result = asdict(receipt)
        result["from_state"] = receipt.from_state.value
        result["to_state"] = receipt.to_state.value
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "replay":
        states = reducer.replay()
        print(json.dumps({key: value.value for key, value in sorted(states.items())}, sort_keys=True))
        return 0

    reducer.verify()
    print(json.dumps({"database": str(args.database), "status": "verified"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
