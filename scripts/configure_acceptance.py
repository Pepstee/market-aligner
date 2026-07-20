#!/usr/bin/env python3
"""Atomically configure private runtime paths used by commercial acceptance."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from acceptance_runtime import (
    RuntimeConfigurationError,
    SCHEMA_VERSION,
    default_config_path,
    validate_config_path,
    validate_runtime_values,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--original-source-root", required=True)
    result.add_argument("--recertification-evidence-directory", required=True)
    result.add_argument("--config", type=Path, help="explicit private config path")
    return result


def write_config(path: Path, document: dict[str, object]) -> None:
    path = validate_config_path(path, may_be_absent=True)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    validate_config_path(path, may_be_absent=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".runtime-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    args = parser().parse_args()
    try:
        source, evidence = validate_runtime_values(
            args.original_source_root, args.recertification_evidence_directory
        )
        destination = args.config if args.config is not None else default_config_path()
        write_config(destination, {
            "schema_version": SCHEMA_VERSION,
            "original_source_root": str(source),
            "recertification_evidence_directory": str(evidence),
        })
    except (RuntimeConfigurationError, OSError) as exc:
        print(f"configure-acceptance: ERROR: {exc}", file=os.sys.stderr)
        return 2
    print("Commercial acceptance runtime configuration written securely.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
