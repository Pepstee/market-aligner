#!/usr/bin/env python3
"""Fail closed when the committed Graphify evidence is absent, stale, or corrupt."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


SCHEMA = "market-aligner.graphify-freshness.v1"
DEFAULT_RECEIPT = Path("graphify-out/freshness.json")
OUTPUTS = ("graph.json", "GRAPH_REPORT.md", ".graphify_labels.json")


class FreshnessError(RuntimeError):
    """The architecture graph cannot represent the current tracked source tree."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tracked_files(root: Path) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    paths = []
    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = raw_path.decode("utf-8")
        if relative == str(DEFAULT_RECEIPT) or relative.startswith("graphify-out/"):
            continue
        paths.append(relative)
    return tuple(sorted(paths))


def source_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for relative in _tracked_files(root):
        path = root / relative
        if not path.is_file():
            raise FreshnessError(f"tracked source is absent or not a file: {relative}")
        hashes[relative] = _sha256(path)
    return hashes


def verify(root: Path, receipt_path: Path = DEFAULT_RECEIPT) -> dict:
    root = root.resolve()
    path = root / receipt_path
    if not path.is_file():
        raise FreshnessError(f"missing Graphify freshness receipt: {receipt_path}")
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FreshnessError(f"invalid Graphify freshness receipt: {exc}") from exc
    if receipt.get("schema") != SCHEMA:
        raise FreshnessError("unsupported Graphify freshness receipt schema")

    expected_sources = receipt.get("sources")
    if not isinstance(expected_sources, dict) or not expected_sources:
        raise FreshnessError("freshness receipt has no bound source files")
    actual_sources = source_hashes(root)
    if set(actual_sources) != set(expected_sources):
        added = sorted(set(actual_sources) - set(expected_sources))
        removed = sorted(set(expected_sources) - set(actual_sources))
        raise FreshnessError(f"tracked source set changed; added={added}, removed={removed}")
    changed = [
        relative
        for relative, digest in actual_sources.items()
        if expected_sources.get(relative) != digest
    ]
    if changed:
        raise FreshnessError(f"tracked source content changed: {changed}")

    expected_outputs = receipt.get("outputs")
    if not isinstance(expected_outputs, dict) or set(expected_outputs) != set(OUTPUTS):
        raise FreshnessError("freshness receipt output set is incomplete")
    for relative in OUTPUTS:
        output = root / "graphify-out" / relative
        if not output.is_file():
            raise FreshnessError(f"missing Graphify output: graphify-out/{relative}")
        if _sha256(output) != expected_outputs[relative]:
            raise FreshnessError(f"Graphify output hash mismatch: graphify-out/{relative}")

    graph = json.loads((root / "graphify-out/graph.json").read_text(encoding="utf-8"))
    graph_edges = graph.get("edges", graph.get("links"))
    if not graph.get("nodes") or not graph_edges:
        raise FreshnessError("Graphify graph is empty")
    if receipt.get("node_count") != len(graph["nodes"]):
        raise FreshnessError("Graphify node count does not match receipt")
    if receipt.get("edge_count") != len(graph_edges):
        raise FreshnessError("Graphify edge count does not match receipt")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    receipt = verify(args.root)
    print(
        f"Graphify freshness PASS: {receipt['node_count']} nodes, "
        f"{receipt['edge_count']} edges, {len(receipt['sources'])} tracked sources"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
