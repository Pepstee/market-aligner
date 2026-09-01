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


def build_receipt(root: Path, receipt_path: Path = DEFAULT_RECEIPT) -> dict:
    """Bind the current tracked tree to already-generated Graphify outputs.

    Graph extraction remains a separate, explicit operation.  This function only
    records the exact source and output bytes that an operator has just rebuilt;
    it cannot make an absent or empty graph authoritative.
    """

    root = root.resolve()
    outputs: dict[str, str] = {}
    for relative in OUTPUTS:
        output = root / "graphify-out" / relative
        if not output.is_file():
            raise FreshnessError(f"missing Graphify output: graphify-out/{relative}")
        outputs[relative] = _sha256(output)

    graph_path = root / "graphify-out/graph.json"
    try:
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FreshnessError(f"invalid Graphify graph: {exc}") from exc
    graph_edges = graph.get("edges", graph.get("links"))
    if not graph.get("nodes") or not graph_edges:
        raise FreshnessError("Graphify graph is empty")

    previous_path = root / receipt_path
    previous: dict = {}
    if previous_path.is_file():
        try:
            previous = json.loads(previous_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            previous = {}

    communities = {
        node.get("community")
        for node in graph["nodes"]
        if node.get("community") is not None
    }
    commit_result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    source_base_commit = (
        commit_result.stdout.strip() if commit_result.returncode == 0 else "UNBORN"
    )
    return {
        "community_count": len(communities),
        "edge_count": len(graph_edges),
        "node_count": len(graph["nodes"]),
        "outputs": outputs,
        "release_authority": False,
        "schema": SCHEMA,
        "semantic_token_usage": previous.get(
            "semantic_token_usage",
            {
                "input": 0,
                "output": 0,
                "note": "Graphify token metering was unavailable for this local rebuild.",
            },
        ),
        "source_base_commit": source_base_commit,
        "sources": source_hashes(root),
    }


def write_receipt(root: Path, receipt_path: Path = DEFAULT_RECEIPT) -> dict:
    receipt = build_receipt(root, receipt_path)
    destination = root.resolve() / receipt_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt


def canonicalize_graph(root: Path) -> tuple[int, int]:
    """Apply Graphify's documented directed-graph collapse deterministically.

    Incremental Graphify extraction can preserve repeated node ids, repeated
    endpoint pairs, and dangling producer edges in the JSON interchange file.
    Graphify's own post-build representation is a ``DiGraph``; normalising to
    that representation prevents cumulative growth and makes the receipt counts
    describe the graph consumers actually traverse.
    """

    graph_path = root.resolve() / "graphify-out/graph.json"
    try:
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FreshnessError(f"invalid Graphify graph: {exc}") from exc

    nodes = graph.get("nodes")
    edge_key = "edges" if "edges" in graph else "links"
    edges = graph.get(edge_key)
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise FreshnessError("Graphify graph has no node/edge lists")

    node_order: list[str] = []
    nodes_by_id: dict[str, dict] = {}
    for node in nodes:
        node_id = node.get("id") if isinstance(node, dict) else None
        if not isinstance(node_id, str) or not node_id:
            continue
        if node_id not in nodes_by_id:
            node_order.append(node_id)
        nodes_by_id[node_id] = node

    edge_order: list[tuple[str, str]] = []
    edges_by_endpoints: dict[tuple[str, str], dict] = {}
    valid_ids = set(nodes_by_id)
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        source, target = edge.get("source"), edge.get("target")
        if source not in valid_ids or target not in valid_ids:
            continue
        endpoints = (source, target)
        if endpoints not in edges_by_endpoints:
            edge_order.append(endpoints)
        # NetworkX DiGraph semantics: the last edge for an endpoint pair wins.
        edges_by_endpoints[endpoints] = edge

    graph["nodes"] = [nodes_by_id[node_id] for node_id in node_order]
    graph[edge_key] = [edges_by_endpoints[endpoints] for endpoints in edge_order]
    graph_path.write_text(
        json.dumps(graph, separators=(",", ":"), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return len(graph["nodes"]), len(graph[edge_key])


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
    parser.add_argument(
        "--write",
        action="store_true",
        help="write a receipt for an already-regenerated non-empty Graphify graph",
    )
    parser.add_argument(
        "--canonicalize",
        action="store_true",
        help="collapse duplicate/dangling interchange records to Graphify DiGraph semantics",
    )
    args = parser.parse_args()
    if args.canonicalize:
        nodes, edges = canonicalize_graph(args.root)
        print(f"Graphify canonicalized: {nodes} nodes, {edges} edges")
    receipt = write_receipt(args.root) if args.write else verify(args.root)
    print(
        f"Graphify freshness {'WRITTEN' if args.write else 'PASS'}: "
        f"{receipt['node_count']} nodes, "
        f"{receipt['edge_count']} edges, {len(receipt['sources'])} tracked sources"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
