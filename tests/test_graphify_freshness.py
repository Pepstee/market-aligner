from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_graphify_freshness", ROOT / "scripts/verify_graphify_freshness.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "graphify-out").mkdir()
    (tmp_path / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    graph = {"nodes": [{"id": "value"}], "edges": [{"source": "value", "target": "value"}]}
    (tmp_path / "graphify-out/graph.json").write_text(json.dumps(graph), encoding="utf-8")
    (tmp_path / "graphify-out/GRAPH_REPORT.md").write_text("# Graph\n", encoding="utf-8")
    (tmp_path / "graphify-out/.graphify_labels.json").write_text("{}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "source.py"], check=True)
    receipt = {
        "schema": MODULE.SCHEMA,
        "sources": {"source.py": _sha256(tmp_path / "source.py")},
        "outputs": {
            relative: _sha256(tmp_path / "graphify-out" / relative)
            for relative in MODULE.OUTPUTS
        },
        "node_count": 1,
        "edge_count": 1,
    }
    (tmp_path / MODULE.DEFAULT_RECEIPT).write_text(json.dumps(receipt), encoding="utf-8")
    return tmp_path


def test_repository_graph_is_current() -> None:
    receipt = MODULE.verify(ROOT)
    assert receipt["node_count"] > 0
    assert receipt["edge_count"] > 0


def test_gate_rejects_changed_source(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    (root / "source.py").write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(MODULE.FreshnessError, match="content changed"):
        MODULE.verify(root)


def test_gate_rejects_new_tracked_source(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    (root / "new.py").write_text("VALUE = 3\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "new.py"], check=True)
    with pytest.raises(MODULE.FreshnessError, match="source set changed"):
        MODULE.verify(root)


def test_gate_rejects_tampered_graph(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    (root / "graphify-out/graph.json").write_text('{"nodes": [], "edges": []}', encoding="utf-8")
    with pytest.raises(MODULE.FreshnessError, match="output hash mismatch"):
        MODULE.verify(root)
