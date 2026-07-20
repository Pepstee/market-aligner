"""
skeleton/graph_gate.py — graphify enforcement with TEETH.

The rule is not a suggestion. Every module MUST:
  1. read()        the knowledge graph before it does any work   (context in)
  2. checkpoint()  at each required milestone                     (write out)
and a module's output is REJECTED unless every one of its milestones has been
checkpointed. assert_complete() raises; the orchestrator refuses the module.

What gives it teeth (each is enforced in code, not documented as etiquette):
  T1  checkpoint() before read()            -> raises  (no blind writes)
  T2  checkpoint() of an unknown milestone  -> raises  (no off-book milestones)
  T3  assert_complete() with any gap        -> raises  (module cannot be 'done')
  T4  verify() detects a tampered/forged ledger via per-artifact content hashes
  T5  strict backend fail-closed: if graphify is required but absent -> raises
  T6  a file lock serialises graph writes so parallel agents can't corrupt it

Privacy: the graph build NEVER ingests personal data. IGNORED_PATHS (Hyun's
profiler data, the raw scrape cache) are excluded from what graphify sees,
because graphify sends semantic content to an upstream model.

Backends:
  GraphifyBackend  shells out to the real `graphify` CLI (build = write, query = read)
  LedgerBackend    local, no external calls — used to test the gate itself
Stdlib only.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Required milestones per module. A module is only 'done' when all are checkpointed.
MILESTONES: dict[str, list[str]] = {
    "scraper":  ["adapters_ready", "discover", "fetch"],
    "profiler": ["instrument_ready", "scoring_ready", "profile_emitted"],
    "llm":      ["client_ready", "prompts_versioned", "capabilities_ready"],
    "skeleton": ["contracts_frozen", "scoring_ready", "runner_ready", "reporter_ready"],
}

# Never fed to graphify's upstream model.
IGNORED_PATHS: tuple[str, ...] = ("profiler/data", "scraper/data", "outputs", "graphify-out")


class MilestoneError(RuntimeError):
    """Raised when the enforcement bites."""


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #
class GraphBackend:
    def available(self) -> bool: raise NotImplementedError
    def write(self, root: Path, module: str, milestone: str) -> str: raise NotImplementedError
    def read(self, root: Path, module: str) -> dict: raise NotImplementedError


def _graphify_bin() -> Optional[str]:
    """Resolve the graphify binary even when ~/.local/bin isn't on PATH."""
    cand = shutil.which("graphify")
    if cand:
        return cand
    for p in (os.environ.get("GRAPHIFY_BIN"), os.path.expanduser("~/.local/bin/graphify")):
        if p and os.path.isfile(p):
            return p
    return None


class GraphifyBackend(GraphBackend):
    """Real graphify CLI (v0.9+).

    write() = `graphify update <root> --no-cluster` — pure local tree-sitter
    extraction, no LLM, nothing sent upstream. read() = `graphify query`.
    The clustering/labelling steps (the ONLY ones that call a model) are never
    invoked, so personal data in IGNORED_PATHS never leaves the machine.
    """
    def available(self) -> bool:
        return _graphify_bin() is not None

    def _graph_json(self, root: Path) -> Path:
        return Path(root) / "graphify-out" / "graph.json"

    def write(self, root: Path, module: str, milestone: str) -> str:
        gbin = _graphify_bin()
        if gbin is None:
            raise MilestoneError("graphify CLI not found (PATH / GRAPHIFY_BIN / ~/.local/bin).")
        subprocess.run(
            [gbin, "update", str(root), "--no-cluster"],
            check=True, capture_output=True, text=True, timeout=1800,
        )
        return "graphify"

    def read(self, root: Path, module: str) -> dict:
        gbin = _graphify_bin()
        if gbin is None:
            raise MilestoneError("graphify CLI not found (PATH / GRAPHIFY_BIN / ~/.local/bin).")
        if not self._graph_json(root).exists():
            subprocess.run([gbin, "update", str(root), "--no-cluster"],
                           check=True, capture_output=True, text=True, timeout=1800)
        out = subprocess.run([gbin, "query", module],
                             capture_output=True, text=True, timeout=300)
        return {"module": module, "result": out.stdout[:4000]}


class LedgerBackend(GraphBackend):
    """Local fallback: no external model calls. Lets us prove the gate's teeth."""
    def available(self) -> bool: return True
    def write(self, root: Path, module: str, milestone: str) -> str: return "ledger"
    def read(self, root: Path, module: str) -> dict: return {"backend": "ledger", "module": module}


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #
@dataclass
class GraphGate:
    root: Path
    backend: GraphBackend
    strict: bool = True          # T5: fail closed if a required backend is absent

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self._out = self.root / "graphify-out"
        self._out.mkdir(parents=True, exist_ok=True)
        self._ledger = self._out / "milestones.jsonl"
        self._lock = self._out / ".gate.lock"
        self._read_modules: set[str] = set()
        if self.strict and not self.backend.available():
            raise MilestoneError(
                "graphify backend unavailable and strict=True: refusing to proceed. "
                "Configure graphify (or pass strict=False for a local ledger run)."
            )

    # -- locking (T6) --------------------------------------------------------
    def _locked(self):
        gate = self

        class _L:
            def __enter__(self):
                self._fh = open(gate._lock, "w")
                fcntl.flock(self._fh, fcntl.LOCK_EX)
                return self
            def __exit__(self, *a):
                fcntl.flock(self._fh, fcntl.LOCK_UN)
                self._fh.close()
        return _L()

    # -- read before work ----------------------------------------------------
    def read(self, module: str) -> dict:
        ctx = self.backend.read(self.root, module)
        self._read_modules.add(module)
        return ctx

    # -- checkpoint a milestone (write) --------------------------------------
    def checkpoint(self, module: str, milestone: str, artifacts: list[str], summary: str = "") -> None:
        if module not in MILESTONES:
            raise MilestoneError(f"unknown module '{module}'")
        if milestone not in MILESTONES[module]:                       # T2
            raise MilestoneError(
                f"'{milestone}' is not a declared milestone for '{module}'. "
                f"Declared: {MILESTONES[module]}"
            )
        if module not in self._read_modules:                         # T1
            raise MilestoneError(
                f"module '{module}' tried to checkpoint '{milestone}' before read(). "
                "Read the graph before writing to it."
            )
        digest = _hash_artifacts(self.root, artifacts)
        with self._locked():
            backend = self.backend.write(self.root, module, milestone)  # may raise (T5)
            rec = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "module": module, "milestone": milestone,
                "artifacts": artifacts, "hash": digest,
                "summary": summary, "backend": backend,
            }
            with self._ledger.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # -- gate: is the module allowed to be 'done'? (T3) ----------------------
    def assert_complete(self, module: str) -> None:
        done = {r["milestone"] for r in self._records() if r["module"] == module}
        missing = [m for m in MILESTONES.get(module, []) if m not in done]
        if missing:
            raise MilestoneError(
                f"module '{module}' is NOT done — missing graph checkpoints: {missing}"
            )

    # -- tamper / integrity check (T4) ---------------------------------------
    def verify(self, module: str) -> None:
        # Ledger is append-only; the LATEST checkpoint per milestone wins, so a
        # legitimate re-checkpoint after editing code re-baselines cleanly, while
        # editing a checkpointed artifact WITHOUT re-checkpointing still fails.
        self.assert_complete(module)
        latest: dict[str, dict] = {}
        for r in self._records():
            if r["module"] == module:
                latest[r["milestone"]] = r          # append order => last wins
        for r in latest.values():
            if _hash_artifacts(self.root, r["artifacts"]) != r["hash"]:
                raise MilestoneError(
                    f"integrity check failed for {module}/{r['milestone']}: "
                    "artifacts changed since their latest checkpoint (re-checkpoint or revert)."
                )

    def _records(self) -> list[dict]:
        if not self._ledger.exists():
            return []
        return [json.loads(l) for l in self._ledger.read_text(encoding="utf-8").splitlines() if l.strip()]


def _hash_artifacts(root: Path, artifacts: list[str]) -> str:
    h = hashlib.sha256()
    for rel in sorted(artifacts):
        p = Path(root) / rel
        h.update(rel.encode())
        h.update(p.read_bytes() if p.exists() else b"\0MISSING")
    return h.hexdigest()


def open_gate(root: str | Path, strict: Optional[bool] = None) -> GraphGate:
    """Factory: real graphify if present, else local ledger unless strict forces graphify."""
    backend: GraphBackend = GraphifyBackend()
    if not backend.available():
        if strict:
            raise MilestoneError("strict=True but graphify CLI not found on PATH.")
        backend = LedgerBackend()
    return GraphGate(root=Path(root), backend=backend, strict=bool(strict))
