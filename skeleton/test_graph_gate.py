"""
Prove the teeth bite. Run: python3 skeleton/test_graph_gate.py
Uses LedgerBackend so no external model calls are needed to test enforcement.
"""
import sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from graph_gate import GraphGate, LedgerBackend, MilestoneError, MILESTONES


def raises(fn, label):
    try:
        fn()
    except MilestoneError:
        print(f"  OK  {label} -> refused")
        return True
    print(f"  FAIL {label} -> was allowed (no teeth!)")
    return False


def main() -> int:
    ok = True
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        art = root / "scraper" / "crawl.py"
        art.parent.mkdir(parents=True)
        art.write_text("# module code\n")
        rel = "scraper/crawl.py"

        gate = GraphGate(root=root, backend=LedgerBackend(), strict=False)

        # T2: unknown milestone refused (must read first to reach the check)
        gate.read("scraper")
        ok &= raises(lambda: gate.checkpoint("scraper", "not_a_real_milestone", [rel]), "T2 unknown milestone")

        # T1: writing before reading refused
        gate2 = GraphGate(root=root, backend=LedgerBackend(), strict=False)
        ok &= raises(lambda: gate2.checkpoint("profiler", "instrument_ready", [rel]), "T1 write-before-read")

        # T3: incomplete module cannot be 'done'
        gate.checkpoint("scraper", "adapters_ready", [rel])
        ok &= raises(lambda: gate.assert_complete("scraper"), "T3 incomplete module")

        # Complete it -> now allowed
        gate.checkpoint("scraper", "discover", [rel])
        gate.checkpoint("scraper", "fetch", [rel])
        try:
            gate.assert_complete("scraper")
            gate.verify("scraper")
            print("  OK  complete + verified module accepted")
        except MilestoneError as e:
            print(f"  FAIL complete module rejected: {e}"); ok = False

        # T4: tamper the artifact after checkpoint -> verify() must catch it
        art.write_text("# tampered after checkpoint\n")
        ok &= raises(lambda: gate.verify("scraper"), "T4 tamper detection")

    print("\nALL TEETH BIT" if ok else "\nSOME TEETH MISSING")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
