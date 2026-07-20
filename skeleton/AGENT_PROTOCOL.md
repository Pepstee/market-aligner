# Agent protocol — MANDATORY for every module build

You are building ONE module in a shared tree. Obey all of this; the gate enforces it.

## graphify enforcement (has teeth — not optional)
Before any work, and at every milestone, use the gate:

```python
import sys; sys.path.insert(0, "skeleton")
from graph_gate import open_gate
gate = open_gate(".", strict=True)          # repo root; real graphify, fail-closed

gate.read("<module>")                        # 1. READ the graph BEFORE you build
# ...build a milestone's worth of code...
gate.checkpoint("<module>", "<milestone>",   # 2. WRITE at each milestone
                artifacts=["<files you made>"], summary="one line")
gate.assert_complete("<module>")             # 3. module is DONE only if this passes
gate.verify("<module>")                      # 4. integrity check
```

Rules with teeth:
- `checkpoint()` before `read()` → refused. Read first.
- Only the milestones declared for your module in `graph_gate.MILESTONES` are accepted.
- Your module is NOT done until `assert_complete()` + `verify()` pass. Don't report done otherwise.
- Run bash with `export PATH="$HOME/.local/bin:$PATH"` so `graphify` resolves (the gate also finds it in ~/.local/bin).

## Privacy (hard constraint)
- graphify writes locally only. NEVER run `graphify label` / clustering (those call a model). Use only `graphify update . --no-cluster` (the gate already does this).
- Never send `profiler/data/` or `scraper/data/` anywhere. Keep personal data local.

## Boundaries
- Talk to other modules ONLY through `skeleton/contracts.py`. Do not import another module's internals.
- Read config from `skeleton/config.yaml` (it's a STUB — don't hardcode; read values).
- Build against small fixtures so your module is testable ALONE, without the others.
- Keep deps light; prefer stdlib. Write a runnable self-test and show it passing.
- Put your code in your module's folder and its data in `<module>/data/`.
