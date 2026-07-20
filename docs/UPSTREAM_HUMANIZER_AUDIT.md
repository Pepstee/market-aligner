# Upstream audit: blader/humanizer

## Decision

Adapt selected rules from `blader/humanizer` as a probabilistic style-critique
stage inside the application compiler. Do not install the plugin as an
unbounded final rewriter, and do not treat its output as deterministic
validation.

The audited upstream revision is:

```text
repository: https://github.com/blader/humanizer
commit: 1b48564898e999219882660237fde01bf4843a0f
commit date: 2026-06-29
audit date: 2026-07-19
implementation: portable Markdown prompt/skill; no runtime model or test suite
```

A graph-based audit was generated outside the live project at:

```text
/Users/admin/.graphify/repos/blader/humanizer/graphify-out/
```

No upstream prompt or plugin file has been copied into this repository.

## What it actually does

Humanizer is a writing policy encoded in `SKILL.md`, packaged for Claude Code
and other agent harnesses. It is not a deterministic detector, classifier,
language model, or post-processing library. It asks a model to:

- detect clusters of recurring AI-writing patterns;
- avoid treating a single polished feature as proof of AI authorship;
- preserve meaning and coverage while rewriting;
- calibrate personality to the author's voice and the document's register;
- run a draft, audit and final-rewrite loop;
- remove filler, excessive scaffolding, canned contrasts, generic emphasis and
  other formulaic patterns;
- apply some opinionated hard rules, including a blanket ban on em and en
  dashes.

Its useful centre is the relationship between meaning preservation, clustered
pattern detection, false-positive guards and voice calibration. Its weakest
part is that all of these remain prompt-following judgments with no factual or
semantic guarantee.

## Correct position in our pipeline

```text
verified evidence selection
  -> evidence-linked first draft
  -> job/company targeting reviewer
  -> Humanizer-inspired style critic
       flags pattern IDs and exact spans
       proposes bounded old-text/new-text edits
       states expected meaning and requirement impact
  -> edit acceptance policy
  -> evidence entailment revalidation
  -> requirement-coverage revalidation
  -> dates, metrics, eligibility and consistency checks
  -> LaTeX compile and visual inspection
  -> ATS text-layer and keyword checks
  -> release manifest
```

The style stage never receives permission to create new experience, metrics,
skills, company facts or eligibility claims. It cannot advance pipeline state.

## Adapted contract

Each proposed style edit must have this shape:

```json
{
  "document_id": "...",
  "old_text": "exact unique span",
  "new_text": "bounded replacement",
  "pattern_ids": ["..."],
  "reason": "...",
  "voice_basis_ids": ["..."],
  "claim_ids_touched": ["..."],
  "requirement_ids_touched": ["..."],
  "meaning_preserved": true,
  "confidence": 0.0
}
```

Automatic acceptance requires:

- `old_text` matches exactly once;
- every touched claim remains entailed by the same approved evidence;
- no requirement coverage is lost;
- no new named entity, number, date, credential, employer fact or skill is
  introduced without an approved source;
- dates and metrics remain identical unless the change is separately approved
  by the factual-correction path;
- the edit does not weaken an ATS-critical exact term that is truthfully
  supported;
- the resulting voice remains within the operator-derived voice profile;
- confidence and policy thresholds pass.

Anything else is rejected or queued for a stronger reviewer. A whole-document
rewrite is never accepted as a single opaque edit.

## Rules to adopt

1. Detect clusters, not isolated stylistic features.
2. Preserve the complete meaning and vacancy-requirement coverage.
3. Calibrate voice using the candidate's own approved writing corpus.
4. Use a restrained register for CVs and structured answers; allow more
   personality in cover letters and outreach where appropriate.
5. Flag exact spans and propose auditable replacements rather than returning an
   unexplained rewritten document.
6. Run a second style audit after accepted edits.
7. Keep the style critic separate from the targeting reviewer and factual
   validator so one model does not grade its own work.

## Rules not to adopt blindly

| Upstream rule or assumption | Our policy |
|---|---|
| A universal em/en-dash ban | Treat punctuation frequency as a configurable voice/style signal, not evidence of AI authorship. |
| “Human” equals adding opinions or messiness | Add neither unless supported by the candidate's real voice and appropriate to the document. |
| One prompt can preserve meaning reliably | Re-run evidence entailment and requirement coverage after every accepted edit. |
| Generic AI-writing patterns are sufficient | Calibrate against Artiom's corpus, successful applications and employer outcomes. |
| Whole-document rewrite output | Require atomic, attributable edits with claim and requirement impact. |
| Humanizer as the final step | Deterministic truth, ATS, rendering and release gates must come afterwards. |

## Evaluation before activation

Create a blinded benchmark containing:

- Artiom's genuine writing in several registers;
- current model-generated CV bullets, letters and application answers;
- deliberately factual but polished text;
- deliberately formulaic AI text;
- documents with planted claim drift and requirement loss.

Measure:

- human preference without revealing which version was edited;
- false-positive rate on genuine writing;
- factual and numerical mutation rate;
- requirement-coverage loss;
- ATS keyword loss;
- voice similarity to the approved corpus;
- interview invitation rate after deployment, segmented by document strategy.

The module ships only if it improves judged authenticity without increasing
unsupported claims or reducing requirement coverage.

