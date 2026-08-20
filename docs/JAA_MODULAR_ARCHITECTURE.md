# JAA modular architecture

JAA is split into three authority domains. Dependencies flow down this list;
they do not flow back up.

```text
form_filling  ->  cv_generation  ->  jaa_core
      |                                  ^
      +----------------------------------+
```

## `jaa_core`

Owns candidate evidence, opportunity requirements, eligibility, application
state, durable identities, and receipts. It must not know how a CV is laid out
or how a website field is operated.

## `cv_generation`

Owns evidence-bound composition, tailoring, document rendering, and every CV
presentation constraint. `validate_generated_cv` is called synchronously by the
existing generation path after deterministic rendering and before any revision
is published. A failure aborts package creation. Its receipt is diagnostic and
cannot grant release or submission authority.

The active Artiom Gutu policy deterministically requires Birmingham, July 2026,
the canonical SCAFAD dissertation title, and a professional capabilities
section. It rejects document labels, work-rights/visa declarations, day-level
graduation dates, continuation-page banners, and formats or storage engines
presented as skills.

## `form_filling`

Owns provider-field discovery and binding, browser interaction, uploads,
consent state, pre-submit verification, and the final certified executor. It
may consume immutable approved application artifacts; it may not rewrite CV
content.

## Migration state

The new packages are the public boundaries. Existing implementations remain in
`career_automation` behind compatibility services for this first working
increment. `jaa_core.module_boundaries` records one owner for each consequential
legacy file and checks that the new public modules cannot reverse the dependency
direction. Subsequent increments can move owner groups physically, one at a
time, while the compatibility imports keep existing runtime entry points green.
