# Market Aligner — Product Direction

## Purpose

Market Aligner helps serious UK technology candidates turn a verified personal evidence
base and live vacancies into fewer, stronger, truthful applications. It removes repetitive
search, research, document writing, form entry and bookkeeping while keeping consequential
decisions deterministic and auditable.

## User

The first user is an ambitious, technically comfortable UK job seeker who applies across
AI, software, platform and adjacent technical roles. They care about fit, evidence and
privacy more than raw application volume. The architecture must support other candidate
profiles without embedding the first operator's identity or career assumptions.

## Core job

Continuously find worthwhile roles, explain why they are worthwhile, compile a truthful
application from approved evidence, submit only through an authorised official route, and
retain enough provenance to explain every decision and outcome.

## Product principles

- Qualified interviews per eligible, truthfully supported application is the primary
  outcome. Application volume is not success.
- Local-first and private by default. User data remains inspectable, exportable and
  recoverable without an active entitlement.
- Verdict first, evidence second. Every important score links to its inputs and sources.
- Models advise and draft; deterministic policy controls release and external action.
- Unknown means blocked or abstained, never guessed.
- Automation stops at login, MFA, CAPTCHA, consent, legal attestation, site policy or any
  unsupported submission boundary that requires the person.

## Product personality

Rigorous, calm, direct and unsentimental. British English. It behaves like a capable career
operator, not a motivational coach and not an application spammer.

## Interface direction

Ship a responsive local web application. The primary surface is a pipeline workspace with
clear current states, queues, evidence, blockers and receipts. Use restrained typography,
neutral colour, dense but legible tables where comparison matters, progressive disclosure
for evidence detail, and WCAG 2.2 AA interaction contrast and keyboard behaviour.

Do not use generic AI-dashboard decoration: no gratuitous gradients, glass panels, glowing
cards, oversized hero text, fake live metrics, decorative chat bubbles, excessive rounded
containers or animation without a state-change purpose. Empty and blocked states must say
what is known, what is missing and what the system will do next.

## Version 0.1 release

The first commercial shape is a local-first, single-user product with a polished browser UI,
CLI and documented install/update/backup lifecycle. It includes a usable evaluation mode and
a real entitlement boundary suitable for later merchant activation. A hosted multi-tenant
service is deliberately deferred until local product evidence justifies its privacy and
operational cost.

## Success measures

- Eligible applications released with zero unsupported claims.
- At-most-once submission with official receipts.
- Qualified interview rate, offer rate and time to offer.
- Candidate minutes required per application and per week.
- Abstention, block and recovery accuracy.
- Clean-install, upgrade and restore success on supported hardware.

## Release blockers

Unsupported claims, guessed eligibility, duplicate submission, absent receipts, private-data
leakage, first-user-specific defaults, inaccessible critical flows, non-reproducible installs,
or commercial claims that outrun product evidence.
