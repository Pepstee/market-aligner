# JAA-11 authorised live-canary selection assessment

Status: `NO_RELEASE_READY_TARGET_FOUND`

This assessment fills no field, uploads no document, issues or consumes no
release token, submits no application, and does not consume the single JAA-11
canary authority.

The production evidence gate changes the earlier selection result: **there is
currently no release-ready canary in the bounded frozen search**. Vega and
CloudCops are both parked. JAA must not issue a JAA-08 release for either one.

## Governing boundary

- Authority: `/Users/admin/Documents/giga-user/reports/JAA11_LIVE_CANARY_OPERATOR_AUTHORITY_2026-07-31.md`.
- Approved evidence: `/Users/admin/Documents/giga-user/job-application-automation/candidate-evidence/approved_evidence_packet_2026-07-28.json`.
- Frozen snapshot: `/Users/admin/Projects/job-application-automation-gutua-20260803-evidence/jaa11-acquisition-unaccepted-full/jaa11_ranked_snapshot.json`.
- Snapshot schema: `jaa11.live-ranked-vacancy-snapshot.v1`.
- Snapshot internal SHA-256: `78d9c69ca53d4733a10e2242d49e6d03f3941b10cb76e94ed13c73b914f77d76`.
- Snapshot file SHA-256: `a37b133be37e811a468bd7ae98e6679903fac9eae04b2e8b6d03e0b33affae8d`.
- Ranked entries: `469`.
- Candidate evidence SHA-256: `7a7e18a686b0979e48716f983871568e018c04398e05b8c71af88059f6fb6195`.
- Viability manifest SHA-256: `e7b76d05a69e90a8a4551c10b673eb9078d29e95e1d046cb1a4f534a9699ee80`.
- Database SHA-256: `67dfb680ad422ea7e1fe1e02d2362957ba3493a5eb0cdae17f0949e9ebbc88c3`.

Every essential role requirement is an evidence gate even when the application
form does not ask the candidate to attest to it. Visible form simplicity cannot
override missing evidence. CAPTCHA detection includes serialized client state,
loaded scripts and observed network routes; it is not limited to visible
challenge widgets.

## Corrected dispositions

### Rank 21 — Vega Product Operations Intern: parked

The earlier statement that Vega had no CAPTCHA was wrong. Its Ashby application
contains Google reCAPTCHA configuration in serialized client state. The
challenge is a forbidden boundary even if no widget is visible before submit.

- Official route: <https://jobs.ashbyhq.com/vega/ebce385f-d4d3-4a39-a999-e048877a81e4/application>.
- Disposition: `captcha_configuration_present`.
- Release: forbidden.

### Rank 32 — CloudCops Junior DevOps / Cloud Engineer: parked

The official Personio route itself passed the live transport/form check. The
fully loaded application asked only for first name, last name, email, phone and
CV, with LinkedIn and one extra document optional. A fresh inspection found no
CAPTCHA, reCAPTCHA, hCaptcha, Turnstile, login/account, MFA, payment or identity
route in the accessibility tree, serialized DOM, loaded script URLs or observed
network-request URLs.

That clean route is not sufficient. The role expressly requires first hands-on
major-cloud experience and **solid Git, Linux and shell skills**. E-001 through
E-018 support the degree, SCAFAD's AWS Lambda subject matter and ownership
boundaries for AI-directed projects, but they do not establish the required
Git/Linux/shell proficiency. A GitHub account is not evidence of solid Git,
Linux or shell skill. SCAFAD investigating AWS Lambda telemetry is not a licence
to infer every operational cloud competency.

- Frozen entry SHA-256: `923ef22e3502a66881a55dfaf9327b86758c7bd7c000bbb5ae0d84ac7b524035`.
- Official route: <https://cloudcops.jobs.personio.com/job/2183016?language=en&apply>.
- Disposition: `required_capability_not_in_approved_packet`.
- Missing evidence: solid Git, Linux and shell competence, plus sufficiently
  direct evidence of hands-on major-cloud work.
- Release: forbidden; no JAA-08 release may be issued.

## Sequential continuation from rank 33

The next ranks were screened against the role requirements before form
execution. Where a candidate survived the evidence screen, its current official
route was then inspected deeply.

| Rank | Candidate | Disposition | Precise blocker |
|---:|---|---|---|
| 33 | RVR Infra Tech, Cloud Engineer Intern | Reject | Requires Linux/command-line, Git, networking and cloud-platform experience not established by E-001–E-018. |
| 34 | Canonical, Junior Linux Kernel Engineer | Reject | Kernel development and Linux systems proficiency are not established. |
| 35 | Canonical, Graduate Software Engineer — Open Source/Linux | Reject | Requires Linux/open-source engineering evidence and extensive academic answers beyond the approved packet. |
| 36 | NHS, Junior Data Engineer | Park | Official NHS route cannot be deterministically inspected without the service's access/account boundary; the packet also does not establish the complete person-specification requirements. |
| 37 | Anthropic Fellows, AI Security | Reject | Current cohort deadline was 26 July 2026, before this inspection; mandatory Python fluency is also not stated by E-001–E-018. |
| 38 | Canonical, Entry-Level Communications Specialist | Reject | Canonical's academic-history application requires unsupported school/university facts; the role-specific communications portfolio is not established by the packet. |
| 39 | BibliU, AI & Innovation Analyst | Reject | Requires production full-stack application proficiency; approved evidence deliberately records MVP/AI-directed implementation boundaries instead. |
| 40 | Bjak, Full Stack Engineer — AI Systems | Reject | Production full-stack engineering capability is not established. |
| 41 | G2i, FullStack Engineer (Python + React) | Reject | Professional Python/React full-stack experience is not established. |
| 42 | WebinarGeek, Junior Front-End/JavaScript Developer | Park | Routes through Magnet.me's account boundary; required personal front-end engineering depth is not established. |

Ranks 43–359 are dominated by architect, research, ML, security, platform,
solutions and professional software-engineering roles whose essential
experience, specialist stack or research credentials are absent from
E-001–E-018. The plausible adjacent exceptions were checked individually:

- Rank 99 Decoded Facilitator is blocked by serialized Recruitee hCaptcha
  configuration, current-location/time-zone ambiguity and unsupported answers.
- Rank 104 Kainos Content Developer requires proven sales-content creation and
  advanced PowerPoint/Canva/Adobe design proficiency, neither in the packet.
- Ranks 117–120 university AI research roles require relevant MSc/PhD,
  publication/research track records, GPU/FPGA depth or equivalent experience.
- Rank 214 xAI Software Engineer Tutor requires professional scalable-software
  engineering, deep language expertise, debugging/profiling and testing depth.
- Rank 227 University of Edinburgh Software Engineer requires strong hands-on
  secure Ruby/Rails full-stack and production service experience.
- Rank 293 NHS System Developer requires significant NHS/similar-industry
  experience and advanced Crystal Reports expertise.
- Other Ashby and Greenhouse routes in this interval are independently blocked
  by CAPTCHA configuration where the evidence screen did not already reject the
  role.

## Deep check of the first later evidence-supported role

### Rank 360 — Gonini/Bezos.ai Graduate Business Operations Associate: parked

This was the first materially later role whose substantive requirements are
plausibly supported by the approved packet: quantitative CS degree (E-001),
AI-directed skills/agents/automation (E-011–E-016), and communication or
operational experience (E-003–E-008).

- Frozen source: <https://himalayas.app/companies/bezos-ai/jobs/graduate-business-operations-associate>.
- Current official application: <https://apply.workable.com/bezos/j/FE3E6C7393/apply/>.
- Current page title: `Graduate Business Operations Associate - Gonini (previously known as Bezos.ai) - Application`.

The official Workable form requires name, email, phone, CV and three yes/no
questions covering UK work rights, AI-native building and quantitative study.
Those questions are answerable from the verified record. The route nevertheless
fails before population: the loaded DOM contains CAPTCHA/reCAPTCHA/Turnstile
markers, loads `https://challenges.cloudflare.com/turnstile/v0/api.js`, and
exposes the Cloudflare Turnstile boundary. No field was populated.

- Disposition: `captcha_configuration_present`.
- Release: forbidden.

## Lower-ranked bounded review

The remainder of the frozen list was screened by entry-level flag, title/role
family and stored requirement text. Every candidate that appeared plausibly
adjacent to E-001–E-018 was opened at the requirement level; none produced a
clean evidence-plus-route target.

- Rank 361 Databento requires at least two years in support/QA/engineering and
  prefers prior Databento API/market-data experience.
- Rank 362 Intuition Machines research fellowship requires research credentials
  not established by the packet.
- Ranks 363–364 require data-engineering or Lenel/Milestone security-system
  experience not established by the packet.
- Rank 365 Swoon Graduate Partner Trading requires advanced spreadsheet/
  merchandising answers, a mandatory cover letter, bespoke exercises, salary
  and notice-period answers; its Workable route is not a simpler release path.
- Rank 366 NHS Junior IT Support requires a valid UK driving licence and daily
  Horley commuting. The approved packet contains no driving licence; the
  operator has separately recorded that the driving test is still to be booked.
- Rank 400 Smartsheet Software Engineer I requires one-plus years each of
  professional scalable software development, programming and cloud work plus
  ongoing US work eligibility.
- Rank 422 Makersite Technical Support requires at least three years in complex
  B2B SaaS support plus API, monitoring, database, cloud and IAM depth.
- Rank 423 Ashcroft Learning Mentor requires experience working with young
  people in a school environment and challenging-behaviour support. Paid online
  English teaching in E-006 does not establish those facts.
- Ranks 432–433 Mercor adversarial/safety roles require native Urdu or fluent
  Punjabi and prior red-team experience; their process also mandates an AI
  interview.
- Rank 436 NISC is explicitly not an active opening; it is a future pipeline.
- Rank 439 Senseon requires personally evidenced practical coding, APIs/auth/
  webhooks, CI/CD and cloud reliability. E-011–E-015 preserve AI-authorship
  caveats and do not support those personal implementation claims.
- Ranks 444–445 require information-governance/security-incident experience.
- Ranks 448, 450 and 453 require technical-support/NHS, specific .NET/IIS/
  clinical-system, or advanced SCORM/e-learning production experience.
- Remaining ranks are specialist software, platform, security, solutions,
  research, data or infrastructure roles whose explicit experience/technology
  gates are outside the approved packet; the final Magnet.me candidate also
  introduces an account boundary.

This is a **bounded no-target conclusion**, not a claim that every downstream
application form was populated or submitted. The full frozen title/role set was
screened; detailed stored requirements were read for every plausible
evidence-adjacent exception; live deep form inspection was reserved for
candidates that survived that requirement screen. That ordering is required by
the no-data-entry-before-boundary law.

## Required next action

Do not select or submit a canary from this snapshot automatically. Return to the
operator/release controller with `NO_RELEASE_READY_TARGET_FOUND`.

A future canary requires one of:

1. a newly acquired low-value vacancy whose essential requirements are already
   supported by E-001–E-018 and whose official route passes the deep blocker
   scan; or
2. a separately operator-approved evidence-packet revision that adds verified
   capabilities without inference, followed by a fresh selection assessment.

The search must not weaken evidence semantics, treat an account or CAPTCHA as
automatable, infer professional coding from AI-directed ownership, infer
Git/Linux/shell proficiency from a GitHub URL, or use CloudCops merely because
its form is technically clean.
