# Deterministic and probabilistic boundaries

| Concern | Owner | Required receipt |
|---|---|---|
| Fetch, cache, source state, hashes, retries | deterministic host code | fetch attempt and content hash |
| Vacancy shell, canonical URL/key, deduplication | deterministic host code | canonicalisation version and representative keys |
| Expiry, accessibility and hard eligibility | deterministic host code over explicit facts | rule/policy hash and reasons |
| Semantic vacancy extraction | explicit RFC 6901 projection for retained structured JSON; otherwise LLM through validated schema | raw-content hash plus pointer map for deterministic projection, or prompt/model and output hash for LLM output |
| Evidence-to-requirement alignment | exact normalised matching over selected approved content-bound evidence when explicit requirements are available; otherwise LLM through validated schema | profile version, permitted evidence IDs, algorithm/prompt identity and output hash |
| Fit and opportunity arithmetic | deterministic host code | parameter hash; fit remains `uncalibrated` |
| Research admission, queues, leases and dossiers | deterministic host code | opportunity-gate event and cited dossier receipt |
| Application documents and answers | separately certified application component | evidence citations and validation release |
| Final employer-visible semantic sanity review | one-shot LLM through a strict schema; CLI or opt-in direct Responses transport | exact package/policy/model/result binding and provider transport hashes when available |
| Submission, legal consent, irreversible external action | operator | explicit approval and external receipt |

LLM output is data, not authority. Invalid schemas, unknown evidence IDs, missing content hashes,
or non-portable output are rejected before state changes.

The deterministic structured path is owned by `market_aligner.llm.structured`. It validates the
exact retained public bytes through the canonical vacancy evidence boundary, rejects ambiguous
JSON or timestamps, and emits the same extraction/alignment contracts and hash-bound receipts as
the probabilistic path. It may establish only facts selected by explicit pointers and lexical
matches in approved evidence; it cannot infer a missing vacancy fact or candidate claim.

The direct OpenAI adapter is owned by `internal/jaa/llm`; it is an optional
transport beneath the same client and review policy, not a separate JAA or
employer-review product. It is tool-free and stateless (`store=false`), and its
secret-free request/response identities are bound into the final sanity receipt.
