# Deterministic and probabilistic boundaries

| Concern | Owner | Required receipt |
|---|---|---|
| Fetch, cache, source state, hashes, retries | deterministic host code | fetch attempt and content hash |
| Vacancy shell, canonical URL/key, deduplication | deterministic host code | canonicalisation version and representative keys |
| Expiry, accessibility and hard eligibility | deterministic host code over explicit facts | rule/policy hash and reasons |
| Semantic vacancy extraction | LLM through validated schema | raw-content hash, prompt/model and output hash |
| Evidence-to-requirement alignment | LLM through validated schema | profile version, permitted evidence IDs and output hash |
| Fit and opportunity arithmetic | deterministic host code | parameter hash; fit remains `uncalibrated` |
| Research admission, queues, leases and dossiers | deterministic host code | opportunity-gate event and cited dossier receipt |
| Application documents and answers | separately certified application component | evidence citations and validation release |
| Submission, legal consent, irreversible external action | operator | explicit approval and external receipt |

LLM output is data, not authority. Invalid schemas, unknown evidence IDs, missing content hashes,
or non-portable output are rejected before state changes.
