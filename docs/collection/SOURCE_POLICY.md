# Collection policy

Market Aligner keeps collector mechanics deterministic and source-specific:

- adapters discover and fetch public vacancy material using injected configuration;
- the collector has no result cap and persists each discovery before detail fetching;
- source polling and detail fetching are independently concurrent;
- pending detail fetches make interrupted cycles immediately resumable;
- per-source delays, request limits, credentials, and terms-of-service constraints belong in
  external operator configuration;
- Scrapling exposes its complete native protocol, while the automatic fallback chain defaults
  to static and dynamic fetching only;
- stealth, challenge-solving, authenticated sessions, custom hooks, and spiders require an
  explicit source policy decision and configuration.

Application forms are outside this collector. Supported deterministic execution belongs to the
separately certified application component and remains operator-gated at submission.
