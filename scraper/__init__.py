"""UK Job Matcher — scraper module (legacy Korean adapters retained as fixtures).

Per-board adapters, crawl/fetch orchestration, rate-limiting, and the raw
cache. Talks to the rest of the system ONLY through skeleton/contracts.py
(C1 JobUrl, C2 RawPosting). Built fixture-first so it runs standalone.
"""
