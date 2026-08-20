# Complete Scrapling integration

## What is installed

The project uses the actual full upstream distribution, not a local rewrite:

- repository: `D4Vinci/Scrapling`;
- audited commit: `5320319155127519b46c0d35cc7a5037b936af05`;
- package version: `0.4.11`;
- licence: BSD-3-Clause;
- runtime: isolated Python 3.12 at `.venv-scrapling`;
- extras: `scrapling[all]`;
- browser assets: Playwright Chromium and Patchright Chromium.

Recreate it exactly with:

```bash
./scripts/install_scrapling_full.sh
```

## Upstream capability retained

The installed package exposes all of these upstream surfaces:

- `Fetcher`, `AsyncFetcher` and `FetcherSession` with GET, POST, PUT and DELETE;
- browser impersonation, browser headers, HTTP/3, certificates, retries,
  cookies, authentication, redirect control and static proxies;
- `ProxyRotator` with cyclic or custom importable strategies;
- `DynamicFetcher`, `DynamicSession` and `AsyncDynamicSession` on Playwright;
- `StealthyFetcher`, `StealthySession` and `AsyncStealthySession` on Patchright;
- Cloudflare Turnstile/interstitial solving, real Chrome, canvas/WebGL/WebRTC
  controls, DNS-over-HTTPS and browser fingerprint generation;
- persistent user-data directories, executable selection, additional Chromium
  flags, context arguments and CDP connections;
- page setup hooks before navigation and page action hooks after navigation;
- wait selectors/states, DOM/network-idle waits, resource/domain/ad blocking,
  locale/timezone, headers, cookies and XHR/fetch capture;
- CSS, XPath, text and regex parsing plus stored adaptive selectors;
- Spider, CrawlSpider, SitemapSpider and ShopifySpider; per-domain concurrency,
  sessions, robots, cache, retries, blocked-request hooks, statistics,
  streaming and pause/resume checkpoints;
- the upstream extraction CLI, interactive shell and MCP server;
- AI-targeted extraction/Markdown support included by the `all` extra.

The worker does not whitelist a reduced set of Scrapling kwargs. JSON payloads
are passed through after restoring Python-only values:

| JSON form | Restored value |
|---|---|
| `{"$ref":"package.module:object"}` | class, function or other importable object |
| `{"$set":[...]}` | `set` |
| `{"$tuple":[...]}` | `tuple` |
| `{"$bytes_base64":"..."}` | raw `bytes` |
| `{"$path":"..."}` | `pathlib.Path` |
| `{"$proxy_rotator":{...}}` | upstream `ProxyRotator` |

This allows custom page hooks, selector storage classes, proxy strategies and
spiders without `eval` or a feature-specific wrapper release.

## Collector behaviour

Board-specific adapters remain the fastest first attempt. If an adapter fails,
`scraper.collector.Collector` uses the chain in
`skeleton/config.overnight.yaml`:

```text
Scrapling static -> Scrapling dynamic -> Scrapling stealth
```

The default dynamic and stealth stages capture every XHR/fetch response. The
stealth stage enables Cloudflare solving. Configuration is plain YAML and every
`kwargs` member is passed to the corresponding upstream fetcher.

For a successful recovery, the raw record contains decoded page text and a
`_scrapling.attempts` envelope with every attempted response: status, reason,
final URL, response/request headers, cookies, metadata, redirects, raw body as
base64 and captured XHR bodies. If all engines fail, the complete attempts are
written below `raw_cache/_scrapling_failures/`; they are not discarded into a
short log line. Downstream extraction and deterministic scoring are unchanged.

## Direct use

Use the actual upstream CLI:

```bash
./scripts/scrapling.sh --help
./scripts/scrapling.sh extract --help
./scripts/scrapling.sh shell
./scripts/scrapling.sh mcp --help
```

Use the complete Python API directly:

```bash
./.venv-scrapling/bin/python
```

Then import from `scrapling.fetchers`, `scrapling.parser` or
`scrapling.spiders` exactly as documented upstream.

For a machine-readable worker request:

```bash
echo '{"operation":"capabilities"}' | \
  ./.venv-scrapling/bin/python -m scraper.scrapling_worker
```

Supported worker operations are `fetch`, `session_batch`, `parse`, `spider`,
`call` and `capabilities`. `call` accepts any importable project function, so
specialised flows can work with the native Scrapling objects in-process rather
than waiting for the JSON protocol to grow another bespoke option.
