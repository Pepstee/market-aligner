"""Full Scrapling sidecar protocol.

This module runs inside ``.venv-scrapling``.  It intentionally passes options
through to upstream Scrapling instead of maintaining a reduced parallel API.
JSON values can reference Python objects with ``{"$ref": "module:object"}``,
which preserves custom page actions, setup hooks, selector storage classes,
proxy strategies and arbitrary extension functions.
"""

from __future__ import annotations

import base64
import dataclasses
import importlib
import importlib.metadata
import json
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


RESULT_PREFIX = "__SCRAPLING_RESULT__="


def _import_ref(reference: str) -> Any:
    module_name, separator, object_path = reference.partition(":")
    if not separator or not module_name or not object_path:
        raise ValueError(f"invalid Python reference {reference!r}; expected module:object")
    value: Any = importlib.import_module(module_name)
    for part in object_path.split("."):
        value = getattr(value, part)
    return value


def _hydrate(value: Any) -> Any:
    """Restore Python-only values that cannot be represented directly in JSON."""
    if isinstance(value, list):
        return [_hydrate(item) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {"$ref"}:
        return _import_ref(str(value["$ref"]))
    if set(value) == {"$set"}:
        return set(_hydrate(value["$set"]))
    if set(value) == {"$tuple"}:
        return tuple(_hydrate(value["$tuple"]))
    if set(value) == {"$bytes_base64"}:
        return base64.b64decode(str(value["$bytes_base64"]), validate=True)
    if set(value) == {"$path"}:
        return Path(str(value["$path"]))
    if set(value) == {"$proxy_rotator"}:
        from scrapling.fetchers import ProxyRotator

        options = dict(value["$proxy_rotator"])
        proxies = _hydrate(options.pop("proxies"))
        strategy = _hydrate(options.pop("strategy", {"$ref": "scrapling.engines.toolbelt.proxy_rotation:cyclic_rotation"}))
        if options:
            raise ValueError(f"unknown ProxyRotator options: {sorted(options)}")
        return ProxyRotator(proxies, strategy=strategy)
    return {str(key): _hydrate(item) for key, item in value.items()}


def _prepare_kwargs(url: str, value: Mapping[str, Any]) -> dict[str, Any]:
    kwargs = dict(_hydrate(dict(value)))
    selector_config = kwargs.get("selector_config")
    if isinstance(selector_config, dict):
        selector_config = dict(selector_config)
        storage_args = selector_config.get("storage_args")
        if isinstance(storage_args, dict):
            storage_args = dict(storage_args)
            storage_args.setdefault("url", url)
            selector_config["storage_args"] = storage_args
        kwargs["selector_config"] = selector_config
    return kwargs


def _selector_value(value: Any) -> dict[str, Any]:
    return {
        "type": type(value).__name__,
        "url": getattr(value, "url", ""),
        "tag": getattr(value, "tag", ""),
        "attributes": dict(getattr(value, "attrib", {}) or {}),
        "text": str(getattr(value, "text", "")),
        "all_text": str(value.get_all_text()) if hasattr(value, "get_all_text") else "",
        "html": str(getattr(value, "html_content", value)),
    }


def _jsonable(value: Any, *, depth: int = 0) -> Any:
    if depth > 20:
        return {"type": type(value).__name__, "representation": repr(value)}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {"encoding": "base64", "data": base64.b64encode(value).decode("ascii")}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return _jsonable(value.value, depth=depth + 1)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _jsonable(dataclasses.asdict(value), depth=depth + 1)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item, depth=depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item, depth=depth + 1) for item in value]
    if value.__class__.__module__.startswith("scrapling.parser"):
        if isinstance(value, list):
            return [_selector_value(item) for item in value]
        return _selector_value(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _jsonable(to_dict(), depth=depth + 1)
    if hasattr(value, "__dict__"):
        return {
            "type": type(value).__name__,
            "values": _jsonable(vars(value), depth=depth + 1),
        }
    return {"type": type(value).__name__, "representation": repr(value)}


def _response_to_dict(response: Any, *, include_related: bool = True) -> dict[str, Any]:
    body = bytes(response.body)
    encoding = str(getattr(response, "encoding", "utf-8") or "utf-8")
    try:
        text = body.decode(encoding, errors="replace")
    except LookupError:
        encoding = "utf-8"
        text = body.decode(encoding, errors="replace")
    result = {
        "status": int(response.status),
        "reason": str(response.reason),
        "url": str(response.url),
        "encoding": encoding,
        "method": str(getattr(response, "method", "GET")),
        "headers": _jsonable(response.headers),
        "request_headers": _jsonable(response.request_headers),
        "cookies": _jsonable(response.cookies),
        "meta": _jsonable(response.meta),
        "body_bytes": len(body),
        "body_base64": base64.b64encode(body).decode("ascii"),
        "text": text,
    }
    if include_related:
        result["history"] = [
            _response_to_dict(item, include_related=False) for item in response.history
        ]
        result["captured_xhr"] = [
            _response_to_dict(item, include_related=False)
            for item in (getattr(response, "captured_xhr", ()) or ())
        ]
    return result


def _fetch(request: Mapping[str, Any]) -> dict[str, Any]:
    engine = str(request.get("engine", "http")).casefold()
    url = str(request["url"])
    kwargs = _prepare_kwargs(url, dict(request.get("kwargs") or {}))
    if engine == "http":
        from scrapling.fetchers import Fetcher
        method = str(request.get("method", "get")).casefold()
        if method not in {"get", "post", "put", "delete"}:
            raise ValueError("HTTP method must be get, post, put or delete")
        response = getattr(Fetcher, method)(url, **kwargs)
    elif engine == "dynamic":
        from scrapling.fetchers import DynamicFetcher
        response = DynamicFetcher.fetch(url, **kwargs)
    elif engine in {"stealth", "stealthy"}:
        from scrapling.fetchers import StealthyFetcher
        response = StealthyFetcher.fetch(url, **kwargs)
    else:
        raise ValueError("engine must be http, dynamic or stealth")
    return _response_to_dict(response)


def _session_batch(request: Mapping[str, Any]) -> list[dict[str, Any]]:
    from scrapling.fetchers import DynamicSession, FetcherSession, StealthySession

    engine = str(request.get("engine", "http")).casefold()
    session_kwargs = _hydrate(dict(request.get("session_kwargs") or {}))
    jobs = list(request.get("requests") or ())
    if engine == "http":
        manager = FetcherSession(**session_kwargs)
    elif engine == "dynamic":
        manager = DynamicSession(**session_kwargs)
    elif engine in {"stealth", "stealthy"}:
        manager = StealthySession(**session_kwargs)
    else:
        raise ValueError("engine must be http, dynamic or stealth")

    rows: list[dict[str, Any]] = []
    with manager as session:
        for job in jobs:
            url = str(job["url"])
            kwargs = _prepare_kwargs(url, dict(job.get("kwargs") or {}))
            if "selector_config" not in kwargs and isinstance(session_kwargs.get("selector_config"), dict):
                kwargs["selector_config"] = _prepare_kwargs(
                    url, {"selector_config": session_kwargs["selector_config"]}
                )["selector_config"]
            if engine == "http":
                method = str(job.get("method", "get")).casefold()
                response = getattr(session, method)(url, **kwargs)
            else:
                response = session.fetch(url, **kwargs)
            rows.append(_response_to_dict(response))
    return rows


def _parse(request: Mapping[str, Any]) -> dict[str, Any]:
    from scrapling.parser import Selector

    if request.get("content_base64") is not None:
        content: str | bytes = base64.b64decode(str(request["content_base64"]), validate=True)
    else:
        content = str(request.get("content", ""))
    selector = Selector(
        content=content,
        url=str(request.get("url", "")),
        **_hydrate(dict(request.get("selector_config") or {})),
    )
    outputs: dict[str, Any] = {}
    for index, operation in enumerate(request.get("operations") or ()):
        name = str(operation.get("name") or f"operation_{index}")
        method_name = str(operation["method"])
        target: Any = selector
        for attribute in operation.get("target", ()):
            target = getattr(target, str(attribute))
        method = getattr(target, method_name)
        value = method(
            *_hydrate(list(operation.get("args") or ())),
            **_hydrate(dict(operation.get("kwargs") or {})),
        )
        outputs[name] = _jsonable(value)
    return {
        "document": _selector_value(selector),
        "outputs": outputs,
    }


def _spider(request: Mapping[str, Any]) -> Any:
    spider_class = _import_ref(str(request["class_ref"]))
    spider = spider_class(
        *_hydrate(list(request.get("init_args") or ())),
        **_hydrate(dict(request.get("init_kwargs") or {})),
    )
    result = spider.start(**_hydrate(dict(request.get("start_kwargs") or {})))
    return _jsonable(result)


def _call(request: Mapping[str, Any]) -> Any:
    function = _import_ref(str(request["callable_ref"]))
    return _jsonable(function(
        *_hydrate(list(request.get("args") or ())),
        **_hydrate(dict(request.get("kwargs") or {})),
    ))


def capabilities() -> dict[str, Any]:
    from scrapling.fetchers import (
        AsyncDynamicSession,
        AsyncFetcher,
        AsyncStealthySession,
        DynamicFetcher,
        DynamicSession,
        Fetcher,
        FetcherSession,
        ProxyRotator,
        StealthyFetcher,
        StealthySession,
    )
    from scrapling.spiders import (
        CrawlRule,
        CrawlSpider,
        LinkExtractor,
        Request,
        SessionManager,
        ShopifySpider,
        SitemapSpider,
        Spider,
    )

    exports = (
        Fetcher, AsyncFetcher, FetcherSession, DynamicFetcher, DynamicSession,
        AsyncDynamicSession, StealthyFetcher, StealthySession,
        AsyncStealthySession, ProxyRotator, Spider, Request, SessionManager,
        LinkExtractor, CrawlSpider, CrawlRule, SitemapSpider, ShopifySpider,
    )
    return {
        "scrapling_version": importlib.metadata.version("scrapling"),
        "python": sys.version,
        "operations": ["fetch", "session_batch", "parse", "spider", "call", "capabilities"],
        "exports": [f"{value.__module__}:{value.__qualname__}" for value in exports],
        "engines": ["http", "dynamic", "stealth"],
        "http_methods": ["get", "post", "put", "delete"],
        "typed_json": ["$ref", "$set", "$tuple", "$bytes_base64", "$path", "$proxy_rotator"],
        "upstream_cli": ["install", "extract", "shell", "mcp"],
    }


def execute(request: Mapping[str, Any]) -> Any:
    operation = str(request.get("operation", "capabilities"))
    if operation == "capabilities":
        return capabilities()
    if operation == "fetch":
        return _fetch(request)
    if operation == "session_batch":
        return _session_batch(request)
    if operation == "parse":
        return _parse(request)
    if operation == "spider":
        return _spider(request)
    if operation == "call":
        return _call(request)
    raise ValueError(f"unknown operation: {operation}")


def main() -> int:
    request = json.load(sys.stdin)
    try:
        payload = {"ok": True, "result": execute(request)}
    except Exception as exc:
        payload = {
            "ok": False,
            "error": type(exc).__name__,
            "message": str(exc),
        }
    print(RESULT_PREFIX + json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
