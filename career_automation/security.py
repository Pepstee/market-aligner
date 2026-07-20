"""Security boundaries borrowed from mature agent and workflow platforms.

The contracts in this module are deliberately small and deterministic:

* backends receive explicit immutable capability manifests;
* outbound URLs and every redirect hop must resolve only to public addresses;
* access tokens carry narrow subject/resource/action scopes and are stored as
  digests, never as plaintext secrets; and
* subprocesses run without a shell, with a minimal environment, bounded output,
  a temporary working directory, time limits, and best-effort OS resource limits.

``BoundedSubprocessRunner`` is a process boundary, not a network sandbox.  A
permitted executable can still use the network and interact with any operating
system resource available to the parent account.  Network isolation requires a
separate OS/container boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import math
import os
import re
import secrets
import signal
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Iterable, Mapping, Sequence
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit


PROCESS_BOUNDARY_NOTICE = (
    "This runner is a bounded process boundary, not a network sandbox; permitted "
    "executables retain the parent account's network and operating-system access."
)


class SecurityPolicyError(ValueError):
    """Raised when untrusted input violates a deterministic security policy."""


# ---------------------------------------------------------------------------
# Immutable backend capabilities


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")


def _validated_identifier(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise SecurityPolicyError(f"invalid {field_name}: {value!r}")
    return value


def _resource_matches(pattern: str, resource: str) -> bool:
    """Match an exact resource or one explicit ``prefix/*`` subtree.

    General globbing is intentionally unsupported: it is difficult to audit and
    tends to produce accidental privilege expansion.
    """

    if pattern.endswith("/*"):
        prefix = pattern[:-2]
        return resource.startswith(prefix + "/") and len(resource) > len(prefix) + 1
    return hmac.compare_digest(pattern, resource)


@dataclass(frozen=True)
class CapabilityGrant:
    """One capability and the resources on which it may operate."""

    capability: str
    resource_patterns: tuple[str, ...]

    def __post_init__(self) -> None:
        _validated_identifier(self.capability, "capability")
        patterns = tuple(sorted(set(self.resource_patterns)))
        if not patterns or any(not isinstance(item, str) or not item for item in patterns):
            raise SecurityPolicyError("a capability grant needs non-empty resource patterns")
        if any("*" in item[:-1] or ("*" in item and not item.endswith("/*")) for item in patterns):
            raise SecurityPolicyError("only exact resources and trailing /* scopes are allowed")
        object.__setattr__(self, "resource_patterns", patterns)


@dataclass(frozen=True)
class BackendCapabilityManifest:
    """Immutable, versioned declaration of everything a backend may do."""

    backend_id: str
    grants: tuple[CapabilityGrant, ...]
    version: int = 1

    def __post_init__(self) -> None:
        _validated_identifier(self.backend_id, "backend_id")
        grants = tuple(self.grants)
        if self.version < 1:
            raise SecurityPolicyError("manifest version must be positive")
        names = [grant.capability for grant in grants]
        if len(names) != len(set(names)):
            raise SecurityPolicyError("a manifest cannot contain duplicate capabilities")
        object.__setattr__(self, "grants", tuple(sorted(grants, key=lambda item: item.capability)))


@dataclass(frozen=True)
class CapabilityDecision:
    allowed: bool
    backend_id: str
    capability: str
    resource: str
    reason: str


class CapabilityAuthorizer:
    """Pure, deterministic authorization over immutable manifests."""

    def __init__(self, manifests: Iterable[BackendCapabilityManifest]) -> None:
        indexed: dict[str, BackendCapabilityManifest] = {}
        for manifest in manifests:
            if manifest.backend_id in indexed:
                raise SecurityPolicyError(f"duplicate backend manifest: {manifest.backend_id}")
            indexed[manifest.backend_id] = manifest
        self._manifests: Mapping[str, BackendCapabilityManifest] = MappingProxyType(indexed)

    @property
    def manifests(self) -> Mapping[str, BackendCapabilityManifest]:
        return self._manifests

    def authorize(self, backend_id: str, capability: str, resource: str) -> CapabilityDecision:
        manifest = self._manifests.get(backend_id)
        if manifest is None:
            return CapabilityDecision(False, backend_id, capability, resource, "unknown_backend")
        grant = next((item for item in manifest.grants if item.capability == capability), None)
        if grant is None:
            return CapabilityDecision(False, backend_id, capability, resource, "capability_not_granted")
        if any(_resource_matches(pattern, resource) for pattern in grant.resource_patterns):
            return CapabilityDecision(True, backend_id, capability, resource, "explicit_grant")
        return CapabilityDecision(False, backend_id, capability, resource, "resource_out_of_scope")


# ---------------------------------------------------------------------------
# Outbound URL and SSRF controls


DNSResolver = Callable[[str, int], Iterable[str]]


def _system_resolver(hostname: str, port: int) -> Iterable[str]:
    results = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    return tuple(sorted({item[4][0] for item in results}))


def _public_ip(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise SecurityPolicyError(f"resolver returned an invalid IP address: {address!r}") from exc
    # Check every prohibited class explicitly as well as ``is_global``.  Some
    # Python/platform combinations report multicast addresses as globally
    # routable even though they are never valid HTTP destinations.
    if (
        not parsed.is_global
        or parsed.is_private
        or parsed.is_link_local
        or parsed.is_loopback
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    ):
        raise SecurityPolicyError(f"outbound target is not a public IP address: {parsed}")
    return parsed


@dataclass(frozen=True)
class ValidatedOutboundURL:
    url: str
    scheme: str
    hostname: str
    port: int
    resolved_addresses: tuple[str, ...]

    def assert_connected_peer(self, peer_address: str) -> None:
        """Ensure the actual peer is public and one of the validated DNS answers."""

        peer = str(_public_ip(peer_address))
        if peer not in self.resolved_addresses:
            raise SecurityPolicyError("connected peer was not present in the validated DNS result")


@dataclass(frozen=True)
class OutboundURLPolicy:
    """Strict public-web URL policy with injectable DNS resolution."""

    resolver: DNSResolver = field(default=_system_resolver, repr=False, compare=False)
    allowed_ports: frozenset[int] = frozenset({80, 443})
    max_redirects: int = 8

    def __post_init__(self) -> None:
        ports = frozenset(self.allowed_ports)
        if not ports or any(not isinstance(port, int) or not 1 <= port <= 65535 for port in ports):
            raise SecurityPolicyError("allowed ports must be integers from 1 to 65535")
        if not 0 <= self.max_redirects <= 20:
            raise SecurityPolicyError("max_redirects must be between zero and twenty")
        object.__setattr__(self, "allowed_ports", ports)

    def validate(self, url: str) -> ValidatedOutboundURL:
        if not isinstance(url, str) or not url or len(url) > 8192:
            raise SecurityPolicyError("outbound URL must be a non-empty string of at most 8192 bytes")
        if any(ord(character) < 32 or character == "\\" for character in url):
            raise SecurityPolicyError("control characters and backslashes are forbidden in URLs")
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as exc:
            raise SecurityPolicyError("malformed outbound URL") from exc
        if parsed.scheme.lower() not in {"http", "https"}:
            raise SecurityPolicyError("only http and https outbound URLs are allowed")
        if not parsed.netloc or parsed.hostname is None:
            raise SecurityPolicyError("outbound URL must include a hostname")
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            raise SecurityPolicyError("credentials are forbidden in outbound URLs")
        if parsed.fragment:
            raise SecurityPolicyError("URL fragments are not sent to servers and are forbidden here")

        scheme = parsed.scheme.lower()
        effective_port = port or (443 if scheme == "https" else 80)
        if effective_port not in self.allowed_ports:
            raise SecurityPolicyError(f"outbound port {effective_port} is not allowed")

        raw_hostname = parsed.hostname.rstrip(".").lower()
        try:
            hostname = raw_hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise SecurityPolicyError("hostname cannot be encoded as IDNA") from exc
        if not hostname or hostname == "localhost" or hostname.endswith(".localhost"):
            raise SecurityPolicyError("localhost names are forbidden")

        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            try:
                answers = tuple(self.resolver(hostname, effective_port))
            except (OSError, socket.gaierror) as exc:
                raise SecurityPolicyError(f"DNS resolution failed for {hostname}") from exc
            if not answers:
                raise SecurityPolicyError(f"DNS resolution returned no addresses for {hostname}")
            addresses = tuple(sorted({str(_public_ip(answer)) for answer in answers}))
        else:
            addresses = (str(_public_ip(str(literal))),)

        normalized_host = f"[{hostname}]" if ":" in hostname else hostname
        default_port = 443 if scheme == "https" else 80
        normalized_netloc = normalized_host if effective_port == default_port else f"{normalized_host}:{effective_port}"
        normalized = urlunsplit(
            SplitResult(scheme, normalized_netloc, parsed.path or "/", parsed.query, "")
        )
        return ValidatedOutboundURL(
            url=normalized,
            scheme=scheme,
            hostname=hostname,
            port=effective_port,
            resolved_addresses=addresses,
        )

    def validate_redirect_hop(self, current_url: str, location: str) -> ValidatedOutboundURL:
        if not isinstance(location, str) or not location:
            raise SecurityPolicyError("redirect Location must be non-empty")
        return self.validate(urljoin(current_url, location))

    def validate_redirect_chain(
        self, initial_url: str, redirect_locations: Sequence[str]
    ) -> tuple[ValidatedOutboundURL, ...]:
        if len(redirect_locations) > self.max_redirects:
            raise SecurityPolicyError("redirect chain exceeds the configured limit")
        validated = [self.validate(initial_url)]
        current = validated[0].url
        for location in redirect_locations:
            hop = self.validate_redirect_hop(current, location)
            validated.append(hop)
            current = hop.url
        return tuple(validated)


# ---------------------------------------------------------------------------
# RLS-like scoped token policies


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise SecurityPolicyError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class ScopedAccessPolicy:
    """Least-privilege subject/resource/action policy carried by one token."""

    subject: str
    resource_patterns: tuple[str, ...]
    actions: frozenset[str]
    expires_at: datetime

    def __post_init__(self) -> None:
        _validated_identifier(self.subject, "subject")
        patterns = tuple(sorted(set(self.resource_patterns)))
        actions = frozenset(self.actions)
        if not patterns or not actions:
            raise SecurityPolicyError("access policy requires resources and actions")
        if any(not pattern or pattern == "*" for pattern in patterns):
            raise SecurityPolicyError("global resource wildcards are forbidden")
        if any("*" in item[:-1] or ("*" in item and not item.endswith("/*")) for item in patterns):
            raise SecurityPolicyError("only exact resources and trailing /* scopes are allowed")
        for action in actions:
            _validated_identifier(action, "action")
        object.__setattr__(self, "resource_patterns", patterns)
        object.__setattr__(self, "actions", actions)
        object.__setattr__(self, "expires_at", _utc(self.expires_at))


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True, repr=False)
class IssuedAccessToken:
    """A plaintext secret returned once to its caller; repr is always redacted."""

    secret: str
    policy: ScopedAccessPolicy

    def __repr__(self) -> str:
        return f"IssuedAccessToken(secret=<redacted>, policy={self.policy!r})"


class ScopedTokenAuthority:
    """In-memory token authority that persists only SHA-256 token digests."""

    def __init__(self, *, maximum_ttl_seconds: int = 3600) -> None:
        if maximum_ttl_seconds < 1:
            raise SecurityPolicyError("maximum token TTL must be positive")
        self._maximum_ttl_seconds = maximum_ttl_seconds
        self._records: dict[str, ScopedAccessPolicy] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _digest(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    @property
    def stored_token_digests(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._records))

    def issue(
        self, policy: ScopedAccessPolicy, *, now: datetime | None = None
    ) -> IssuedAccessToken:
        issued_at = _utc(now or datetime.now(timezone.utc))
        ttl = (policy.expires_at - issued_at).total_seconds()
        if ttl <= 0:
            raise SecurityPolicyError("cannot issue an already-expired token")
        if ttl > self._maximum_ttl_seconds:
            raise SecurityPolicyError("token expiry exceeds the maximum TTL")
        secret = secrets.token_urlsafe(32)
        digest = self._digest(secret)
        with self._lock:
            self._records[digest] = policy
        return IssuedAccessToken(secret=secret, policy=policy)

    def authorize(
        self,
        secret: str,
        *,
        subject: str,
        resource: str,
        action: str,
        now: datetime | None = None,
    ) -> AccessDecision:
        if not isinstance(secret, str) or not secret:
            return AccessDecision(False, "invalid_token")
        digest = self._digest(secret)
        with self._lock:
            policy = self._records.get(digest)
        if policy is None:
            return AccessDecision(False, "invalid_token")
        checked_at = _utc(now or datetime.now(timezone.utc))
        if checked_at >= policy.expires_at:
            with self._lock:
                self._records.pop(digest, None)
            return AccessDecision(False, "expired")
        if not hmac.compare_digest(policy.subject, subject):
            return AccessDecision(False, "subject_mismatch")
        if action not in policy.actions:
            return AccessDecision(False, "action_not_granted")
        if not any(_resource_matches(pattern, resource) for pattern in policy.resource_patterns):
            return AccessDecision(False, "resource_out_of_scope")
        return AccessDecision(True, "explicit_scope")

    def revoke(self, secret: str) -> bool:
        digest = self._digest(secret)
        with self._lock:
            return self._records.pop(digest, None) is not None


# ---------------------------------------------------------------------------
# Bounded subprocess execution


_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_DANGEROUS_ENV_PREFIXES = ("DYLD_", "LD_")
_DANGEROUS_ENV_NAMES = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "IFS",
        "NODE_OPTIONS",
        "PERL5OPT",
        "PYTHONHOME",
        "PYTHONPATH",
        "RUBYOPT",
    }
)


@dataclass(frozen=True)
class SubprocessPolicy:
    """Immutable resource and input bounds for subprocess execution."""

    allowed_executables: tuple[str, ...]
    max_runtime_seconds: float = 30.0
    max_stdout_bytes: int = 1_000_000
    max_stderr_bytes: int = 1_000_000
    max_argv_items: int = 128
    max_argument_bytes: int = 16_384
    memory_limit_bytes: int | None = 512 * 1024 * 1024
    file_size_limit_bytes: int | None = 16 * 1024 * 1024
    open_file_limit: int | None = 64
    allowed_env_names: frozenset[str] = frozenset()
    base_environment: tuple[tuple[str, str], ...] = (
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("PATH", "/usr/bin:/bin"),
        ("PYTHONNOUSERSITE", "1"),
        ("PYTHONSAFEPATH", "1"),
        ("TZ", "UTC"),
    )

    def __post_init__(self) -> None:
        canonical: list[str] = []
        for executable in self.allowed_executables:
            candidate = Path(executable)
            if not candidate.is_absolute():
                raise SecurityPolicyError("allowlisted executables must use absolute paths")
            resolved = str(candidate.resolve())
            if not Path(resolved).is_file() or not os.access(resolved, os.X_OK):
                raise SecurityPolicyError(f"allowlisted executable is not executable: {resolved}")
            canonical.append(resolved)
        if not canonical:
            raise SecurityPolicyError("at least one executable must be allowlisted")
        if self.max_runtime_seconds <= 0 or self.max_runtime_seconds > 3600:
            raise SecurityPolicyError("runtime limit must be between zero and 3600 seconds")
        for name, value in (
            ("max_stdout_bytes", self.max_stdout_bytes),
            ("max_stderr_bytes", self.max_stderr_bytes),
            ("max_argv_items", self.max_argv_items),
            ("max_argument_bytes", self.max_argument_bytes),
        ):
            if not isinstance(value, int) or value < 1:
                raise SecurityPolicyError(f"{name} must be a positive integer")
        allowed_env = frozenset(self.allowed_env_names)
        for name in allowed_env:
            self._validate_env_name(name)
        base = tuple(self.base_environment)
        if len({name for name, _ in base}) != len(base):
            raise SecurityPolicyError("base environment contains duplicate names")
        for name, value in base:
            self._validate_env_name(name)
            self._validate_env_value(value)
        object.__setattr__(self, "allowed_executables", tuple(sorted(set(canonical))))
        object.__setattr__(self, "allowed_env_names", allowed_env)
        object.__setattr__(self, "base_environment", tuple(sorted(base)))

    @staticmethod
    def _validate_env_name(name: str) -> None:
        if (
            not isinstance(name, str)
            or not _ENV_NAME.fullmatch(name)
            or name in _DANGEROUS_ENV_NAMES
            or name.startswith(_DANGEROUS_ENV_PREFIXES)
        ):
            raise SecurityPolicyError(f"unsafe environment variable name: {name!r}")

    @staticmethod
    def _validate_env_value(value: str) -> None:
        if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > 8192:
            raise SecurityPolicyError("environment values must be strings of at most 8192 bytes")


@dataclass(frozen=True)
class ProcessResult:
    argv: tuple[str, ...]
    executable: str
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    duration_seconds: float
    resource_limits_applied: bool
    boundary_notice: str = PROCESS_BOUNDARY_NOTICE

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")

    @property
    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", errors="replace")


class _BoundedCapture:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.buffer = bytearray()
        self.truncated = False

    def drain(self, stream: object) -> None:
        read = getattr(stream, "read")
        try:
            while True:
                chunk = read(65_536)
                if not chunk:
                    break
                remaining = self.limit - len(self.buffer)
                if remaining > 0:
                    self.buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.truncated = True
        finally:
            getattr(stream, "close")()


def _posix_resource_limiter(policy: SubprocessPolicy) -> Callable[[], None] | None:
    if os.name != "posix":
        return None
    try:
        import resource
    except ImportError:
        return None

    def apply_limits() -> None:
        def supported(limit: int, bounds: tuple[int, int]) -> None:
            # macOS exposes RLIMIT_AS but rejects attempts to set it.  Resource
            # limits are defence in depth, so apply each supported limit without
            # allowing one unsupported kernel feature to disable the boundary.
            try:
                resource.setrlimit(limit, bounds)
            except (OSError, ValueError):
                pass

        supported(resource.RLIMIT_CORE, (0, 0))
        cpu_seconds = max(1, math.ceil(policy.max_runtime_seconds) + 1)
        supported(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        if policy.file_size_limit_bytes is not None:
            supported(
                resource.RLIMIT_FSIZE,
                (policy.file_size_limit_bytes, policy.file_size_limit_bytes),
            )
        if policy.open_file_limit is not None:
            current_soft, current_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            requested = min(policy.open_file_limit, current_hard)
            supported(resource.RLIMIT_NOFILE, (requested, requested))
        if policy.memory_limit_bytes is not None and hasattr(resource, "RLIMIT_AS"):
            supported(
                resource.RLIMIT_AS,
                (policy.memory_limit_bytes, policy.memory_limit_bytes),
            )

    return apply_limits


class BoundedSubprocessRunner:
    """Run an explicitly permitted argv under bounded local process controls.

    This class never invokes a shell and never inherits the parent environment or
    working directory.  It does *not* provide network isolation; see
    :data:`PROCESS_BOUNDARY_NOTICE`.
    """

    def __init__(self, policy: SubprocessPolicy) -> None:
        self.policy = policy

    def _argv(self, argv: Sequence[str]) -> tuple[str, ...]:
        if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
            raise SecurityPolicyError("argv must be a sequence of strings, never a shell command")
        materialized = tuple(argv)
        if not materialized or len(materialized) > self.policy.max_argv_items:
            raise SecurityPolicyError("argv is empty or exceeds the item limit")
        for argument in materialized:
            if (
                not isinstance(argument, str)
                or "\x00" in argument
                or len(argument.encode("utf-8")) > self.policy.max_argument_bytes
            ):
                raise SecurityPolicyError("every argument must be a bounded NUL-free string")
        candidate = Path(materialized[0])
        if not candidate.is_absolute():
            raise SecurityPolicyError("argv[0] must be an absolute executable path")
        executable = str(candidate.resolve())
        if executable not in self.policy.allowed_executables:
            raise SecurityPolicyError(f"executable is not allowlisted: {executable}")
        return (executable, *materialized[1:])

    def _environment(self, additions: Mapping[str, str] | None) -> dict[str, str]:
        environment = dict(self.policy.base_environment)
        for name, value in (additions or {}).items():
            SubprocessPolicy._validate_env_name(name)
            SubprocessPolicy._validate_env_value(value)
            if name not in self.policy.allowed_env_names:
                raise SecurityPolicyError(f"environment variable is not allowlisted: {name}")
            environment[name] = value
        return environment

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> ProcessResult:
        safe_argv = self._argv(argv)
        safe_env = self._environment(env)
        timeout = self.policy.max_runtime_seconds if timeout_seconds is None else timeout_seconds
        if timeout <= 0 or timeout > self.policy.max_runtime_seconds:
            raise SecurityPolicyError("timeout must be positive and no greater than the policy limit")

        limiter = _posix_resource_limiter(self.policy)
        started = time.monotonic()
        stdout_capture = _BoundedCapture(self.policy.max_stdout_bytes)
        stderr_capture = _BoundedCapture(self.policy.max_stderr_bytes)
        timed_out = False
        with tempfile.TemporaryDirectory(prefix="career-process-") as temporary_cwd:
            process = subprocess.Popen(
                safe_argv,
                cwd=temporary_cwd,
                env=safe_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=(os.name == "posix"),
                preexec_fn=limiter,
            )
            assert process.stdout is not None and process.stderr is not None
            readers = (
                threading.Thread(target=stdout_capture.drain, args=(process.stdout,), daemon=True),
                threading.Thread(target=stderr_capture.drain, args=(process.stderr,), daemon=True),
            )
            for reader in readers:
                reader.start()
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.wait()
            finally:
                for reader in readers:
                    reader.join(timeout=2.0)
                # A descendant outside the process group retaining a pipe must not
                # hold this call open.  Closing is safe even after the reader did it.
                for stream in (process.stdout, process.stderr):
                    if not stream.closed:
                        stream.close()

        return ProcessResult(
            argv=safe_argv,
            executable=safe_argv[0],
            returncode=process.returncode,
            stdout=bytes(stdout_capture.buffer),
            stderr=bytes(stderr_capture.buffer),
            timed_out=timed_out,
            stdout_truncated=stdout_capture.truncated,
            stderr_truncated=stderr_capture.truncated,
            duration_seconds=time.monotonic() - started,
            resource_limits_applied=limiter is not None,
        )


__all__ = [
    "AccessDecision",
    "BackendCapabilityManifest",
    "BoundedSubprocessRunner",
    "CapabilityAuthorizer",
    "CapabilityDecision",
    "CapabilityGrant",
    "IssuedAccessToken",
    "OutboundURLPolicy",
    "PROCESS_BOUNDARY_NOTICE",
    "ProcessResult",
    "ScopedAccessPolicy",
    "ScopedTokenAuthority",
    "SecurityPolicyError",
    "SubprocessPolicy",
    "ValidatedOutboundURL",
]
