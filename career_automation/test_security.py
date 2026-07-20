from __future__ import annotations

import json
import os
import sys
import time
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path

from career_automation.security import (
    PROCESS_BOUNDARY_NOTICE,
    BackendCapabilityManifest,
    BoundedSubprocessRunner,
    CapabilityAuthorizer,
    CapabilityGrant,
    OutboundURLPolicy,
    ScopedAccessPolicy,
    ScopedTokenAuthority,
    SecurityPolicyError,
    SubprocessPolicy,
)


PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"


def public_resolver(hostname: str, port: int) -> tuple[str, ...]:
    del hostname, port
    return (PUBLIC_V4,)


class CapabilityTests(unittest.TestCase):
    def test_manifest_is_immutable_and_authorization_is_explicit(self) -> None:
        manifest = BackendCapabilityManifest(
            backend_id="employer-research",
            grants=(
                CapabilityGrant("fetch", ("web/employers/*",)),
                CapabilityGrant("read", ("jobs/viable",)),
            ),
        )
        authorizer = CapabilityAuthorizer([manifest])
        self.assertTrue(authorizer.authorize("employer-research", "fetch", "web/employers/acme").allowed)
        self.assertFalse(authorizer.authorize("employer-research", "fetch", "web/jobs/acme").allowed)
        self.assertFalse(authorizer.authorize("employer-research", "write", "jobs/viable").allowed)
        self.assertFalse(authorizer.authorize("unknown", "fetch", "web/employers/acme").allowed)
        with self.assertRaises(FrozenInstanceError):
            manifest.version = 2  # type: ignore[misc]
        with self.assertRaises(TypeError):
            authorizer.manifests["other"] = manifest  # type: ignore[index]

    def test_manifest_rejects_duplicate_or_ambiguous_grants(self) -> None:
        with self.assertRaises(SecurityPolicyError):
            CapabilityGrant("fetch", ("web/*/secret",))
        grant = CapabilityGrant("fetch", ("web/*",))
        with self.assertRaises(SecurityPolicyError):
            BackendCapabilityManifest("backend", (grant, grant))


class OutboundURLTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = OutboundURLPolicy(resolver=public_resolver)

    def test_accepts_and_normalizes_public_http_urls(self) -> None:
        result = self.policy.validate("HTTPS://Example.COM./jobs?q=ml")
        self.assertEqual(result.url, "https://example.com/jobs?q=ml")
        self.assertEqual(result.resolved_addresses, (PUBLIC_V4,))
        result.assert_connected_peer(PUBLIC_V4)
        with self.assertRaisesRegex(SecurityPolicyError, "validated DNS"):
            result.assert_connected_peer("8.8.8.8")

    def test_rejects_non_web_credentials_localhost_and_nonstandard_ports(self) -> None:
        bad = (
            "file:///etc/passwd",
            "ftp://example.com/file",
            "https://user:secret@example.com/",
            "https://localhost/",
            "https://api.localhost/",
            "https://example.com:8080/",
            "https://example.com/path#fragment",
            "https:\\example.com\\jobs",
        )
        for url in bad:
            with self.subTest(url=url), self.assertRaises(SecurityPolicyError):
                self.policy.validate(url)

    def test_rejects_all_non_public_literal_address_classes(self) -> None:
        bad = (
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "192.0.2.1",
            "[::1]",
            "[fe80::1]",
            "[ff02::1]",
            "[::]",
        )
        for address in bad:
            with self.subTest(address=address), self.assertRaises(SecurityPolicyError):
                self.policy.validate(f"http://{address}/")
        self.assertEqual(
            self.policy.validate(f"https://[{PUBLIC_V6}]/").resolved_addresses,
            (PUBLIC_V6,),
        )

    def test_rejects_dns_answer_set_if_even_one_address_is_private(self) -> None:
        def rebinding_resolver(hostname: str, port: int) -> tuple[str, ...]:
            del hostname, port
            return (PUBLIC_V4, "127.0.0.1")

        with self.assertRaisesRegex(SecurityPolicyError, "not a public"):
            OutboundURLPolicy(resolver=rebinding_resolver).validate("https://example.com")

    def test_validates_every_relative_or_absolute_redirect_hop(self) -> None:
        chain = self.policy.validate_redirect_chain(
            "https://example.com/start", ["/login", "https://jobs.example.org/final"]
        )
        self.assertEqual(len(chain), 3)
        self.assertEqual(chain[1].url, "https://example.com/login")
        with self.assertRaises(SecurityPolicyError):
            self.policy.validate_redirect_chain(
                "https://example.com", ["https://127.0.0.1/admin"]
            )
        with self.assertRaisesRegex(SecurityPolicyError, "exceeds"):
            OutboundURLPolicy(resolver=public_resolver, max_redirects=1).validate_redirect_chain(
                "https://example.com", ["/one", "/two"]
            )


class ScopedTokenTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
        self.authority = ScopedTokenAuthority(maximum_ttl_seconds=300)
        self.policy = ScopedAccessPolicy(
            subject="research-worker-1",
            resource_patterns=("employers/acme/*",),
            actions=frozenset({"read", "write"}),
            expires_at=self.now + timedelta(seconds=120),
        )

    def test_token_enforces_subject_resource_action_and_expiry(self) -> None:
        issued = self.authority.issue(self.policy, now=self.now)
        self.assertTrue(
            self.authority.authorize(
                issued.secret,
                subject="research-worker-1",
                resource="employers/acme/dossier",
                action="write",
                now=self.now,
            ).allowed
        )
        checks = (
            ("other-worker", "employers/acme/dossier", "write", "subject_mismatch"),
            ("research-worker-1", "employers/other/dossier", "write", "resource_out_of_scope"),
            ("research-worker-1", "employers/acme/dossier", "delete", "action_not_granted"),
        )
        for subject, resource, action, reason in checks:
            with self.subTest(reason=reason):
                result = self.authority.authorize(
                    issued.secret,
                    subject=subject,
                    resource=resource,
                    action=action,
                    now=self.now,
                )
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, reason)
        expired = self.authority.authorize(
            issued.secret,
            subject="research-worker-1",
            resource="employers/acme/dossier",
            action="read",
            now=self.policy.expires_at,
        )
        self.assertEqual(expired.reason, "expired")

    def test_authority_never_persists_or_displays_plaintext_secret(self) -> None:
        issued = self.authority.issue(self.policy, now=self.now)
        self.assertNotIn(issued.secret, repr(issued))
        digests = self.authority.stored_token_digests
        self.assertEqual(len(digests), 1)
        self.assertNotEqual(digests[0], issued.secret)
        self.assertEqual(len(digests[0]), 64)
        self.assertTrue(self.authority.revoke(issued.secret))
        self.assertFalse(
            self.authority.authorize(
                issued.secret,
                subject="research-worker-1",
                resource="employers/acme/dossier",
                action="read",
                now=self.now,
            ).allowed
        )

    def test_policy_rejects_global_scope_naive_time_and_excessive_ttl(self) -> None:
        with self.assertRaises(SecurityPolicyError):
            ScopedAccessPolicy("worker", ("*",), frozenset({"read"}), self.policy.expires_at)
        with self.assertRaisesRegex(SecurityPolicyError, "timezone-aware"):
            ScopedAccessPolicy(
                "worker", ("jobs/1",), frozenset({"read"}), datetime(2026, 7, 19)
            )
        long_policy = ScopedAccessPolicy(
            "worker",
            ("jobs/1",),
            frozenset({"read"}),
            self.now + timedelta(seconds=301),
        )
        with self.assertRaisesRegex(SecurityPolicyError, "maximum TTL"):
            self.authority.issue(long_policy, now=self.now)


class BoundedSubprocessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.executable = str(Path(sys.executable).resolve())
        self.policy = SubprocessPolicy(
            allowed_executables=(self.executable,),
            max_runtime_seconds=2,
            max_stdout_bytes=32,
            max_stderr_bytes=24,
            allowed_env_names=frozenset({"SAFE_VALUE"}),
        )
        self.runner = BoundedSubprocessRunner(self.policy)

    def test_requires_argv_and_an_exact_absolute_allowlisted_executable(self) -> None:
        with self.assertRaisesRegex(SecurityPolicyError, "never a shell"):
            self.runner.run(f"{self.executable} -c pass")
        with self.assertRaisesRegex(SecurityPolicyError, "absolute"):
            self.runner.run(("python", "-c", "pass"))
        unlisted = shutil_which("true")
        if unlisted is not None and str(Path(unlisted).resolve()) != self.executable:
            with self.assertRaisesRegex(SecurityPolicyError, "not allowlisted"):
                self.runner.run((unlisted,))

    def test_shell_metacharacters_are_passed_as_inert_argv_data(self) -> None:
        marker = "; touch SHOULD_NOT_EXIST"
        result = self.runner.run(
            (self.executable, "-c", "import sys; print(sys.argv[1])", marker)
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout_text.strip(), marker)

    def test_uses_temporary_cwd_and_a_sanitized_non_inherited_environment(self) -> None:
        host_secret_name = "CAREER_AUTOMATION_HOST_SECRET"
        previous = os.environ.get(host_secret_name)
        os.environ[host_secret_name] = "must-not-leak"
        try:
            code = (
                "import json, os; "
                "print(os.getcwd()); "
                "print(json.dumps({'safe': os.getenv('SAFE_VALUE'), "
                "'leak': os.getenv('CAREER_AUTOMATION_HOST_SECRET')}))"
            )
            # Use a larger bound for this deliberately structured diagnostic.
            runner = BoundedSubprocessRunner(
                SubprocessPolicy(
                    allowed_executables=(self.executable,),
                    max_stdout_bytes=4096,
                    allowed_env_names=frozenset({"SAFE_VALUE"}),
                )
            )
            result = runner.run((self.executable, "-c", code), env={"SAFE_VALUE": "yes"})
        finally:
            if previous is None:
                os.environ.pop(host_secret_name, None)
            else:
                os.environ[host_secret_name] = previous
        lines = result.stdout_text.splitlines()
        temporary_cwd = lines[0]
        self.assertFalse(Path(temporary_cwd).exists())
        self.assertEqual(json.loads(lines[1]), {"safe": "yes", "leak": None})
        with self.assertRaises(SecurityPolicyError):
            self.runner.run((self.executable, "-c", "pass"), env={"PYTHONPATH": "/tmp"})

    def test_caps_both_streams_while_draining_and_reports_truncation(self) -> None:
        result = self.runner.run(
            (
                self.executable,
                "-c",
                "import sys; sys.stdout.write('o'*1000); sys.stderr.write('e'*1000)",
            )
        )
        self.assertEqual(len(result.stdout), 32)
        self.assertEqual(len(result.stderr), 24)
        self.assertTrue(result.stdout_truncated)
        self.assertTrue(result.stderr_truncated)

    def test_timeout_kills_the_process_group_and_boundary_is_honest(self) -> None:
        started = time.monotonic()
        result = self.runner.run(
            (self.executable, "-c", "import time; time.sleep(30)"),
            timeout_seconds=0.15,
        )
        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started, 2)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.boundary_notice, PROCESS_BOUNDARY_NOTICE)
        self.assertIn("not a network sandbox", result.boundary_notice)


def shutil_which(executable: str) -> str | None:
    # Local helper avoids importing the module just for one platform-dependent test.
    for directory in os.get_exec_path():
        candidate = Path(directory) / executable
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate.resolve())
    return None


if __name__ == "__main__":
    unittest.main()
