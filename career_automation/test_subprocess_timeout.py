"""Adversarial timeout tests for the public subprocess boundary."""

from __future__ import annotations

import io
import os
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

import career_automation.security as security
from career_automation.security import BoundedSubprocessRunner, SubprocessPolicy


class _NeverReapedProcess:
    """Minimal Popen double whose timeout fallback never terminates it."""

    pid = 4242
    returncode = None

    def __init__(self) -> None:
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.wait_timeouts: list[float | None] = []

    def wait(self, timeout: float | None = None) -> int:
        self.wait_timeouts.append(timeout)
        raise subprocess.TimeoutExpired(("unreapable",), timeout)


class BoundedSubprocessTimeoutFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertEqual(os.name, "posix", "the process-group timeout boundary is POSIX-specific")
        executable = str(Path(sys.executable).resolve())
        self.runner = BoundedSubprocessRunner(
            SubprocessPolicy(allowed_executables=(executable,), max_runtime_seconds=2)
        )
        self.command = (executable, "-c", "import time; time.sleep(30)")

    def test_permission_denied_group_signal_kills_and_reaps_direct_child(self) -> None:
        """A sandbox-denied killpg must still yield a reaped timed-out child."""
        real_popen = security.subprocess.Popen
        spawned: list[subprocess.Popen[bytes]] = []

        def record_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = real_popen(*args, **kwargs)
            spawned.append(process)
            return process

        started = time.monotonic()
        with (
            mock.patch.object(security.subprocess, "Popen", side_effect=record_popen),
            mock.patch.object(security.os, "killpg", side_effect=PermissionError("sandbox")) as killpg,
        ):
            result = self.runner.run(self.command, timeout_seconds=0.05)

        self.assertTrue(result.timed_out)
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].poll(), "the direct child was not reaped")
        self.assertEqual(spawned[0].returncode, result.returncode)
        self.assertLess(result.returncode, 0, "the timed-out child was not killed")
        killpg.assert_called_once_with(spawned[0].pid, signal.SIGKILL)

    def test_missing_process_group_is_harmless_and_still_reports_timeout(self) -> None:
        """A raced-away process group is not an error or a false success."""
        with mock.patch.object(
            security.os, "killpg", side_effect=ProcessLookupError("already gone")
        ) as killpg:
            result = self.runner.run(self.command, timeout_seconds=0.05)

        self.assertTrue(result.timed_out)
        self.assertLess(result.returncode, 0)
        killpg.assert_called_once()

    def test_unreaped_permission_denied_fallback_propagates_failure(self) -> None:
        """Never report a timeout result when the fallback did not terminate the child."""
        process = _NeverReapedProcess()
        with (
            mock.patch.object(security.subprocess, "Popen", return_value=process),
            mock.patch.object(security.os, "killpg", side_effect=PermissionError("sandbox")),
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.runner.run(self.command, timeout_seconds=0.05)

        self.assertEqual(process.wait_timeouts, [0.05, 2.0])


if __name__ == "__main__":
    unittest.main()
