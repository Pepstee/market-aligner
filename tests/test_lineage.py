from __future__ import annotations

import unittest

import market_aligner


class CanonicalLineageTests(unittest.TestCase):
    def test_package_identity_is_canonical(self) -> None:
        self.assertEqual(market_aligner.__version__, "0.1.0.dev0")


if __name__ == "__main__":
    unittest.main()
