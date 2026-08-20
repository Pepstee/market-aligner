"""Per-board scraper adapters.

Each board (wanted, saramin, jobkorea, notefolio) implements the Adapter
interface in base.py. Adapters are fixture-driven in this walking skeleton;
each carries a clear `# TODO: wire live endpoint` marker where the real API
or Playwright call belongs.
"""

from .base import Adapter, load_adapter, ADAPTERS  # noqa: F401
