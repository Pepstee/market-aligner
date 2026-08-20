"""
llm/prompt_loader.py — load and render the versioned prompt templates.

Each template in llm/prompts/*.txt carries a `# version:` header and two labelled
sections, SYSTEM: and USER:. The SYSTEM block embeds a `[[task:<name>]]` marker so
MockBackend can route deterministically. The USER block has a single
`{placeholder}` that render() fills with the caller's JSON payload.

Keeping prompts as files (not string literals) is what makes them *versioned* and
diff-able — a prompt change is a reviewable file change, per Architecture.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_PROMPT_DIR = Path(__file__).resolve().parent / "prompts"

_VERSION_RE = re.compile(r"^#\s*version:\s*(.+)$", re.MULTILINE)


@dataclass(frozen=True)
class Prompt:
    task: str
    version: str
    system: str
    user_template: str

    def render_user(self, payload: str) -> str:
        """Fill the single {placeholder} in the USER block with `payload`."""
        # There is exactly one placeholder per template; substitute the first.
        m = re.search(r"\{([a-zA-Z0-9_]+)\}", self.user_template)
        if not m:
            return self.user_template
        return self.user_template[: m.start()] + payload + self.user_template[m.end():]


def _parse(text: str, task: str) -> Prompt:
    vm = _VERSION_RE.search(text)
    version = vm.group(1).strip() if vm else "0.0.0"

    # Split on the SYSTEM:/USER: section labels (line-anchored).
    sys_idx = text.find("\nSYSTEM:")
    usr_idx = text.find("\nUSER:")
    if sys_idx == -1 or usr_idx == -1 or usr_idx < sys_idx:
        raise ValueError(f"prompt '{task}' missing SYSTEM:/USER: sections")
    system = text[sys_idx + len("\nSYSTEM:") : usr_idx].strip()
    user = text[usr_idx + len("\nUSER:") :].strip()
    return Prompt(task=task, version=version, system=system, user_template=user)


def load_prompt(task: str, prompt_dir: str | Path = _PROMPT_DIR) -> Prompt:
    path = Path(prompt_dir) / f"{task}.txt"
    if not path.exists():
        raise FileNotFoundError(f"no prompt template for task '{task}' at {path}")
    return _parse(path.read_text(encoding="utf-8"), task)


def list_prompts(prompt_dir: str | Path = _PROMPT_DIR) -> dict[str, str]:
    """task -> version, for every template. Handy for a versions manifest."""
    out: dict[str, str] = {}
    for p in sorted(Path(prompt_dir).glob("*.txt")):
        out[p.stem] = load_prompt(p.stem, prompt_dir).version
    return out
