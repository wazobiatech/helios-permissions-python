"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure ``src`` is importable when running ``pytest`` from the repo root.
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
