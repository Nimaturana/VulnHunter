"""VulnHunter backend package."""

import os
from pathlib import Path


# Matplotlib is imported by the PDF adapter. Keep its writable cache inside the
# repository so restricted Windows environments do not fall back to a new temp
# directory on every process start.
_repository_root = Path(__file__).resolve().parents[2]
_matplotlib_cache = _repository_root / "artifacts" / "cache" / "matplotlib"
_matplotlib_cache.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(_matplotlib_cache))

__version__ = "0.1.0"
