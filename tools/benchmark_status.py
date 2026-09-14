"""Script wrapper for ADS-B benchmark status reports."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from adsb.benchmark_status import main


if __name__ == "__main__":
    main(sys.argv[1:])
