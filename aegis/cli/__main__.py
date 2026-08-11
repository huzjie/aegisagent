from __future__ import annotations
"""允许 ``python -m aegis.cli``。"""
import sys
from .main import main

if __name__ == "__main__":
    sys.exit(main())
