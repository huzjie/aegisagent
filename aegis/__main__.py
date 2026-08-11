from __future__ import annotations
"""Allow ``python -m aegis`` to launch the CLI."""
import sys

from aegis.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
